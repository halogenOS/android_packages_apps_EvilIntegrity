#!/usr/bin/env python3
"""
vbmeta_extract - Read the real AVB verified-boot values out of a Google factory
image, without downloading the whole thing.

A Play Integrity DEVICE pass needs a coherent verified-boot story: the spoofed
"green / locked" bootloader state has to be backed by the *same* vbmeta digest,
dm-verity root digests and verified-boot key that a stock device of the
claimed model reports. Those values are not in the OTA metadata; they live in
the signed vbmeta partitions of the factory image. Emptying them (the previous
approach) makes a locked-looking device look data-sparse, which is itself a
tell. Here we pull the exact values instead.

The factory zip is multi-GB, but the vbmeta partitions are tiny, so we fetch
only the handful of small members we need via HTTP Range requests through the
nested ZIP structure (outer factory zip -> STORED image-*.zip -> members). The
values are then computed with avbtool used as a library.

Everything here runs offline, at overlay-generation time, on the maintainer's
machine — never on device.
"""
import base64
import os
import struct
import subprocess
import sys
import tempfile
import urllib.request
import zlib

# avbtool lives in the AOSP tree; import it as a library for robust vbmeta
# parsing (footer detection, descriptor decode) instead of re-implementing it.
_AVB_DIR = os.path.join(
    os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(
        os.path.dirname(os.path.abspath(__file__)))))),
    "external", "avb")

_UA = "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"

# dm-verity mode reported by a production, enforcing device. Mirrors
# fs_mgr_load_verity_state(): veritymode=enforcing -> VERITY_MODE_DEFAULT ==
# VERITY_MODE_RESTART == 2 (system/core/fs_mgr/include/fs_mgr.h). init publishes
# it as partition.<name>.verified (system/core/init/builtins.cpp).
_VERITY_MODE_ENFORCING = "2"
# Pixels do not enable dm-verity check_at_most_once on these partitions.
_CHECK_AT_MOST_ONCE = "0"
# Standard locked-Pixel kernel cmdline: androidboot.vbmeta.invalidate_on_error.
_INVALIDATE_ON_ERROR = "yes"

# SoC / hardware props read from the factory image's vendor/build.prop. The
# probe collects these; leaving the device's real values in place while claiming
# different silicon is an obvious inconsistency. Extracted verbatim from the
# claimed device's image so they stay coherent with the fingerprint.
_HW_PROP_KEYS = frozenset({
    "ro.board.platform",
    "ro.board.api_level",
    "ro.board.api_frozen",
    "ro.soc.manufacturer",
    "ro.soc.model",
    "ro.product.board",
    "ro.hardware.egl",
    "ro.hardware.vulkan",
    "ro.hardware.keystore",
    "ro.hardware.gatekeeper",
    "ro.hardware.keystore_desede",
    "ro.hardware.gralloc",
    "ro.arch",
})

# The chained partitions whose own vbmeta struct we must fetch to reproduce the
# top-level vbmeta digest (boot/init_boot carry theirs in an AVB footer, the
# vbmeta_* partitions are standalone). Discovered from the main vbmeta's chain
# descriptors at runtime; this is only the set of member files to pull.


def _http_range(url, cookie, start, end):
    req = urllib.request.Request(url, headers={
        "User-Agent": _UA, "Cookie": cookie, "Range": f"bytes={start}-{end}"})
    return urllib.request.urlopen(req, timeout=180).read()


def _http_size(url, cookie):
    req = urllib.request.Request(url, method="HEAD",
                                 headers={"User-Agent": _UA, "Cookie": cookie})
    return int(urllib.request.urlopen(req, timeout=60).headers["Content-Length"])


def _find_eocd(tail):
    """Return (cd_offset, cd_size), resolving ZIP64 if the classic EOCD is maxed."""
    i = tail.rfind(b"PK\x05\x06")
    if i < 0:
        raise RuntimeError("no EOCD found")
    cd_size = struct.unpack_from("<I", tail, i + 12)[0]
    cd_off = struct.unpack_from("<I", tail, i + 16)[0]
    if cd_off == 0xFFFFFFFF or cd_size == 0xFFFFFFFF:
        z = tail.rfind(b"PK\x06\x06")
        if z < 0:
            raise RuntimeError("ZIP64 EOCD missing")
        cd_size = struct.unpack_from("<Q", tail, z + 40)[0]
        cd_off = struct.unpack_from("<Q", tail, z + 48)[0]
    return cd_off, cd_size


def _parse_central_dir(cd, base):
    """Parse a central directory blob -> {name: (local_header_off, comp_size, method)}.

    base is the byte offset of this zip within the outer stream (0 for the outer
    zip, the nested image zip's data offset for the inner one).
    """
    out = {}
    off = 0
    while off + 4 <= len(cd) and cd[off:off + 4] == b"PK\x01\x02":
        method = struct.unpack_from("<H", cd, off + 10)[0]
        comp = struct.unpack_from("<I", cd, off + 20)[0]
        ucomp = struct.unpack_from("<I", cd, off + 24)[0]
        nlen = struct.unpack_from("<H", cd, off + 28)[0]
        elen = struct.unpack_from("<H", cd, off + 30)[0]
        clen = struct.unpack_from("<H", cd, off + 32)[0]
        lho = struct.unpack_from("<I", cd, off + 42)[0]
        name = cd[off + 46:off + 46 + nlen].decode("utf-8", "ignore")
        extra = cd[off + 46 + nlen:off + 46 + nlen + elen]
        if comp == 0xFFFFFFFF or lho == 0xFFFFFFFF or ucomp == 0xFFFFFFFF:
            eo = 0
            while eo + 4 <= len(extra):
                hid, hsz = struct.unpack_from("<HH", extra, eo)
                if hid == 0x0001:
                    vals = struct.unpack_from("<" + "Q" * (hsz // 8), extra, eo + 4)
                    vi = 0
                    if ucomp == 0xFFFFFFFF:
                        ucomp = vals[vi]; vi += 1
                    if comp == 0xFFFFFFFF:
                        comp = vals[vi]; vi += 1
                    if lho == 0xFFFFFFFF:
                        lho = vals[vi]; vi += 1
                    break
                eo += 4 + hsz
        out[name] = (base + lho, comp, method)
        off += 46 + nlen + elen + clen
    return out


def _central_dir(url, cookie, total, base):
    tail = _http_range(url, cookie, base + max(0, total - 200000), base + total - 1)
    cd_off, cd_size = _find_eocd(tail)
    return _parse_central_dir(
        _http_range(url, cookie, base + cd_off, base + cd_off + cd_size - 1), base)


def _data_offset(url, cookie, local_header_off):
    h = _http_range(url, cookie, local_header_off, local_header_off + 29)
    nlen = struct.unpack_from("<H", h, 26)[0]
    elen = struct.unpack_from("<H", h, 28)[0]
    return local_header_off + 30 + nlen + elen


def _extract_member(url, cookie, entries, name, out_dir):
    lho, comp, method = entries[name]
    data_off = _data_offset(url, cookie, lho)
    blob = _http_range(url, cookie, data_off, data_off + comp - 1)
    if method == 8:
        blob = zlib.decompress(blob, -15)
    path = os.path.join(out_dir, os.path.basename(name))
    with open(path, "wb") as f:
        f.write(blob)
    return path


def _fetch_image_members(factory_url, cookie, wanted, out_dir):
    """Range-extract the requested members from the nested image-*.zip.

    Returns {basename: path} for the members that were present. Silently skips
    members not in the image (e.g. a device without init_boot).
    """
    total = _http_size(factory_url, cookie)
    outer = _central_dir(factory_url, cookie, total, 0)
    img_name = next(k for k in outer if k.endswith(".zip") and "image-" in k)
    img_lho, img_comp, img_method = outer[img_name]
    if img_method != 0:
        raise RuntimeError("nested image zip is not STORED; range walk needs rework")
    img_base = _data_offset(factory_url, cookie, img_lho)
    inner = _central_dir(factory_url, cookie, img_comp, img_base)
    result = {}
    for want in wanted:
        key = next((k for k in inner if os.path.basename(k) == want), None)
        if key:
            result[want] = _extract_member(factory_url, cookie, inner, key, out_dir)
    return result


def _vbmeta_blob(avb, path):
    """Return (avbtool.Avb-parsed descriptors, header, raw vbmeta struct bytes)."""
    import avbtool
    image = avbtool.ImageHandler(path, read_only=True)
    footer, header, descriptors, _ = avb._parse_image(image)
    offset = footer.vbmeta_offset if footer else 0
    size = (header.SIZE + header.authentication_data_block_size +
            header.auxiliary_data_block_size)
    image.seek(offset)
    return descriptors, header, image.read(size)


def _embedded_public_key(header, blob):
    """Return the AVB public-key bytes embedded in a vbmeta struct's aux block."""
    aux_off = header.SIZE + header.authentication_data_block_size
    aux = blob[aux_off:aux_off + header.auxiliary_data_block_size]
    return aux[header.public_key_offset:header.public_key_offset + header.public_key_size]


def _read_build_prop(img_path):
    """Read /build.prop out of a filesystem partition image and return its text.

    Handles both filesystems Google ships partitions as: ext4 (magic 0xEF53 at
    byte 1080) via ``debugfs``, and erofs (magic 0xE0F5E1E2 at byte 1024) via
    ``fsck.erofs``. Returns None if the tool is unavailable or the file is not
    found — the caller treats hardware props as best-effort.
    """
    with open(img_path, "rb") as f:
        f.seek(1080)
        is_ext4 = f.read(2) == b"\x53\xef"
    try:
        if is_ext4:
            r = subprocess.run(["debugfs", "-R", "cat build.prop", img_path],
                               capture_output=True, timeout=120)
            return r.stdout.decode("utf-8", "ignore") if r.returncode == 0 else None
        with tempfile.TemporaryDirectory() as d:
            subprocess.run(["fsck.erofs", f"--extract={d}", "--path=/build.prop",
                            img_path], capture_output=True, timeout=120)
            out = os.path.join(d, "build.prop")
            return open(out, errors="ignore").read() if os.path.exists(out) else None
    except (FileNotFoundError, subprocess.SubprocessError):
        return None


def _extract_fs_file(img_path, fs_path, out_dir):
    """Extract a single file (fs_path relative to the filesystem root, no leading
    slash) from a partition image into out_dir and return its local path.

    Same dual-filesystem handling as _read_build_prop: debugfs for ext4,
    fsck.erofs for erofs. Raises on failure — callers that want best-effort
    semantics catch and degrade themselves.
    """
    with open(img_path, "rb") as f:
        f.seek(1080)
        is_ext4 = f.read(2) == b"\x53\xef"
    fs_dir, base = os.path.split(fs_path)
    if is_ext4:
        # rdump insists on creating <dest>/<basename(src)> itself and fails if
        # it already exists — always hand it a fresh directory.
        with tempfile.TemporaryDirectory(dir=out_dir) as td:
            r = subprocess.run(["debugfs", "-R", f"rdump /{fs_dir} {td}", img_path],
                               capture_output=True, timeout=600)
            dumped = os.path.join(td, os.path.basename(fs_dir), base)
            out = os.path.join(out_dir, base)
            if r.returncode != 0 or not os.path.exists(dumped):
                raise RuntimeError(f"debugfs could not extract /{fs_path}: "
                                   f"{r.stderr.decode('utf-8', 'ignore')[:200]}")
            os.replace(dumped, out)
        return out
    subprocess.run(["fsck.erofs", f"--extract={out_dir}", f"--path=/{fs_path}",
                    img_path], capture_output=True, timeout=600, check=True)
    out = os.path.join(out_dir, fs_path)
    if not os.path.exists(out):
        raise RuntimeError(f"fsck.erofs did not produce /{fs_path}")
    return out


# --- APK signing-block parsing (v2/v3 schemes) -------------------------------
# The APK Signing Block sits immediately before the ZIP central directory:
# [size u64][(len u64, id u32, value)*][size u64]["APK Sig Block 42"].
# v2 (0x7109871a) and v3 (0xf05368c0) share the same signer layout:
#   signers      = u32-len-prefixed sequence of signer
#   signer       = lp(signed_data) lp(signatures) lp(public_key)
#   signed_data  = lp(digests) lp(certificates) lp(attributes)
# and the lineage is represented as multiple signers, newest first is NOT
# guaranteed — order is signing order, so signers[0] is the current signer for
# apksigner-produced lineage (apksigner writes the current signer first).
_APK_SIG_BLOCK_MAGIC = b"APK Sig Block 42"
_APK_SIG_V2_ID = 0x7109871A
_APK_SIG_V3_ID = 0xF05368C0


def _lp(buf, off):
    """Read a u32-LE length-prefixed blob; return (bytes, next_offset)."""
    ln = struct.unpack_from("<I", buf, off)[0]
    return buf[off + 4:off + 4 + ln], off + 4 + ln


def _der_tlv(buf, off):
    """Minimal DER TLV reader -> (tag, content_off, content_len, next_off)."""
    tag = buf[off]
    off += 1
    ln = buf[off]
    off += 1
    if ln & 0x80:
        n = ln & 0x7F
        ln = int.from_bytes(buf[off:off + n], "big")
        off += n
    return tag, off, ln, off + ln


def _cert_from_pkcs7(der):
    """Pull the first X.509 cert out of a PKCS#7 SignedData (META-INF/*.RSA)."""
    tag, c, _, _ = _der_tlv(der, 0)              # ContentInfo SEQUENCE
    if tag != 0x30:
        raise RuntimeError("not a PKCS#7 ContentInfo")
    off = c
    _, _, _, off = _der_tlv(der, off)            # contentType OID
    tag, c, _, _ = _der_tlv(der, off)            # [0] EXPLICIT signedData
    tag, c, _, _ = _der_tlv(der, c)              # SignedData SEQUENCE
    off = c
    _, _, _, off = _der_tlv(der, off)            # version
    _, _, _, off = _der_tlv(der, off)            # digestAlgorithms
    _, _, _, off = _der_tlv(der, off)            # contentInfo
    tag, c, _, _ = _der_tlv(der, off)            # [0] IMPLICIT certificates
    if tag != 0xA0:
        raise RuntimeError("no certificates in PKCS#7")
    tag, cc, _, nxt = _der_tlv(der, c)           # first certificate SEQUENCE
    if tag != 0x30:
        raise RuntimeError("malformed certificate")
    return der[c:nxt]


def _apk_signing_certs(apk_path):
    """Return the ordered list of X.509 DER certs from an APK's v3 (preferred)
    or v2 signing block — one entry per signer (lineage), first = current.
    Falls back to the v1/JAR signature (META-INF/*.RSA) — Google's
    framework-res.apk ships v1-only."""
    with open(apk_path, "rb") as f:
        data = f.read()
    i = data.rfind(b"PK\x05\x06")
    if i < 0:
        raise RuntimeError("not a zip")
    cd_off = struct.unpack_from("<I", data, i + 16)[0]
    if data[cd_off - 16:cd_off] == _APK_SIG_BLOCK_MAGIC:
        block_size = struct.unpack_from("<Q", data, cd_off - 24)[0]
        off, end = cd_off - 24 - block_size + 8, cd_off - 24
        pairs = {}
        while off < end:
            plen = struct.unpack_from("<Q", data, off)[0]
            if plen < 4 or off + 8 + plen > end:
                break
            pid = struct.unpack_from("<I", data, off + 8)[0]
            pairs[pid] = data[off + 12:off + 8 + plen]
            off += 8 + plen
        blob = pairs.get(_APK_SIG_V3_ID) or pairs.get(_APK_SIG_V2_ID)
        if blob is not None:
            signers, _ = _lp(blob, 0)
            certs = []
            s_off = 0
            while s_off < len(signers):
                signer, s_off = _lp(signers, s_off)
                signed_data, _ = _lp(signer, 0)
                _, c_off = _lp(signed_data, 0)          # digests
                cert_seq, _ = _lp(signed_data, c_off)   # certificates
                cert, _ = _lp(cert_seq, 0)              # first = signing cert
                certs.append(cert)
            if certs:
                return certs
    # v1 fallback: PKCS#7 in META-INF
    import zipfile
    with zipfile.ZipFile(apk_path) as z:
        rsa = next((n for n in z.namelist()
                    if n.startswith("META-INF/") and n.upper().endswith(".RSA")), None)
        if rsa is None:
            raise RuntimeError("no v2/v3 signing scheme and no META-INF/*.RSA")
        return [_cert_from_pkcs7(z.read(rsa))]


def _java_cert_hashcode(der):
    """The java.util.Arrays.hashCode(byte[]) of the cert DER — the exact value
    PackageManager reports as the legacy PackageInfo.signatures[] int."""
    h = 1
    for b in der:
        sb = b - 256 if b > 127 else b
        h = (31 * h + sb) & 0xFFFFFFFF
    return h


def _varint(buf, off):
    v = 0
    shift = 0
    while True:
        x = buf[off]
        off += 1
        v |= (x & 0x7F) << shift
        if not (x & 0x80):
            break
        shift += 7
    return v, off


def _apex_manifest_name_version(manifest):
    """Parse apex_manifest.pb for (moduleName, versionCode) with a minimal
    proto walker — fields 1 (name, len-delimited) and 2 (version, varint)."""
    import zipfile  # noqa: F401 (kept import-local style of this module)
    off = 0
    name = None
    ver = None
    while off < len(manifest):
        tag, off = _varint(manifest, off)
        field, wt = tag >> 3, tag & 7
        if wt == 2:
            ln, off = _varint(manifest, off)
            val = manifest[off:off + ln]
            off += ln
            if field == 1:
                name = val.decode()
        elif wt == 0:
            val, off = _varint(manifest, off)
            if field == 2:
                ver = val
        elif wt == 1:
            off += 8
        elif wt == 5:
            off += 4
        else:
            break
    return name, ver


def _der_len(n):
    if n < 128:
        return bytes([n])
    b = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(b)]) + b


def _der_octet(data):
    return b"\x04" + _der_len(len(data)) + data


def _der_int(v):
    b = v.to_bytes((v.bit_length() + 8) // 8, "big") if v else b"\x00"
    b = b.lstrip(b"\x00") or b"\x00"
    if b[0] & 0x80:
        b = b"\x00" + b
    return b"\x02" + _der_len(len(b)) + b


def _der_seq(content):
    return b"\x30" + _der_len(len(content)) + content


def _der_set(content):
    return b"\x31" + _der_len(len(content)) + content


def compute_module_hash(apex_dir):
    """Compute the KeyMint moduleHash over a directory of .apex packages.

    moduleHash = SHA-256 over the DER encoding of
      Modules ::= SET OF { SEQUENCE { packageName OCTET_STRING, version INTEGER } }
    with entries sorted by OctetString DerOrd (name length, then name bytes) —
    mirroring keystore2's Maintenance::encode_module_info. Returns hex string.
    """
    import hashlib
    import zipfile
    mods = []
    for fn in sorted(os.listdir(apex_dir)):
        if not fn.endswith(".apex"):
            continue
        try:
            with zipfile.ZipFile(os.path.join(apex_dir, fn)) as z:
                name, ver = _apex_manifest_name_version(z.read("apex_manifest.pb"))
            if name and ver is not None:
                mods.append((name, ver))
        except Exception:
            continue
    mods.sort(key=lambda m: (len(m[0].encode()), m[0].encode()))
    blob = _der_set(b"".join(_der_seq(_der_octet(n.encode()) + _der_int(v))
                             for n, v in mods))
    return hashlib.sha256(blob).hexdigest()


def extract_module_hash(factory_url, cookie, work_dir):
    """Pull the factory image's system partition and compute the KeyMint
    moduleHash of the claimed device from its APEX packages."""
    os.makedirs(work_dir, exist_ok=True)
    files = _fetch_image_members(factory_url, cookie, ["system.img"], work_dir)
    if "system.img" not in files:
        raise RuntimeError("factory image has no system.img")
    img = files["system.img"]
    with open(img, "rb") as f:
        f.seek(1080)
        is_ext4 = f.read(2) == b"\x53\xef"
    if not is_ext4:
        raise RuntimeError("module hash: erofs not supported yet")
    import tempfile
    with tempfile.TemporaryDirectory(dir=work_dir) as td:
        subprocess.run(["debugfs", "-R", f"rdump /system/apex {td}", img],
                       capture_output=True, timeout=600, check=True)
        return compute_module_hash(os.path.join(td, "apex"))


def extract_platform_cert(factory_url, cookie, work_dir,
                          carrier=("system.img", "framework/framework-res.apk")):
    """Pull the stock platform signing certificate out of the factory image.

    The integrity probe hashes the signing certificate of the ``android``
    package (and other platform-signed packages). On stock that is Google's
    platform cert; on a custom ROM it is the ROM's own cert — a direct tell.
    This extracts the stock cert from the factory image so the conformance
    attributes can carry it. ``carrier`` is (partition member, path of a
    platform-signed APK in that partition's filesystem); framework-res.apk is
    the ``android`` package itself.

    Returns {"pem": str, "der_b64": str, "java_hashcode": "0x........",
             "sha256": hex, "lineage": [der_b64, ...]} — raises on failure.
    """
    import hashlib
    os.makedirs(work_dir, exist_ok=True)
    files = _fetch_image_members(factory_url, cookie, [carrier[0]], work_dir)
    if carrier[0] not in files:
        raise RuntimeError(f"factory image has no {carrier[0]}")
    try:
        apk = _extract_fs_file(files[carrier[0]], carrier[1], work_dir)
    except RuntimeError:
        # system-as-root images (modern Pixels) carry /system as a subdirectory
        # of the partition root rather than mounting at the root.
        apk = _extract_fs_file(files[carrier[0]], "system/" + carrier[1], work_dir)
    certs = _apk_signing_certs(apk)
    if not certs:
        raise RuntimeError(f"no signing certs in {carrier[1]}")
    der = certs[0]
    pem = ("-----BEGIN CERTIFICATE-----\n"
           + "\n".join(base64.encodebytes(der).decode().splitlines())
           + "\n-----END CERTIFICATE-----\n")
    return {
        "pem": pem,
        "der_b64": base64.b64encode(der).decode(),
        "java_hashcode": "0x%08x" % _java_cert_hashcode(der),
        "sha256": hashlib.sha256(der).hexdigest(),
        "lineage": [base64.b64encode(c).decode() for c in certs[1:]],
    }


def extract_vendor_hardware_props(factory_url, cookie, work_dir):
    """Pull the SoC/hardware props from the factory image's vendor/build.prop.

    Returns a {name: value} dict of the props in _HW_PROP_KEYS plus a derived
    plain ``ro.hardware`` (a runtime bootloader value absent from build.prop; on
    a Google Tensor device it equals the SoC platform, e.g. zuma). Best-effort:
    returns {} if vendor.img or the extraction tool is unavailable.
    """
    files = _fetch_image_members(factory_url, cookie, ["vendor.img"], work_dir)
    if "vendor.img" not in files:
        return {}
    text = _read_build_prop(files["vendor.img"])
    if not text:
        return {}
    props = {}
    for line in text.splitlines():
        line = line.strip()
        if line.startswith("#") or "=" not in line:
            continue
        key, value = line.split("=", 1)
        if key in _HW_PROP_KEYS:
            props[key] = value
    # ro.hardware is set by init from the bootloader (ro.boot.hardware), not
    # build.prop. For a Google/Tensor device it is the SoC platform codename.
    if props.get("ro.soc.manufacturer") == "Google" and props.get("ro.board.platform"):
        props["ro.hardware"] = props["ro.board.platform"]
    return props


def extract_baseband(factory_url, cookie, work_dir):
    """Pull the modem baseband version from the factory image's android-info.txt.

    The bootloader's ``require version-baseband=`` line is exactly the string a
    real device reports as ``gsm.version.baseband``, so publishing it keeps
    the probe from seeing a Qualcomm/WAIPIO modem on a device claiming to be a
    Tensor Pixel. Best-effort: returns {} if android-info.txt is unavailable.
    """
    files = _fetch_image_members(factory_url, cookie, ["android-info.txt"], work_dir)
    if "android-info.txt" not in files:
        return {}
    for line in open(files["android-info.txt"], errors="ignore"):
        line = line.strip()
        if line.startswith("require version-baseband="):
            return {"gsm.version.baseband": line.split("=", 1)[1]}
    return {}


def extract_vbmeta_values(factory_url, cookie, work_dir, hash_algorithm="sha256"):
    """Compute the real verified-boot props for a factory image.

    Returns a dict:
      {
        "sysprops": { "ro.boot.vbmeta.digest": ..., "partition.system.verified": ..., ... },
        "verified_boot_key": "<sha256 hex of the top-level AVB public key>",
      }

    Raises on any failure — the caller decides whether to treat vbmeta as
    optional. avbtool is imported here so a caller that never needs vbmeta does
    not pay for it.
    """
    import hashlib
    sys.path.insert(0, _AVB_DIR)
    import avbtool

    os.makedirs(work_dir, exist_ok=True)
    # boot/init_boot are needed only to reproduce the top-level vbmeta digest;
    # the vbmeta_* partitions carry the hashtree root digests we publish.
    files = _fetch_image_members(
        factory_url, cookie,
        ["vbmeta.img", "vbmeta_system.img", "vbmeta_vendor.img",
         "boot.img", "init_boot.img"],
        work_dir)
    if "vbmeta.img" not in files:
        raise RuntimeError("factory image has no vbmeta.img")

    avb = avbtool.Avb()

    # --- top-level vbmeta: digest + total chained size + verified-boot key ---
    main_desc, main_header, main_blob = _vbmeta_blob(avb, files["vbmeta.img"])
    hasher = hashlib.new(hash_algorithm)
    hasher.update(main_blob)
    total_size = len(main_blob)

    # Walk chain partitions in descriptor order, exactly like avbtool's
    # calculate_vbmeta_digest, so both the digest and the reported vbmeta.size
    # (== length of everything hashed) match what the bootloader publishes.
    for desc in main_desc:
        if isinstance(desc, avbtool.AvbChainPartitionDescriptor):
            member = desc.partition_name + ".img"
            if member not in files:
                raise RuntimeError(f"chain partition {member} missing from image")
            _, _, ch_blob = _vbmeta_blob(avb, files[member])
            hasher.update(ch_blob)
            total_size += len(ch_blob)

    verified_boot_key = hashlib.sha256(
        _embedded_public_key(main_header, main_blob)).hexdigest()

    sysprops = {
        "ro.boot.vbmeta.digest": hasher.hexdigest(),
        "ro.boot.vbmeta.hash_alg": hash_algorithm,
        "ro.boot.vbmeta.size": str(total_size),
        "ro.boot.vbmeta.invalidate_on_error": _INVALIDATE_ON_ERROR,
    }

    # --- dm-verity partitions: root digests from every hashtree descriptor ---
    # Hashtree descriptors live in the main vbmeta and the chained vbmeta_*
    # partitions. Their set is exactly the dm-verity partitions init publishes
    # partition.<name>.verified.* for — derived, never hardcoded.
    hashtree_sources = [main_desc]
    for member in ("vbmeta_system.img", "vbmeta_vendor.img"):
        if member in files:
            desc, _, _ = _vbmeta_blob(avb, files[member])
            hashtree_sources.append(desc)

    for descriptors in hashtree_sources:
        for desc in descriptors:
            if not isinstance(desc, avbtool.AvbHashtreeDescriptor):
                continue
            name = desc.partition_name
            base = f"partition.{name}.verified"
            sysprops[base] = _VERITY_MODE_ENFORCING
            sysprops[base + ".hash_alg"] = desc.hash_algorithm
            sysprops[base + ".root_digest"] = desc.root_digest.hex()
            sysprops[base + ".check_at_most_once"] = _CHECK_AT_MOST_ONCE

    # --- SoC / hardware props from vendor/build.prop (best-effort) ---
    # Keeps the probe from seeing a Qualcomm/Adreno/QSEE device that claims to
    # be a Tensor Pixel. A failure here (no vendor.img, no debugfs) only omits
    # these props; the vbmeta values above are unaffected.
    try:
        sysprops.update(extract_vendor_hardware_props(factory_url, cookie, work_dir))
    except Exception as e:
        print(f"  WARN: could not read vendor hardware props ({e})", file=sys.stderr)

    # --- modem baseband from android-info.txt (best-effort) ---
    # Same rationale as the SoC props: a WAIPIO/Qualcomm gsm.version.baseband on
    # a device claiming to be a Tensor Pixel is an incoherence the probe reads.
    try:
        sysprops.update(extract_baseband(factory_url, cookie, work_dir))
    except Exception as e:
        print(f"  WARN: could not read baseband ({e})", file=sys.stderr)

    return {"sysprops": sysprops, "verified_boot_key": verified_boot_key}


if __name__ == "__main__":
    # Self-test against the known akita CP1A.260505.005 factory image.
    url = "https://dl.google.com/dl/android/aosp/akita-cp1a.260505.005-factory-4790ccab.zip"
    if len(sys.argv) > 1 and sys.argv[1] == "cert":
        out = extract_platform_cert(url, "devsite_wall_acks=nexus-image-tos",
                                    os.path.expanduser("~/.cache/vbmeta_extract_selftest"))
        import json
        printable = {k: (v if k != "pem" else v[:60] + "...") for k, v in out.items()}
        print(json.dumps(printable, indent=2))
        dest = os.path.join(os.path.expanduser("~/.cache/vbmeta_extract_selftest"),
                            "stock_platform_cert.pem")
        with open(dest, "w") as f:
            f.write(out["pem"])
        print(f"PEM written to {dest}")
    else:
        out = extract_vbmeta_values(url, "devsite_wall_acks=nexus-image-tos",
                                    os.path.expanduser("~/.cache/vbmeta_extract_selftest"))
        import json
        print(json.dumps(out, indent=2))
