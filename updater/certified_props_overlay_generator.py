#!/usr/bin/env python3
"""
Certified Props Overlay Generator - Generates fingerprint overlay for Play Integrity
Automatically fetches device fingerprints from Google Pixel Beta OTAs
Based on osm0sis' autopif2.sh
"""

import argparse
import json
import os
import re
import requests
import sys
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta
from typing import Dict, Optional
import random


class FingerprintFetcher:
    """Fetches Android device fingerprints from various sources"""

    # Google's developer pages for Android versions
    ANDROID_VERSIONS_URL = "https://developer.android.com/about/versions"
    # Stable full-OTA image list. The download table is behind a devsite ToS
    # wall; replaying the acknowledgement cookie reveals the same server-rendered
    # rows the page shows after you click "Acknowledge".
    STABLE_OTA_URL = "https://developers.google.com/android/ota"
    STABLE_OTA_COOKIE = "devsite_wall_acks=nexus-ota-tos"
    # Factory image list (raw partition images, incl. the signed vbmeta from
    # which the real verified-boot values are read). Behind its own ToS wall.
    STABLE_IMAGES_URL = "https://developers.google.com/android/images"
    STABLE_IMAGES_COOKIE = "devsite_wall_acks=nexus-image-tos"

    # Launch API level (ro.product.first_api_level / DEVICE_INITIAL_SDK_INT) by
    # Pixel codename = the SDK the device SHIPPED with. The integrity probe
    # cross-checks it against the claimed model, so a wrong value is an
    # inconsistency no stock device has. It is NOT in the OTA metadata, so
    # it is a maintained per-device constant.
    LAUNCH_API_LEVEL = {
        "oriole": 31, "raven": 31, "bluejay": 31,             # Pixel 6 / 6 Pro / 6a   (A12)
        "panther": 33, "cheetah": 33, "lynx": 33,             # Pixel 7 / 7 Pro / 7a   (A13)
        "tangorpro": 33, "felix": 33,                         # Pixel Tablet / Fold    (A13)
        "shiba": 34, "husky": 34, "akita": 34,                # Pixel 8 / 8 Pro / 8a   (A14)
        "tokay": 34, "caiman": 34, "komodo": 34, "comet": 34, # Pixel 9 / Pro / XL / Fold (A14)
        "tegu": 35,                                           # Pixel 9a               (A15)
    }
    DEFAULT_LAUNCH_API_LEVEL = 34

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def fetch_from_google(self, force_preview: bool = False, depth: int = 1,
                          version: Optional[int] = None) -> Optional[Dict[str, str]]:
        """
        Fetch latest Pixel Beta fingerprint from Google Developer pages
        Mimics osm0sis' autopif2.sh logic
        """
        try:
            print("Crawling Android Developers for latest Pixel Beta...")

            # Get versions page
            resp = self.session.get(self.ANDROID_VERSIONS_URL, timeout=10)
            resp.raise_for_status()

            # Find beta version URLs (sorted reverse, unique)
            beta_urls = list(set(re.findall(r'href="(/about/versions/[^"]+\d)"', resp.text)))
            beta_urls.sort(reverse=True)

            if not beta_urls:
                print("No beta version URLs found")
                return None

            # Filter by version if specified
            if version is not None:
                beta_urls = [u for u in beta_urls if u.rstrip('/').endswith(f'/{version}')
                             or u.rstrip('/').endswith(f'-{version}')]
                if not beta_urls:
                    print(f"No beta URLs found for Android {version}")
                    return None
                print(f"Filtered to Android {version}")

            # Get the latest or second latest based on preview status
            latest_url = f"https://developer.android.com{beta_urls[0]}"
            resp = self.session.get(latest_url, timeout=10)
            resp.raise_for_status()

            is_preview = bool(re.search(r'Developer Preview|tooltip>.*preview program', resp.text))

            if is_preview and not force_preview and len(beta_urls) > 1:
                # Use second latest if current is preview
                beta_url = f"https://developer.android.com{beta_urls[1]}"
                print("Skipping Developer Preview, using previous beta")
            else:
                beta_url = latest_url
                if is_preview:
                    print("Using Developer Preview")

            resp = self.session.get(beta_url, timeout=10)
            resp.raise_for_status()

            # Find OTA download pages
            ota_links = re.findall(r'href="([^"]*download-ota[^"]*)"', resp.text)
            if not ota_links:
                print("No OTA download links found")
                return None

            if depth > 0:
                # Specific depth requested
                if len(ota_links) < depth:
                    print("Not enough OTA download links found")
                    return None
                pages_to_try = [(depth, ota_links[depth-1])]
            else:
                # Try all pages, pick newest security patch
                pages_to_try = [(i+1, link) for i, link in enumerate(ota_links)]

            best_result = None
            best_patch = ""

            for page_depth, link in pages_to_try:
                ota_url = f"https://developer.android.com{link}"
                print(f"Fetching OTA page (depth={page_depth}): {ota_url}")

                page_resp = self.session.get(ota_url, timeout=10)
                page_resp.raise_for_status()

                # Extract Android version info
                version_match = re.search(r'tooltip>Android\s+([^<]+)', page_resp.text)
                qpr_match = re.search(r'tooltip>QPR.*?\s+Beta', page_resp.text)

                if version_match:
                    version_str = f"Android {version_match.group(1)}"
                    if qpr_match:
                        version_str += f" {qpr_match.group(0).split('>')[-1]}"
                    print(version_str)

                result = self._parse_ota_page(page_resp.text)
                if result:
                    if version is not None and not self._build_id_matches_version(
                            self._build_id(result), version):
                        print(f"  -> build {self._build_id(result) or '?'} is not "
                              f"Android {version} (want {self._expected_build_letter(version)}* "
                              f"build ID), skipping")
                        continue
                    patch = result.get('SECURITY_PATCH', '')
                    if depth > 0:
                        return result
                    if patch > best_patch:
                        best_patch = patch
                        best_result = result
                        print(f"  -> security patch: {patch} (best so far)")
                        # Stop early if patch is from current month
                        current_month = datetime.now().strftime('%Y-%m')
                        if patch.startswith(current_month):
                            print(f"  -> current month patch found, stopping search")
                            return best_result
                    else:
                        print(f"  -> security patch: {patch} (skipping, older)")

            return best_result

        except Exception as e:
            print(f"Error fetching from Google: {e}")
            return None

    def fetch_from_google_stable(self, version: Optional[int] = None,
                                 min_devices: int = 2) -> Optional[Dict[str, str]]:
        """Fetch the newest *stable* release fingerprint from Google's full-OTA
        image list.

        Unlike the Beta crawl, these are the exact builds shipping to retail
        Pixels, so the fingerprint cannot be burned without breaking real
        devices. Selection: the newest build (by build-ID date) whose HTML row
        is labelled with the requested Android version AND that ships on at
        least ``min_devices`` models — the device-count floor skips one-off
        device-specific trains (e.g. a tablet's private CP1A/BD6A build that is
        still labelled "16.0.0") and lands on the mainstream flagship release.
        The version comes from the row's authoritative "16.0.0 (...)" label,
        never from the build-ID prefix letter, which is not a reliable signal.
        """
        try:
            print("Fetching stable full-OTA list from Google...")
            resp = self.session.get(
                self.STABLE_OTA_URL, timeout=15,
                headers={'Cookie': self.STABLE_OTA_COOKIE})
            resp.raise_for_status()
            html = resp.text

            # codename -> marketing model, from the per-device <h2> headings.
            models = dict(re.findall(
                r'<h2 id="([^"]+)"[^>]*data-text=\'"[^"]*" for ([^\']+)\'', html))

            # Each OTA is a table row:
            #   <td>16.0.0 (BP4A.251205.006, Dec 2025)</td>
            #   <td><a href="...codename-ota-buildid-hash.zip">Link</a></td>
            builds = {}   # build_id -> list of (codename, url, model)
            for block in re.findall(r'<tr id="[^"]*">(.*?)</tr>', html, re.DOTALL):
                vm = re.search(r'<td>([\d.]+)\s*\(([^,]+),', block)
                um = re.search(r'href="(https://dl\.google\.com/[^"]+\.zip)"', block)
                if not vm or not um:
                    continue
                version_label, build_id = vm.group(1), vm.group(2).strip()
                if version is not None and version_label.split('.')[0] != str(version):
                    continue
                url = um.group(1)
                codename = url.rsplit('/', 1)[-1].split('-ota-')[0]
                builds.setdefault(build_id, []).append(
                    (codename, url, models.get(codename, codename)))

            eligible = {b: d for b, d in builds.items() if len(d) >= min_devices}
            if not eligible:
                print(f"  No stable Android {version} build shipping on "
                      f">= {min_devices} devices found")
                return None

            def newness(build_id: str):
                # e.g. BP4A.260205.002[.a1]: sort by (date, build number), and
                # prefer the base build over a ".<letter><digit>" carrier variant.
                m = re.search(r'\.(\d{6})\.(\d+)', build_id)
                if not m:
                    return ('', 0, 0)
                is_base = 0 if re.search(r'\.\d+\.[a-z]', build_id, re.I) else 1
                return (m.group(1), int(m.group(2)), is_base)

            newest = max(eligible, key=newness)
            codename, url, model = sorted(eligible[newest])[0]
            print(f"  Newest stable Android {version}: {newest} "
                  f"({len(eligible[newest])} devices) -> {model} ({codename})")

            result = self._fingerprint_from_ota(
                url, model, extra_headers={'Cookie': self.STABLE_OTA_COOKIE})
            if not result:
                print("  Failed to read fingerprint from OTA metadata")
                return result

            # Pull the real verified-boot values from the matching factory
            # image so the spoofed "locked/green" state is backed by coherent
            # vbmeta/dm-verity data. Best-effort: a failure here must not break
            # the fingerprint refresh, only omit the vbmeta props.
            self._attach_vbmeta_values(result, codename, newest)
            return result
        except Exception as e:
            print(f"Error fetching stable OTA: {e}")
            return None

    def _find_factory_url(self, codename: str, build_id: str) -> Optional[str]:
        """Locate the factory-image zip for an exact codename+build on the
        images page. Returns None if not published (older/newer than OTA)."""
        resp = self.session.get(self.STABLE_IMAGES_URL, timeout=30,
                                headers={'Cookie': self.STABLE_IMAGES_COOKIE})
        resp.raise_for_status()
        pattern = (r'https://dl\.google\.com/dl/android/aosp/'
                   + re.escape(codename) + '-' + re.escape(build_id.lower())
                   + r'-factory-[0-9a-f]+\.zip')
        m = re.search(pattern, resp.text)
        return m.group(0) if m else None

    def _attach_vbmeta_values(self, result: Dict[str, str], codename: str,
                              build_id: str) -> None:
        """Read the factory image's real vbmeta/dm-verity values and stash them
        on ``result`` under private keys the OverlayGenerator turns into raw
        SYSPROP.* / ATTEST.* overlay items."""
        try:
            import shutil
            sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
            import vbmeta_extract

            factory_url = self._find_factory_url(codename, build_id)
            if not factory_url:
                print(f"  No factory image for {codename} {build_id}; "
                      "skipping vbmeta values")
                return
            print(f"  Reading verified-boot values from {factory_url}")
            repo_root = os.path.dirname(os.path.dirname(os.path.dirname(
                os.path.dirname(os.path.abspath(__file__)))))
            work_dir = os.path.join(repo_root, ".cache", "vbmeta-getter")
            try:
                values = vbmeta_extract.extract_vbmeta_values(
                    factory_url, self.STABLE_IMAGES_COOKIE, work_dir)
                result['_RAW_SYSPROPS'] = values['sysprops']
                result['_ATTEST'] = {'VBOOT_KEY': values['verified_boot_key']}
                print(f"  vbmeta.digest={values['sysprops']['ro.boot.vbmeta.digest']} "
                      f"({len(values['sysprops'])} raw props, "
                      f"verifiedBootKey={values['verified_boot_key'][:16]}...)")
                # The stock platform signing cert: the probe hashes the
                # `android` package's signer, so the conformance attributes
                # carry the stock cert for the report-time signing-info
                # spoof. Best-effort, independent of the vbmeta values.
                try:
                    cert = vbmeta_extract.extract_platform_cert(
                        factory_url, self.STABLE_IMAGES_COOKIE, work_dir)
                    result['_ATTEST']['PLATFORM_CERT'] = cert['der_b64']
                    if cert['lineage']:
                        result['_ATTEST']['PLATFORM_CERT_LINEAGE'] = \
                            ','.join(cert['lineage'])
                    print(f"  platform cert sha256={cert['sha256'][:16]}... "
                          f"(java_hashcode={cert['java_hashcode']})")
                except Exception as e:
                    print(f"  WARN: could not extract platform cert ({e}); "
                          "overlay will omit it")
                # KeyMint moduleHash of the claimed device: SHA-256 over the
                # DER-encoded APEX Modules set (KeyMint 4.0 attestations carry
                # it in softwareEnforced). Best-effort, independent.
                try:
                    mh = vbmeta_extract.extract_module_hash(
                        factory_url, self.STABLE_IMAGES_COOKIE, work_dir)
                    result['_ATTEST']['MODULE_HASH'] = mh
                    print(f"  moduleHash={mh[:16]}...")
                except Exception as e:
                    print(f"  WARN: could not compute module hash ({e}); "
                          "overlay will omit it")
            finally:
                shutil.rmtree(work_dir, ignore_errors=True)
        except Exception as e:
            print(f"  WARN: could not read vbmeta values ({e}); "
                  "overlay will omit them")

    def _fingerprint_from_ota(self, ota_url: str, model: str,
                              extra_headers: Optional[Dict[str, str]] = None
                              ) -> Optional[Dict[str, str]]:
        """Read an OTA zip's metadata head and assemble a fingerprint dict.

        Only the first 2 MB is read (the OTA metadata block lives near the
        start), then post-build (the full build fingerprint) and the
        security-patch-level are extracted, exactly like autopif2.sh.
        """
        try:
            resp = self.session.get(ota_url, stream=True, timeout=15,
                                    headers=extra_headers or {})
            resp.raise_for_status()
            metadata = b''
            for chunk in resp.iter_content(chunk_size=8192):
                metadata += chunk
                if len(metadata) >= 2 * 1024 * 1024:
                    break
            text = metadata.decode('utf-8', errors='ignore')
            fp_match = re.search(r'post-build=([^\x00\n]+)', text)
            sp_match = re.search(r'(?:post-)?security-patch-level=([^\x00\n]+)', text)
            if not fp_match or not sp_match:
                print("  post-build / security-patch-level not found in OTA metadata")
                return None
            fingerprint = fp_match.group(1).strip()
            parts = fingerprint.split('/')
            device = parts[2].split(':')[0] if len(parts) > 2 else ""
            initial_sdk = self.LAUNCH_API_LEVEL.get(device, self.DEFAULT_LAUNCH_API_LEVEL)
            if device not in self.LAUNCH_API_LEVEL:
                print(f"  WARN: no launch API level known for '{device}', "
                      f"defaulting DEVICE_INITIAL_SDK_INT to {initial_sdk}")
            return {
                "MANUFACTURER": "Google",
                "MODEL": model,
                "FINGERPRINT": fingerprint,
                "PRODUCT": parts[1] if len(parts) > 1 else "",
                "DEVICE": device,
                "SECURITY_PATCH": sp_match.group(1).strip(),
                "DEVICE_INITIAL_SDK_INT": str(initial_sdk),
                "BRAND": "google",
                "RELEASE": fingerprint.split(':')[1].split('/')[0] if ':' in fingerprint else "",
                "ID": parts[3] if len(parts) >= 4 else "",
                "INCREMENTAL": parts[4].split(':')[0] if len(parts) >= 5 else "",
                "TYPE": "user",
                "TAGS": "release-keys",
            }
        except Exception as e:
            print(f"  Error reading OTA metadata: {e}")
            return None

    def _parse_ota_page(self, html: str) -> Optional[Dict[str, str]]:
        """Parse OTA page to extract device fingerprint info"""
        # Pair each device's MODEL, PRODUCT and OTA URL through the shared
        # codename so they can never cross-associate. On the OTA pages every
        # device is a `<tr id="CODENAME">` whose first <td> is the marketing
        # MODEL; the download URL lives in a separate modal dialog but its
        # filename is prefixed with the same codename (ota/CODENAME_beta-ota-...).
        # Pairing MODEL to the URL by codename avoids the misalignment that
        # independent page-wide regexes hit when their lists differ in
        # length/order — which would ship an inconsistent fingerprint (e.g. a
        # marketing name on the wrong codename) and fail Play Integrity.
        ota_by_codename = {}
        for url, codename in re.findall(
                r'href="([^"]*ota/([^/"]+)_beta-ota-[^"]*)"', html):
            ota_by_codename.setdefault(codename, url)

        devices = []
        for codename, body in re.findall(r'<tr id="([^"]+)">(.*?)</tr>', html,
                                         re.DOTALL):
            model_match = re.search(r'<td>([^<]+)</td>', body)
            if codename in ota_by_codename and model_match:
                devices.append((model_match.group(1).strip(),
                                f"{codename}_beta", ota_by_codename[codename]))

        if not devices:
            print("Failed to extract device information from OTA page")
            return None

        # Select random device
        model, product, ota_url = devices[random.randint(0, len(devices) - 1)]
        device = product.replace('_beta', '')

        print(f"Selected: {model} ({product})")

        # Fetch OTA metadata (with 2MB limit like autopif2.sh)
        try:
            # Use a limited request to avoid downloading entire OTA
            resp = self.session.get(ota_url, stream=True, timeout=10)
            resp.raise_for_status()

            # Read first 2MB
            metadata = b''
            for chunk in resp.iter_content(chunk_size=8192):
                metadata += chunk
                if len(metadata) >= 2 * 1024 * 1024:  # 2MB limit
                    break

            # Extract fingerprint and security patch from metadata
            metadata_str = metadata.decode('utf-8', errors='ignore')

            fp_match = re.search(r'post-build=([^\x00\n]+)', metadata_str)
            sp_match = re.search(r'security-patch-level=([^\x00\n]+)', metadata_str)

            if not fp_match or not sp_match:
                print("Failed to extract fingerprint/security patch from OTA metadata")
                return None

            fingerprint = fp_match.group(1)
            security_patch = sp_match.group(1)

            # Calculate release and expiry dates
            release_date_match = re.search(r'Release date.*?<td>([^<]+)</td>', html)
            if release_date_match:
                try:
                    release_date = datetime.strptime(release_date_match.group(1), '%B %d, %Y')
                    expiry_date = release_date + timedelta(weeks=6)
                    print(f"Beta Released: {release_date.strftime('%Y-%m-%d')}")
                    print(f"Estimated Expiry: {expiry_date.strftime('%Y-%m-%d')}")
                except:
                    pass

            # Build fingerprint dictionary
            return {
                "MANUFACTURER": "Google",
                "MODEL": model,
                "FINGERPRINT": fingerprint,
                "PRODUCT": product,
                "DEVICE": device,
                "SECURITY_PATCH": security_patch,
                "DEVICE_INITIAL_SDK_INT": "32",
                # Extract additional fields from fingerprint
                "BRAND": "google",
                "RELEASE": fingerprint.split(':')[1].split('/')[0] if ':' in fingerprint else "",
                "ID": fingerprint.split('/')[3] if fingerprint.count('/') >= 4 else "",
                "INCREMENTAL": fingerprint.split('/')[4].split(':')[0] if fingerprint.count('/') >= 4 else "",
                "TYPE": "user",
                "TAGS": "release-keys"
            }

        except Exception as e:
            print(f"Error fetching OTA metadata: {e}")
            return None

    def fetch_from_fallback(self) -> Optional[Dict[str, str]]:
        """Fetch fingerprint from fallback sources"""
        fallback_sources = [
            {
                "name": "osm0sis PlayIntegrityFork example",
                "url": "https://raw.githubusercontent.com/osm0sis/PlayIntegrityFork/main/module/example.pif.json",
                "type": "json"
            },
            {
                "name": "KOWX712 PIF Fork",
                "url": "https://raw.githubusercontent.com/KOWX712/PlayIntegrityFix/inject_s/module/pif.prop",
                "type": "prop"
            }
        ]

        for source in fallback_sources:
            try:
                print(f"Trying fallback source: {source['name']}")
                resp = self.session.get(source['url'], timeout=10)
                resp.raise_for_status()

                if source['type'] == 'prop':
                    return self._parse_prop_format(resp.text)
                elif source['type'] == 'json':
                    return self._parse_json_format(resp.text)

            except Exception as e:
                print(f"Failed to fetch from {source['name']}: {e}")
                continue

        return None

    def _parse_json_format(self, content: str) -> Dict[str, str]:
        """Parse JSON format fingerprint data"""
        try:
            data = json.loads(content)
            # Clean up the data - remove comments, ensure required fields
            clean_data = {}
            for key, value in data.items():
                if not key.startswith('//') and value:
                    clean_data[key] = value
            return clean_data
        except:
            return None

    def _parse_prop_format(self, content: str) -> Dict[str, str]:
        """Parse pif.prop format into dictionary"""
        result = {}
        for line in content.strip().split('\n'):
            if '=' in line and not line.startswith('#'):
                key, value = line.split('=', 1)
                result[key] = value

        # Extract additional fields from fingerprint if available
        if 'FINGERPRINT' in result:
            fp_parts = result['FINGERPRINT'].split('/')
            if len(fp_parts) >= 4:
                build_parts = fp_parts[2].split(':')
                if len(build_parts) >= 2:
                    result['RELEASE'] = build_parts[1]
                    result['ID'] = fp_parts[3].split('/')[0] if '/' in fp_parts[3] else fp_parts[3]

        return result

    def fetch_fingerprint(self, force_preview: bool = False, depth: int = 1,
                          version: Optional[int] = None,
                          stable: bool = False) -> Optional[Dict[str, str]]:
        """Main method to fetch fingerprint from any available source"""
        print("Pixel pif.json generator")
        print("  based on osm0sis @ xda-developers")
        if version is not None:
            print(f"  filtering for Android {version}")
        print("")

        # A stable retail fingerprint is preferred when requested: it is a build
        # shipping to real devices, so it cannot be burned without collateral.
        if stable:
            fingerprint = self.fetch_from_google_stable(version=version)
            if fingerprint:
                print("Successfully fetched stable fingerprint")
                return fingerprint
            print("Stable fetch failed; falling back to Beta crawl")

        # Try Google first
        fingerprint = self.fetch_from_google(force_preview=force_preview, depth=depth,
                                             version=version)
        if fingerprint:
            if version is not None and not self._matches_version(fingerprint, version):
                print(f"Warning: fetched fingerprint is not Android {version}, skipping")
            else:
                print("Successfully fetched from Google")
                return fingerprint

        # Try fallback sources
        fingerprint = self.fetch_from_fallback()
        if fingerprint:
            if version is not None and not self._matches_version(fingerprint, version):
                print(f"Warning: fallback fingerprint is not Android {version}, skipping")
            else:
                print("Successfully fetched from fallback source")
                return fingerprint

        print("Failed to fetch fingerprint from any source")
        return None

    def _matches_version(self, fingerprint: Dict[str, str], version: int) -> bool:
        """Check that a fingerprint is a genuine build for the requested version.

        A real Google build is internally consistent: the numeric platform
        release AND the build-ID prefix letter encode the same Android version.
        During a beta transition the scraper can land on a *next* version build
        (e.g. an Android 17 "CP..." / Cinnamon Bun build) whose OTA fingerprint
        still carries a stale release token of 16 — that combination never ships
        from Google and fails Play Integrity. Require BOTH signals to agree.
        """
        return (self._release_matches(fingerprint, version)
                and self._build_id_matches_version(self._build_id(fingerprint), version))

    def _release_matches(self, fingerprint: Dict[str, str], version: int) -> bool:
        """Check the numeric VERSION.RELEASE token against the requested version."""
        release = fingerprint.get('RELEASE', '')
        try:
            return int(release) == version
        except ValueError:
            # Non-numeric release (e.g. CinnamonBun) — check the fingerprint string
            fp = fingerprint.get('FINGERPRINT', '')
            # Fingerprint format: brand/product/device:RELEASE/ID/...
            if ':' in fp:
                fp_release = fp.split(':')[1].split('/')[0]
                try:
                    return int(fp_release) == version
                except ValueError:
                    return False
            return False

    @staticmethod
    def _build_id(fingerprint: Dict[str, str]) -> str:
        """Return the platform build ID (e.g. 'BP4A.251205.006') for a fingerprint."""
        build_id = fingerprint.get('ID', '')
        if build_id:
            return build_id
        # Fingerprint format: brand/product/device:RELEASE/ID/INCREMENTAL:...
        parts = fingerprint.get('FINGERPRINT', '').split('/')
        return parts[3] if len(parts) >= 4 else ''

    @staticmethod
    def _expected_build_letter(version: int) -> str:
        """First letter of the build ID for a given Android platform version.

        Post-wrap AOSP scheme (letters restart at 'A' after Android 14 'U'):
        A=15 (VanillaIceCream), B=16 (Baklava), C=17 (Cinnamon Bun), ... so the
        letter is 'A' + (version - 15). Only needs to be correct for the versions
        this tool targets (>= 15).
        """
        return chr(ord('A') + version - 15)

    def _build_id_matches_version(self, build_id: str, version: int) -> bool:
        """True if the build ID's prefix letter matches the requested version."""
        return bool(build_id) and build_id[:1].upper() == self._expected_build_letter(version)


class OverlayGenerator:
    """Generates Android overlay files and pif.json"""

    def __init__(self, fingerprint_data: Dict[str, str]):
        self.fingerprint_data = fingerprint_data

    def generate_all(self, output_dir: str = "CertifiedPropsOverlay"):
        """Generate all files needed for fingerprint spoofing"""
        # Create proper overlay structure
        res_dir = os.path.join(output_dir, "res", "values")
        os.makedirs(res_dir, exist_ok=True)

        # Generate fingerprint overlay XML
        fp_xml_path = os.path.join(res_dir, "arrays.xml")
        self._generate_fingerprint_xml(fp_xml_path)

        # Generate pif.json in output root
        pif_json_path = os.path.join(output_dir, "pif.json")
        self._generate_pif_json(pif_json_path)

        # Create Android.bp for the overlay
        self._generate_android_bp(output_dir)

        # Create AndroidManifest.xml
        self._generate_manifest(output_dir
)

    def _generate_fingerprint_xml(self, output_path: str):
        """Generate fingerprint overlay XML"""
        # Create XML structure
        resources = ET.Element('resources')
        array = ET.SubElement(resources, 'array', name='control_conformance_attributes')

        # Map fingerprint data to property format
        property_map = [
            ('PRODUCT', 'PRODUCT'),
            ('DEVICE', 'DEVICE'),
            ('MANUFACTURER', 'MANUFACTURER'),
            ('BRAND', 'BRAND'),
            ('MODEL', 'MODEL'),
            ('FINGERPRINT', 'FINGERPRINT'),
            ('ID', 'ID'),
            ('INCREMENTAL', 'VERSION.INCREMENTAL'),
            ('TYPE', 'TYPE'),
            ('TAGS', 'TAGS'),
            ('RELEASE', 'VERSION.RELEASE'),
            ('SECURITY_PATCH', 'VERSION.SECURITY_PATCH'),
            ('DEVICE_INITIAL_SDK_INT', 'VERSION.DEVICE_INITIAL_SDK_INT')
        ]

        for json_key, prop_key in property_map:
            if json_key in self.fingerprint_data:
                value = self.fingerprint_data[json_key]
                if value:
                    item = ET.SubElement(array, 'item')
                    item.text = f"{prop_key}:{value}"

        # Raw system properties (real verified-boot values from the factory
        # image). These are applied verbatim by SimplePropImitation via the
        # SYSPROP. prefix, not mapped onto Build.* fields.
        for name, value in sorted(
                self.fingerprint_data.get('_RAW_SYSPROPS', {}).items()):
            if value:
                item = ET.SubElement(array, 'item')
                item.text = f"SYSPROP.{name}:{value}"

        # Attestation-only values with no real sysprop counterpart (the
        # verified-boot key hash). Stashed by SimplePropImitation for
        # KeyboxImitationHooks under the ATTEST. prefix; never set as a prop.
        for name, value in sorted(
                self.fingerprint_data.get('_ATTEST', {}).items()):
            if value:
                item = ET.SubElement(array, 'item')
                item.text = f"ATTEST.{name}:{value}"

        # Write XML file
        self._write_xml(resources, output_path)
        print(f"Generated: {output_path}")

    def _generate_pif_json(self, output_path: str):
        """Generate pif.json for Play Integrity Fix module"""
        # Emit only the Build-field fingerprint; private keys (prefixed with
        # '_', e.g. the raw vbmeta props) are framework-overlay concerns and
        # would confuse a stock PIF module that keys on Build.* fields.
        pif_data = {k: v for k, v in self.fingerprint_data.items()
                    if not k.startswith('_')}
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(pif_data, f, indent=2)
            f.write('\n')  # Add final newline

        print(f"Generated: {output_path}")

    def _generate_android_bp(self, output_dir: str):
        """Generate Android.bp file for the overlay"""
        android_bp_content = '''//
// SPDX-License-Identifier: Apache-2.0
//

runtime_resource_overlay {
    name: "CertifiedPropsOverlay",
    product_specific: true,
    sdk_version: "current",
    resource_dirs: ["res"],
}
'''

        bp_path = os.path.join(output_dir, "Android.bp")
        with open(bp_path, 'w') as f:
            f.write(android_bp_content)

        print(f"Generated: {bp_path}")


    def _generate_manifest(self, output_dir: str):
        """Generate AndroidManifest.xml for the overlay"""
        manifest_content = '''<?xml version="1.0" encoding="utf-8"?>
<manifest
    xmlns:android="http://schemas.android.com/apk/res/android"
    package="custom.overlay.corporatecontrolsatisfier">
    <application android:hasCode="false" />
    <overlay
        android:targetPackage="custom.corporatecontrolsatisfier"
        android:isStatic="true" />
</manifest>
'''
        manifest_path = os.path.join(output_dir, "AndroidManifest.xml")
        with open(manifest_path, 'w') as f:
            f.write(manifest_content)
        print(f"Generated: {manifest_path}")


    def _write_xml(self, root: ET.Element, output_path: str):
        """Write XML with proper formatting"""
        # Convert to string with declaration
        xml_str = ET.tostring(root, encoding='unicode', method='xml')

        # Add XML declaration and format
        formatted_xml = '<?xml version="1.0" encoding="utf-8"?>\n'
        formatted_xml += self._prettify_xml(xml_str)

        # Write file
        with open(output_path, 'w', encoding='utf-8') as f:
            f.write(formatted_xml)

    def _prettify_xml(self, xml_str: str) -> str:
        """Basic XML prettification"""
        lines = []
        indent = 0

        # Split into tags
        parts = re.split(r'(>)(<)', xml_str)
        current_line = ''

        for part in parts:
            if part == '><':
                lines.append(current_line + '>')
                current_line = '<'
            else:
                current_line += part

        if current_line:
            lines.append(current_line)

        # Format with indentation
        formatted = []
        for line in lines:
            line = line.strip()
            if line.startswith('</'):
                indent -= 1

            formatted.append('    ' * indent + line)

            if line.startswith('<') and not line.startswith('</') and not line.endswith('/>'):
                if '</' not in line:  # Opening tag
                    indent += 1

        return '\n'.join(formatted)


def main():
    parser = argparse.ArgumentParser(
        description='Certified Props Overlay Generator - Generates fingerprint overlay for Play Integrity',
        epilog='Based on osm0sis autopif2.sh'
    )
    parser.add_argument(
        '--output-dir',
        default='CertifiedPropsOverlay',
        help='Output directory for generated files (default: CertifiedPropsOverlay)'
    )
    parser.add_argument(
        '-p', '--preview',
        action='store_true',
        help='Force use of Developer Preview builds'
    )
    parser.add_argument(
        '-d', '--depth',
        type=int,
        default=0,
        choices=range(0, 10),
        help='OTA page depth to use (0=auto-select newest patch, default: 0)'
    )
    parser.add_argument(
        '-v', '--version',
        type=int,
        help='Android version to filter for (e.g. 16)'
    )
    parser.add_argument(
        '-s', '--stable',
        action='store_true',
        help='Fetch a stable retail release fingerprint from Google\'s full-OTA '
             'image list instead of a Beta (recommended: real-device builds '
             'cannot be burned without collateral)'
    )

    args = parser.parse_args()

    # Fetch fingerprint
    fetcher = FingerprintFetcher()
    fingerprint = fetcher.fetch_fingerprint(
        force_preview=args.preview,
        depth=args.depth,
        version=args.version,
        stable=args.stable
    )

    if not fingerprint:
        print("Error: Failed to fetch fingerprint data")
        sys.exit(1)

    # Generate overlay
    generator = OverlayGenerator(fingerprint)
    generator.generate_all(args.output_dir)

    print(f"\n✓ Certified Props Overlay generated in: {args.output_dir}/")
    print("\nGenerated structure:")
    print(f"  {args.output_dir}/")
    print(f"  ├── Android.bp")
    print(f"  ├── AndroidManifest.xml")
    print(f"  ├── pif.json")
    print(f"  └── res/")
    print(f"      └── values/")
    print(f"          └── arrays.xml")

    print("\nUsage:")
    print("1. For Play Integrity Fix module:")
    print(f"   Copy {args.output_dir}/pif.json to /data/adb/modules/playintegrityfix/")
    print("2. For Android build:")
    print(f"   Add CertifiedPropsOverlay to PRODUCT_PACKAGES")


if __name__ == '__main__':
    main()
