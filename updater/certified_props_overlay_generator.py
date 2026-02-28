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

    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36'
        })

    def fetch_from_google(self, force_preview: bool = False, depth: int = 1) -> Optional[Dict[str, str]]:
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

            # Find OTA download page
            ota_links = re.findall(r'href="([^"]*download-ota[^"]*)"', resp.text)
            if not ota_links or len(ota_links) < depth:
                print("Not enough OTA download links found")
                return None

            ota_url = f"https://developer.android.com{ota_links[depth-1]}"
            print(f"Fetching OTA page (depth={depth}): {ota_url}")

            resp = self.session.get(ota_url, timeout=10)
            resp.raise_for_status()

            # Extract Android version info
            version_match = re.search(r'tooltip>Android\s+([^<]+)', resp.text)
            qpr_match = re.search(r'tooltip>QPR.*?\s+Beta', resp.text)

            if version_match:
                version_str = f"Android {version_match.group(1)}"
                if qpr_match:
                    version_str += f" {qpr_match.group(0).split('>')[-1]}"
                print(version_str)

            return self._parse_ota_page(resp.text)

        except Exception as e:
            print(f"Error fetching from Google: {e}")
            return None

    def _parse_ota_page(self, html: str) -> Optional[Dict[str, str]]:
        """Parse OTA page to extract device fingerprint info"""
        # Extract device models
        model_matches = re.findall(r'<tr id=[^>]+>.*?<td>([^<]+)</td>', html, re.DOTALL)

        # Extract product names (device_beta format)
        product_matches = re.findall(r'ota/([^/]+_beta)', html)

        # Extract OTA URLs
        ota_urls = re.findall(r'href="([^"]*ota/[^"]+_beta[^"]*)"', html)

        if not model_matches or not product_matches or not ota_urls:
            print("Failed to extract device information from OTA page")
            return None

        # Select random device
        idx = random.randint(0, min(len(model_matches), len(product_matches), len(ota_urls)) - 1)

        model = model_matches[idx]
        product = product_matches[idx]
        ota_url = ota_urls[idx]
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

    def fetch_fingerprint(self, force_preview: bool = False, depth: int = 1) -> Optional[Dict[str, str]]:
        """Main method to fetch fingerprint from any available source"""
        print("Pixel Beta pif.json generator")
        print("  based on osm0sis @ xda-developers")
        print("")

        # Try Google first
        fingerprint = self.fetch_from_google(force_preview=force_preview, depth=depth)
        if fingerprint:
            print("Successfully fetched from Google")
            return fingerprint

        # Try fallback sources
        fingerprint = self.fetch_from_fallback()
        if fingerprint:
            print("Successfully fetched from fallback source")
            return fingerprint

        print("Failed to fetch fingerprint from any source")
        return None


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
        array = ET.SubElement(resources, 'array', name='config_certifiedBuildProperties')

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

        # Write XML file
        self._write_xml(resources, output_path)
        print(f"Generated: {output_path}")

    def _generate_pif_json(self, output_path: str):
        """Generate pif.json for Play Integrity Fix module"""
        # Write JSON file with proper formatting
        with open(output_path, 'w', encoding='utf-8') as f:
            json.dump(self.fingerprint_data, f, indent=2)
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
    package="custom.overlay.certifiedprops">
    <application android:hasCode="false" />
    <overlay
        android:targetPackage="android"
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
        default=1,
        choices=range(1, 10),
        help='OTA page depth to use (default: 1)'
    )

    args = parser.parse_args()

    # Fetch fingerprint
    fetcher = FingerprintFetcher()
    fingerprint = fetcher.fetch_fingerprint(
        force_preview=args.preview,
        depth=args.depth
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
