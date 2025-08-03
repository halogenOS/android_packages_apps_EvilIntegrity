#!/usr/bin/env python3
"""
Keybox Overlay Generator - Generates keybox overlay for Android
Processes keybox.xml files into Android overlay format
"""

import argparse
import os
import sys
import re
import xml.etree.ElementTree as ET
from typing import List, Optional


class KeyboxProcessor:
    """Processes keybox.xml files for overlay generation"""

    def __init__(self):
        self.ec_key = None
        self.rsa_key = None
        self.ec_certs = []
        self.rsa_certs = []

    def load_from_xml(self, xml_path: str) -> bool:
        """Load keybox data from XML file"""
        try:
            tree = ET.parse(xml_path)
            root = tree.getroot()

            # Find keybox element - handle both Keybox and AndroidAttestation root
            keybox = None
            if root.tag == 'AndroidAttestation':
                keybox = root.find('Keybox')
            elif root.tag == 'Keybox':
                keybox = root
            else:
                # Try to find Keybox anywhere in the tree
                keybox = root.find('.//Keybox')

            if keybox is None:
                print("Error: No Keybox element found in XML")
                return False

            print("Found Keybox element")

            # Process each key
            for key_elem in keybox.findall('Key'):
                algorithm = key_elem.get('algorithm', '').lower()
                print(f"Processing {algorithm} key...")

                # Get private key
                priv_elem = key_elem.find('PrivateKey')
                if priv_elem is not None and priv_elem.text:
                    key_data = self._clean_pem(priv_elem.text)
                    if algorithm in ['ecdsa', 'ec']:
                        self.ec_key = key_data
                    elif algorithm == 'rsa':
                        self.rsa_key = key_data

                # Get certificates
                cert_chain = key_elem.find('CertificateChain')
                if cert_chain is not None:
                    certs = []
                    for cert_elem in cert_chain.findall('Certificate'):
                        if cert_elem.text:
                            certs.append(self._clean_pem(cert_elem.text))

                    if algorithm in ['ecdsa', 'ec']:
                        self.ec_certs = certs
                    elif algorithm == 'rsa':
                        self.rsa_certs = certs

            return self._validate_keybox()

        except ET.ParseError as e:
            print(f"Error parsing XML: {e}")
            return False
        except Exception as e:
            print(f"Error loading keybox XML: {e}")
            return False

    def _clean_pem(self, pem_data: str) -> str:
        """Clean PEM data by removing headers/footers and whitespace"""
        lines = pem_data.strip().split('\n')
        cleaned = []

        for line in lines:
            line = line.strip()
            if line and not line.startswith('-----'):
                cleaned.append(line)

        return ''.join(cleaned)

    def _validate_keybox(self) -> bool:
        """Validate that we have all required keybox components"""
        required = [
            (self.ec_key, "EC private key"),
            (self.rsa_key, "RSA private key"),
            (len(self.ec_certs) >= 3, "EC certificate chain (need 3)"),
            (len(self.rsa_certs) >= 3, "RSA certificate chain (need 3)")
        ]

        valid = True
        for condition, name in required:
            if not condition:
                print(f"Missing or incomplete: {name}")
                valid = False

        if valid:
            print("✓ Keybox validation successful")
            print(f"  - EC key: {len(self.ec_key)} chars")
            print(f"  - EC certificates: {len(self.ec_certs)}")
            print(f"  - RSA key: {len(self.rsa_key)} chars")
            print(f"  - RSA certificates: {len(self.rsa_certs)}")

        return valid

    def to_string_array(self) -> List[str]:
        """Convert keybox data to string array format"""
        items = []

        # EC components
        items.append(f"EC.PRIV:{self.ec_key}")
        for i, cert in enumerate(self.ec_certs[:3], 1):
            items.append(f"EC.CERT_{i}:{cert}")

        # RSA components
        items.append(f"RSA.PRIV:{self.rsa_key}")
        for i, cert in enumerate(self.rsa_certs[:3], 1):
            items.append(f"RSA.CERT_{i}:{cert}")

        return items


class KeyboxOverlayGenerator:
    """Generates Android keybox overlay"""

    def __init__(self, keybox_items: List[str]):
        self.keybox_items = keybox_items

    def generate_all(self, output_dir: str = "CertifiedKeyboxOverlay"):
        """Generate all files for keybox overlay"""
        # Create proper overlay structure
        res_dir = os.path.join(output_dir, "res", "values")
        os.makedirs(res_dir, exist_ok=True)

        # Generate keybox overlay XML
        kb_xml_path = os.path.join(res_dir, "strings.xml")
        self._generate_keybox_xml(kb_xml_path)

        # Create Android.bp for the overlay
        self._generate_android_bp(output_dir)

        # Create README with important information
        self._generate_readme(output_dir)

        # Create AndroidManifest.xml
        self._generate_manifest(output_dir)

    def _generate_keybox_xml(self, output_path: str):
        """Generate keybox overlay XML"""
        # Create XML structure
        resources = ET.Element('resources')
        resources.set('xmlns:xliff', 'urn:oasis:names:tc:xliff:document:1.2')

        array = ET.SubElement(resources, 'string-array',
                            name='config_certifiedKeybox',
                            translatable='false')

        # Add comment about keybox format
        comment = ET.Comment("""
    Certified Keybox for hardware attestation
    Format: KEY_TYPE:BASE64_DATA
    Required components:
    - EC.PRIV: EC private key
    - EC.CERT_1-3: EC certificate chain
    - RSA.PRIV: RSA private key
    - RSA.CERT_1-3: RSA certificate chain
""")
        array.append(comment)

        for item_text in self.keybox_items:
            item = ET.SubElement(array, 'item')
            item.text = item_text

        # Write XML file
        self._write_xml(resources, output_path)
        print(f"Generated: {output_path}")

    def _generate_android_bp(self, output_dir: str):
        """Generate Android.bp file for the overlay"""
        android_bp_content = '''//
// SPDX-License-Identifier: Apache-2.0
//

runtime_resource_overlay {
    name: "CertifiedKeyboxOverlay",
    product_specific: true,
    sdk_version: "current",
    resource_dirs: ["res"],
}
'''

        bp_path = os.path.join(output_dir, "Android.bp")
        with open(bp_path, 'w') as f:
            f.write(android_bp_content)

        print(f"Generated: {bp_path}")

    def _generate_readme(self, output_dir: str):
        """Generate README with important information"""
        readme_content = '''# Certified Keybox Overlay

This overlay contains cryptographic keybox data for hardware attestation.

## ⚠️ IMPORTANT SECURITY NOTICE

**DO NOT SHARE THIS OVERLAY PUBLICLY!**

This overlay contains private keys that will be immediately revoked by Google if shared publicly.
Keep this overlay private and only use it for your personal devices.

## Installation

1. Add to your device makefile:
   ```
   PRODUCT_PACKAGES += CertifiedKeyboxOverlay
   ```

2. Build and flash your ROM

## Keybox Information

- **Source**: User-provided keybox.xml
- **Format**: Android TEE keybox format
- **Components**: EC and RSA private keys with certificate chains

## Revocation Status

To check if your keybox is still valid:
1. Use Key Attestation Demo app
2. Check Play Integrity API results
3. Monitor for STRONG integrity pass/fail

## Notes

- Keyboxes are typically valid for days to weeks
- Google actively searches for and revokes public keyboxes
- This overlay is for development/testing purposes only
'''

        readme_path = os.path.join(output_dir, "README.md")
        with open(readme_path, 'w') as f:
            f.write(readme_content)

        print(f"Generated: {readme_path}")


    def _generate_manifest(self, output_dir: str):
        """Generate AndroidManifest.xml for the overlay"""
        manifest_content = '''<?xml version="1.0" encoding="utf-8"?>
<manifest
    xmlns:android="http://schemas.android.com/apk/res/android"
    package="custom.overlay.certifiedkeybox">
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
                if '</' not in line and not line.startswith('<!--'):  # Opening tag
                    indent += 1

        return '\n'.join(formatted)


def print_keybox_format():
    """Print information about keybox.xml format"""
    print("""
Expected keybox.xml format:
===========================

<?xml version="1.0"?>
<AndroidAttestation>
    <NumberOfKeyboxes>1</NumberOfKeyboxes>
    <Keybox DeviceID="...">
        <Key algorithm="ecdsa">
            <PrivateKey format="pem">
-----BEGIN EC PRIVATE KEY-----
... base64 data ...
-----END EC PRIVATE KEY-----
            </PrivateKey>
            <CertificateChain>
                <NumberOfCertificates>3</NumberOfCertificates>
                <Certificate format="pem">
-----BEGIN CERTIFICATE-----
... base64 data ...
-----END CERTIFICATE-----
                </Certificate>
                <!-- More certificates -->
            </CertificateChain>
        </Key>
        <Key algorithm="rsa">
            <PrivateKey format="pem">
-----BEGIN RSA PRIVATE KEY-----
... base64 data ...
-----END RSA PRIVATE KEY-----
            </PrivateKey>
            <CertificateChain>
                <NumberOfCertificates>3</NumberOfCertificates>
                <Certificate format="pem">
-----BEGIN CERTIFICATE-----
... base64 data ...
-----END CERTIFICATE-----
                </Certificate>
                <!-- More certificates -->
            </CertificateChain>
        </Key>
    </Keybox>
</AndroidAttestation>

Where to obtain keybox.xml:
- Private Discord/Telegram groups
- Extract from your own devices
- TrickyStore community resources
- Search using alternative search engines

⚠️ WARNING: Never share keybox files publicly!
""")


def main():
    parser = argparse.ArgumentParser(
        description='Keybox Overlay Generator - Converts keybox.xml to Android overlay',
        epilog='Use --format to see expected keybox.xml format'
    )
    parser.add_argument(
        'keybox_xml',
        nargs='?',
        help='Path to keybox.xml file'
    )
    parser.add_argument(
        '--output-dir',
        default='CertifiedKeyboxOverlay',
        help='Output directory for generated files (default: CertifiedKeyboxOverlay)'
    )
    parser.add_argument(
        '--format',
        action='store_true',
        help='Show expected keybox.xml format and exit'
    )

    args = parser.parse_args()

    if args.format:
        print_keybox_format()
        sys.exit(0)

    if not args.keybox_xml:
        print("Error: keybox.xml file required")
        print("Use --format to see expected format")
        sys.exit(1)

    if not os.path.exists(args.keybox_xml):
        print(f"Error: File not found: {args.keybox_xml}")
        sys.exit(1)

    # Process keybox
    print(f"Processing keybox: {args.keybox_xml}")
    processor = KeyboxProcessor()

    if not processor.load_from_xml(args.keybox_xml):
        print("\nError: Failed to load keybox data")
        print("Use --format to see expected format")
        sys.exit(1)

    # Generate overlay
    keybox_items = processor.to_string_array()
    generator = KeyboxOverlayGenerator(keybox_items)
    generator.generate_all(args.output_dir)

    print(f"\n✓ Keybox Overlay generated in: {args.output_dir}/")
    print("\nGenerated structure:")
    print(f"  {args.output_dir}/")
    print(f"  ├── Android.bp")
    print(f"  ├── AndroidManifest.xml")
    print(f"  ├── README.md")
    print(f"  └── res/")
    print(f"      └── values/")
    print(f"          └── strings.xml")

    print("\n⚠️  SECURITY REMINDER:")
    print("DO NOT share this overlay publicly!")
    print("Keyboxes get revoked quickly when shared.")

    print("\nUsage:")
    print("1. Add 'CertifiedKeyboxOverlay' to PRODUCT_PACKAGES")
    print("2. Build and flash your ROM")


if __name__ == '__main__':
    main()
