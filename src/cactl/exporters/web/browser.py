from pathlib import Path
import subprocess
import tempfile
import os

from ...exporter import Exporter
from ...db import DB
from ...crypto import CertPurpose, Key
from ...entity import Entity


class GenericBrowserExporter(Exporter):
    def name(self) -> str:
        return "generic-browser"

    def export(self, db: DB, entity_name: str, target_path: Path):
        entity = db.get_entity_by_id(entity_name)
        if not entity:
            raise ValueError(f"Entity '{entity_name}' not found")

        cert_chain = db.get_entity_certificate_chain(entity_name, purposes={CertPurpose.WEB_CLIENT})
        if not cert_chain:
            raise ValueError(f"No valid certificate chain found for '{entity_name}'")

        client_cert = cert_chain[0]
        client_key = next((key for key in entity.keys if key.id == client_cert.key_id), None)
        if not client_key:
            raise ValueError(f"Private key not found for certificate '{client_cert.id}'")

        # Create a directory for the browser client files
        browser_dir = target_path / f"{entity_name}_browser_client"
        browser_dir.mkdir(parents=True, exist_ok=True)

        # Write the certificate chain file (PEM format)
        chain_file = browser_dir / f"{entity_name}_cert_chain.pem"
        self._write_cert_chain(chain_file, cert_chain)

        # Write the private key file (PEM format)
        key_file = browser_dir / f"{entity_name}_private_key.pem"
        self._write_file(key_file, self._read_file_content(client_key.path))

        # Write the client certificate file (PEM format)
        cert_file = browser_dir / f"{entity_name}_client_cert.pem"
        self._write_file(cert_file, self._read_file_content(client_cert.path))

        # Generate PKCS#12 file
        pkcs12_file = browser_dir / f"{entity_name}_client.p12"
        pkcs12_password = self._generate_pkcs12(client_cert, client_key, cert_chain, pkcs12_file)

        # Generate PFX file (essentially the same as PKCS#12, but with a different extension)
        pfx_file = browser_dir / f"{entity_name}_client.pfx"
        self._copy_file(pkcs12_file, pfx_file)

        # Generate DER format certificate
        der_cert_file = browser_dir / f"{entity_name}_client_cert.der"
        self._generate_der_cert(client_cert.path, der_cert_file)

        # Generate README.TXT file
        readme_file = browser_dir / "README.TXT"
        self._generate_readme(readme_file, entity_name, pkcs12_password)

        print(f"Browser-compatible files exported to: {browser_dir}")
        print(f"  Certificate chain (PEM): {chain_file}")
        print(f"  Private key (PEM): {key_file}")
        print(f"  Client certificate (PEM): {cert_file}")
        print(f"  Client certificate (DER): {der_cert_file}")
        print(f"  PKCS#12 file: {pkcs12_file}")
        print(f"  PFX file: {pfx_file}")
        print(f"  PKCS#12/PFX password: {pkcs12_password}")
        print(f"  README file: {readme_file}")
        
        print("\nPlease refer to the README.TXT file for detailed instructions on importing the client certificate.")

    def _write_cert_chain(self, output_file: Path, cert_chain):
        pem_content = ""
        for cert in cert_chain:
            pem_content += self._read_file_content(cert.path) + "\n"
        self._write_file(output_file, pem_content.strip())

    def _read_file_content(self, file_path: Path) -> str:
        with open(file_path, "r") as f:
            return f.read().strip()

    def _write_file(self, file_path: Path, content: str):
        with open(file_path, "w") as f:
            f.write(content)

    def _copy_file(self, src: Path, dst: Path):
        with open(src, "rb") as src_file, open(dst, "wb") as dst_file:
            dst_file.write(src_file.read())

    def _generate_pkcs12(self, client_cert, client_key: Key, cert_chain, output_file: Path) -> str:
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_chain:
            for cert in cert_chain[1:]:  # Exclude the client cert
                temp_chain.write(self._read_file_content(cert.path) + '\n')
            temp_chain_path = temp_chain.name

        try:
            password = self._generate_password()
            cmd = [
                "openssl", "pkcs12", "-export",
                "-out", str(output_file),
                "-inkey", str(client_key.path),
                "-in", str(client_cert.path),
                "-certfile", temp_chain_path,
                "-password", f"pass:{password}"
            ]
            subprocess.run(cmd, check=True)
            print(f"PKCS#12 file created successfully.")
            return password
        except subprocess.CalledProcessError as e:
            print(f"Error generating PKCS#12 file: {e}")
            return None
        finally:
            Path(temp_chain_path).unlink()  # Delete the temporary chain file

    def _generate_der_cert(self, pem_cert_path: Path, der_cert_path: Path):
        cmd = [
            "openssl", "x509",
            "-in", str(pem_cert_path),
            "-out", str(der_cert_path),
            "-outform", "DER"
        ]
        subprocess.run(cmd, check=True)

    def _generate_password(self, length=16):
        return ''.join(os.urandom(length).hex())

    def _generate_readme(self, readme_file: Path, entity_name: str, pkcs12_password: str):
        content = f"""Client Certificate Import Instructions for {entity_name}

This directory contains the following files:
1. {entity_name}_client.p12 / {entity_name}_client.pfx: PKCS#12/PFX format certificate (includes private key and certificate chain)
2. {entity_name}_client_cert.pem: Client certificate in PEM format
3. {entity_name}_client_cert.der: Client certificate in DER format
4. {entity_name}_private_key.pem: Private key in PEM format
5. {entity_name}_cert_chain.pem: Certificate chain in PEM format

PKCS#12/PFX Password: {pkcs12_password}

Instructions for major browsers:

1. Google Chrome:
   - Go to Settings > Privacy and security > Security > Manage certificates
   - Click on "Import" and select the {entity_name}_client.p12 file
   - Enter the PKCS#12/PFX password when prompted

2. Mozilla Firefox:
   - Go to Options > Privacy & Security > Certificates > View Certificates
   - Click on "Import" and select the {entity_name}_client.p12 file
   - Enter the PKCS#12/PFX password when prompted

3. Microsoft Edge:
   - Go to Settings > Privacy, search, and services > Manage certificates
   - Click on "Import" and select the {entity_name}_client.pfx file
   - Enter the PKCS#12/PFX password when prompted

4. Apple Safari:
   - Double-click the {entity_name}_client.p12 file
   - It will open Keychain Access. Enter your system password if prompted
   - Enter the PKCS#12/PFX password when prompted

5. Internet Explorer:
   - Go to Internet Options > Content > Certificates
   - Click on "Import" and select the {entity_name}_client.pfx file
   - Enter the PKCS#12/PFX password when prompted

For other browsers or manual import:
- Use the individual PEM or DER files as required by your browser or system
- The {entity_name}_cert_chain.pem file contains the full certificate chain, which may be needed for some import processes

Note: The exact import process may vary depending on the browser version and operating system. If you encounter any issues, please consult your browser's documentation or contact your system administrator.
"""
        self._write_file(readme_file, content)
