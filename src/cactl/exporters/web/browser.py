from pathlib import Path

from ...exporter import Exporter
from ...db import DB
from ...crypto import CertPurpose, Key


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

        # Write the certificate chain file
        chain_file = browser_dir / f"{entity_name}_cert_chain.pem"
        self._write_cert_chain(chain_file, cert_chain)

        # Write the private key file
        key_file = browser_dir / f"{entity_name}_private_key.pem"
        self._write_file(key_file, self._read_file_content(client_key.path))

        # Write the PKCS#12 file (optional, for browsers that support it)
        pkcs12_file = browser_dir / f"{entity_name}_client.p12"
        self._generate_pkcs12(client_cert, client_key, cert_chain, pkcs12_file)

        print(f"Browser-compatible files exported to: {browser_dir}")
        print(f"  Certificate chain: {chain_file}")
        print(f"  Private key: {key_file}")
        print(f"  PKCS#12 file: {pkcs12_file}")

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

    def _generate_pkcs12(self, client_cert, client_key, cert_chain, output_file: Path):
        # This is a placeholder. In a real implementation, you would use a cryptographic
        # library or call an external command to generate a PKCS#12 file.
        placeholder_content = f"""
# Placeholder for PKCS#12 file
# This file should contain:
# - Client certificate: {client_cert.path}
# - Client private key: {client_key.path}
# - Certificate chain: {', '.join(str(cert.path) for cert in cert_chain[1:])}
#
# Generate with: openssl pkcs12 -export -out {output_file.name} -inkey {client_key.path} -in {client_cert.path} -certfile chain.pem
"""
        self._write_file(output_file, placeholder_content.strip())
