from pathlib import Path
import subprocess
import tempfile

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

        # Write the certificate chain file
        chain_file = browser_dir / f"{entity_name}_cert_chain.pem"
        self._write_cert_chain(chain_file, cert_chain)

        # Write the private key file
        key_file = browser_dir / f"{entity_name}_private_key.pem"
        self._write_file(key_file, self._read_file_content(client_key.path))

        # Write the PKCS#12 file
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

    def _generate_pkcs12(self, client_cert, client_key: Key, cert_chain, output_file: Path):
        with tempfile.NamedTemporaryFile(mode='w', suffix='.pem', delete=False) as temp_chain:
            for cert in cert_chain[1:]:  # Exclude the client cert
                temp_chain.write(self._read_file_content(cert.path) + '\n')
            temp_chain_path = temp_chain.name

        try:
            password = "changeit"  # You might want to generate a random password or ask the user
            cmd = [
                "openssl", "pkcs12", "-export",
                "-out", str(output_file),
                "-inkey", str(client_key.path),
                "-in", str(client_cert.path),
                "-certfile", temp_chain_path,
                "-password", f"pass:{password}"
            ]
            subprocess.run(cmd, check=True)
            print(f"PKCS#12 file created successfully. Password: {password}")
        except subprocess.CalledProcessError as e:
            print(f"Error generating PKCS#12 file: {e}")
        finally:
            Path(temp_chain_path).unlink()  # Delete the temporary chain file
