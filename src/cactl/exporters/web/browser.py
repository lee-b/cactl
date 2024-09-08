from pathlib import Path

from ...exporter import Exporter
from ...db import DB
from ...crypto import CertPurpose


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

        pem_content = self._generate_pem_content(cert_chain)

        output_file = target_path / f"{entity_name}_browser_cert_chain.pem"
        with open(output_file, "w") as f:
            f.write(pem_content)

        print(f"Browser-compatible certificate chain exported to: {output_file}")

    def _generate_pem_content(self, cert_chain):
        pem_content = ""
        for cert in cert_chain:
            pem_content += self._read_file_content(cert.path) + "\n"
        return pem_content.strip()

    def _read_file_content(self, file_path: Path) -> str:
        with open(file_path, "r") as f:
            return f.read().strip()
