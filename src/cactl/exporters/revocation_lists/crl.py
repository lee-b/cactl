from pathlib import Path
from datetime import datetime, timedelta

from ...exporter import Exporter
from ...db import DB
from ...crypto import FileFormat, CertPurpose


class CertificateRevocationListExporter(Exporter):
    def name(self) -> str:
        return "crl"

    def export(self, db: DB, entity_name: str, target_path: Path):
        entity = db.get_entity_by_id(entity_name)
        if not entity:
            raise ValueError(f"Entity '{entity_name}' not found")

        if not entity.can_sign:
            raise ValueError(f"Entity '{entity_name}' is not a CA and cannot issue CRLs")

        # Get all revoked certificates for this CA
        revoked_certs = []
        for revocation in entity.revocations:
            cert = db.get_cert_by_id(revocation.cert_id)
            if cert:
                revoked_certs.append((cert, revocation))

        # Generate CRL content
        crl_content = self._generate_crl_content(entity, revoked_certs)

        # Write CRL to file
        target_path.write_text(crl_content)

    def _generate_crl_content(self, ca_entity, revoked_certs):
        crl_content = f"Certificate Revocation List (CRL) for {ca_entity.name}\n"
        crl_content += f"Issued on: {datetime.utcnow().isoformat()}\n"
        crl_content += f"Next update: {(datetime.utcnow() + timedelta(days=1)).isoformat()}\n"
        crl_content += "\nRevoked Certificates:\n"

        for cert, revocation in revoked_certs:
            crl_content += f"- Serial: {cert.id}\n"
            crl_content += f"  Revocation Date: {revocation.revocation_date.isoformat()}\n"
            crl_content += f"  Reason: {revocation.reason}\n"

        return crl_content

