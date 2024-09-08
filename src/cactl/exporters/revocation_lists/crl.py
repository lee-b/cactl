from pathlib import Path

from ...exporter import Exporter
from ...db import DB


class CertificateRevocationListExporter(Exporter):
    def name(self) -> str:
        return "crl"

    def export(self, db: DB, entity_name: str, target_path: Path):
        raise NotImplementedError()
