from pathlib import Path

from ...exporter import Exporter
from ...db import DB


class NginxExporter(Exporter):
    def name(self) -> str:
        return "nginx"

    def export(self, db: DB, entity_name: str, target_path: Path):
        entity = db.get_entity_by_name(entity_name)
        entity_chain = db.get_entity_chain(entity_name)

        raise NotImplementedError()
