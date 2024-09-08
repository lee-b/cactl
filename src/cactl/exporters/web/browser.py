from pathlib import Path

from ...exporter import Exporter
from ...db import DB


class GenericBrowserExporter(Exporter):
    def name(self) -> str:
        return "generic-browser"

    def export(self, db: DB, entity_name: str, target_path: Path):
        raise NotImplementedError()
