from pathlib import Path

from .db import DB


class Exporter:
    def name(self) -> str:
        return self.__class__.__name__

    def export(self, db: DB, entity_name: str, target_path: Path):
        raise NotImplementedError()

    def __str__(self):
        return self.name()
