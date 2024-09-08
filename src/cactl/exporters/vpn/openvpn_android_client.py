from pathlib import Path

from ...exporter import Exporter
from ...db import DB


class OpenVPNAndroidClientExporter(Exporter):
    def name(self) -> str:
        return "openvpn-android-client"

    def export(self, db: DB, entity_name: str, target_path: Path):
        raise NotImplementedError()
