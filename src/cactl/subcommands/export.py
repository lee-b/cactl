import logging
from argparse import _SubParsersAction, Namespace
from typing import Sequence
from pathlib import Path

from ..backend import Backend
from ..db import DB
from ..exporter import Exporter
from ..subcommand import Subcommand


logger = logging.getLogger(__name__)


class ExportSubcommand(Subcommand):
    def __init__(self, exporters: Sequence[Exporter]):
        self._exporters = exporters

    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("export", help="Export an entity as a ready-to-use config")
        subcmd.set_defaults(func=self.run)

        subcmd.add_argument("entity_name", type=str)
        subcmd.add_argument("exporter", type=str, choices=[str(ex) for ex in self._exporters])
        subcmd.add_argument("target_path", type=Path)

    def run(self, ns: Namespace, db: DB, backend: Backend) -> int:
        exporter = next((ex for ex in self._exporters if ex.name() == ns.target), None)

        if not exporter:
            logger.error("Exporter %r is not supported in this version.", ns.target)
            return 1

        exporter.export(db, ns.entity_name, ns.target_path)

        return 0
