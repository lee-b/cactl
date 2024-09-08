import logging
from argparse import _SubParsersAction, Namespace
from typing import Sequence
from pathlib import Path

from ..db import DB
from ..exporter import Exporter
from ..subcommand import Subcommand


logger = logging.getLogger(__name__)


class ListExportersSubcommand(Subcommand):
    def __init__(self, exporters: Sequence[Exporter]):
        self._exporters = exporters

    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("ls-exporters", help="List known exporters")
        subcmd.set_defaults(func=self.run)

    def run(self, ns: Namespace, db: DB) -> int:
        for ex in self._exporters:
            print(ex.name())

        return 0
