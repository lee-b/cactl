from argparse import ArgumentParser, _SubParsersAction, Namespace

from ..backend import Backend
from ..db import DB
from ..subcommand import Subcommand


class HelpSubcommand(Subcommand):
    def __init__(self, parser: ArgumentParser):
        super().__init__()
        self._parser = parser

    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("help", help="(prints the help text)")
        subcmd.set_defaults(func=self.run)

    def run(self, ns: Namespace, db: DB, backend: Backend) -> int:
        self._parser.print_help()
        return 0
