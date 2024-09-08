from argparse import _SubParsersAction, Namespace

from ..db import DB
from ..subcommand import Subcommand


class ListSubcommand(Subcommand):
    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("ls", help="List existing entities (CAs, servers, clients, etc.)")
        subcmd.set_defaults(func=self.run)

    def run(self, ns: Namespace, db: DB) -> int:
        print("Currently registered entities:")

        print("    (none)")

        return 0
