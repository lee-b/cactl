from argparse import _SubParsersAction, Namespace

from ..db import DB
from ..subcommand import Subcommand


class NewServerSubcommand(Subcommand):
    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("new-server", help="Create a new server key and cert")
        subcmd.set_defaults(func=self.run)

        subcmd.add_argument("--with-intermediate-ca", type=str)
        subcmd.add_argument("server_hostname", type=str)

    def run(self, ns: Namespace, db: DB) -> int:
        print("(create new server here)")
        return 0
