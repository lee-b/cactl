from argparse import _SubParsersAction, Namespace

from ..backend import Backend
from ..db import DB
from ..subcommand import Subcommand


class NewClientSubcommand(Subcommand):
    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("new-client", help="Create a new client key and cert")
        subcmd.set_defaults(func=self.run)

        subcmd.add_argument("--with-intermediate-ca", type=str)
        subcmd.add_argument("client_name", type=str)

    def run(self, ns: Namespace, db: DB, backend: Backend) -> int:
        print("(create new client here)")
        return 0
