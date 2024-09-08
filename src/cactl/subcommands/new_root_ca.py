from argparse import _SubParsersAction, Namespace

from ..backend import Backend
from ..db import DB
from ..subcommand import Subcommand


class NewRootCASubcommand(Subcommand):
    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("new-root-ca", help="Create a new Root CA")
        subcmd.set_defaults(func=self.run)

        subcmd.add_argument("root_ca_name", type=str)

    def run(self, ns: Namespace, db: DB, backend: Backend) -> int:
        print("(create new Root CA here)")
        return 0
