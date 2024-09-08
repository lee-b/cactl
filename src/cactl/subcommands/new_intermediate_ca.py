from argparse import _SubParsersAction, Namespace

from ..db import DB
from ..subcommand import Subcommand


class NewIntermediateCASubcommand(Subcommand):
    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("new-intermediate-ca", help="Create a new Intermediate (signing) CA")
        subcmd.set_defaults(func=self.run)

        subcmd.add_argument("--parent-ca", type=str)
        subcmd.add_argument("intermediate_ca_name", type=str)

    def run(self, ns: Namespace, db: DB) -> int:
        print("(create new intermediate ca here)")
        return 0
