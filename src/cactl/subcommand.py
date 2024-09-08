import argparse

from .db import DB


class Subcommand:
    def augment_subcommands(self, subparsers: argparse._SubParsersAction):
        pass

    def run(self, ns: argparse.Namespace, db: DB) -> int:
        pass
