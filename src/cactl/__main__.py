import argparse
import logging
from pathlib import Path
from typing import List

from .exporters import build_exporters
from .subcommand import Subcommand
from .subcommands import build_subcommands
from .db import DB


def get_config(subcommands: List[Subcommand]) -> argparse.Namespace:
    parser = argparse.ArgumentParser(description="Manages CA files stored locally on disk")
    parser.add_argument("--verbose", "-v", action="store_true", help="Enable verbose logging")
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug logging")
    parser.add_argument("--db-path", "-D", type=Path, help="Path to the database file. Default: './CA'", default=Path("./CA"))

    subcommand_subparsers = parser.add_subparsers(title="subcommands", dest="subcommand")

    for subcommand in subcommands:
        subcommand.augment_subcommands(subcommand_subparsers)

    conf = parser.parse_args()

    return conf


def init_logging(conf: argparse.Namespace):
    if conf.verbose:
        logging.basicConfig(level=logging.INFO)
    elif conf.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.WARNING)


def get_db(conf: argparse.Namespace) -> DB:
    return DB(conf.db_path)


def main():
    exporters = build_exporters()
    subcommands = build_subcommands(exporters)

    conf = get_config(subcommands)
    init_logging(conf)

    db = get_db(conf)

    subcmd_func = conf.func
    return subcmd_func(conf, db)


# NOTE: no if __name__ == "__main__" nonsense needed here since poetry generates our wrapper script that calls main() for us
