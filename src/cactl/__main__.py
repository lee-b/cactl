import argparse
import logging
from pathlib import Path
from typing import List

from .backends import get_backend
from .db import DB
from .exporters import build_exporters
from .subcommand import Subcommand
from .subcommands import build_subcommands


def get_config(subcommands: List[Subcommand], parser: argparse.ArgumentParser) -> argparse.Namespace:
    parser.add_argument("--debug", "-d", action="store_true", help="Enable debug logging")
    parser.add_argument("--db-path", "-D", type=Path, help="Path to the database file. Default: './CA'", default=Path("./CA"))

    subcommand_subparsers = parser.add_subparsers(title="subcommands", dest="subcommand", required=True)

    for subcommand in subcommands:
        subcommand.augment_subcommands(subcommand_subparsers)

    conf = parser.parse_args()

    return conf


def init_logging(conf: argparse.Namespace):
    if conf.debug:
        logging.basicConfig(level=logging.DEBUG)
    else:
        logging.basicConfig(level=logging.INFO)


def get_db(conf: argparse.Namespace) -> DB:
    return DB(conf.db_path)


def main():
    parser = argparse.ArgumentParser(description="CA, Key, and Certificate Management, plus generation of configs for various systems.")

    exporters = build_exporters()
    subcommands = build_subcommands(exporters, parser)

    conf = get_config(subcommands, parser)

    init_logging(conf)

    db = get_db(conf)

    backend = get_backend(conf)

    subcmd_func = conf.func
    return subcmd_func(conf, db, backend)


# NOTE: no if __name__ == "__main__" nonsense needed here since poetry generates our wrapper script that calls main() for us
