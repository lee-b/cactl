import logging
from typing import List, Sequence

from ..subcommand import Subcommand
from ..exporter import Exporter

from .new_root_ca import NewRootCASubcommand
from .new_intermediate_ca import NewIntermediateCASubcommand
from .new_client import NewClientSubcommand
from .new_server import NewServerSubcommand
from .export import ExportSubcommand
from .list import ListSubcommand
from .list_exporters import ListExportersSubcommand


def build_subcommands(exporters: Sequence[Exporter]) -> List[Subcommand]:
    subcommands = [
        ListSubcommand(),
        NewRootCASubcommand(),
        NewIntermediateCASubcommand(),
        NewClientSubcommand(),
        NewServerSubcommand(),
        ExportSubcommand(exporters),
        ListExportersSubcommand(exporters),
    ]
    return subcommands
