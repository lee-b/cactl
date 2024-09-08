from ..exporter import Exporter

from .web.nginx import NginxExporter
from .web.browser import GenericBrowserExporter
from .vpn.openvpn_server import OpenVPNServerExporter
from .vpn.openvpn_client import OpenVPNClientExporter
from .revocation_lists.crl import CertificateRevocationListExporter


def build_exporters() -> list[Exporter]:
    exporters = [
        NginxExporter(),
        GenericBrowserExporter(),

        OpenVPNServerExporter(),
        OpenVPNClientExporter(),

        CertificateRevocationListExporter(),
    ]
    return exporters
