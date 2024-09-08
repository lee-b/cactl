from ..exporter import Exporter

from .web.nginx import NginxExporter
from .web.browser import GenericBrowserExporter
from .vpn.openvpn_server import OpenVPNServerExporter
from .vpn.openvpn_android_client import OpenVPNAndroidClientExporter
from .revocation_lists.crl import CertificateRevocationListExporter


def build_exporters() -> list[Exporter]:
    exporters = [
        NginxExporter(),
        GenericBrowserExporter(),

        OpenVPNServerExporter(),
        OpenVPNAndroidClientExporter(),

        CertificateRevocationListExporter(),
    ]
    return exporters
