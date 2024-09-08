from pathlib import Path
from typing import List

from ...exporter import Exporter
from ...db import DB
from ...crypto import Cert, CertPurpose


class OpenVPNAndroidClientExporter(Exporter):
    def name(self) -> str:
        return "openvpn-android-client"

    def export(self, db: DB, entity_name: str, target_path: Path):
        entity = db.get_entity_by_id(entity_name)
        if not entity:
            raise ValueError(f"Entity '{entity_name}' not found")

        cert_chain = db.get_entity_certificate_chain(entity_name, purposes={CertPurpose.WEB_CLIENT})
        if not cert_chain:
            raise ValueError(f"No valid certificate chain found for '{entity_name}'")

        client_cert = cert_chain[0]
        client_key = next((key for key in entity.keys if key.id == client_cert.key_id), None)
        if not client_key:
            raise ValueError(f"Private key not found for certificate '{client_cert.id}'")

        ca_cert = cert_chain[-1]  # The last certificate in the chain is the root CA

        config = self._generate_openvpn_config(entity_name, client_cert, client_key, ca_cert)

        config_path = target_path / f"{entity_name}_openvpn_android.ovpn"
        with open(config_path, "w") as f:
            f.write(config)

        print(f"OpenVPN Android client configuration exported to: {config_path}")

    def _generate_openvpn_config(self, client_name: str, client_cert: Cert, client_key: Path, ca_cert: Cert) -> str:
        config = f"""client
dev tun
proto udp
remote your-vpn-server.com 1194
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3

<ca>
{self._read_file_content(ca_cert.path)}
</ca>

<cert>
{self._read_file_content(client_cert.path)}
</cert>

<key>
{self._read_file_content(client_key.path)}
</key>

<tls-auth>
# Insert your preshared key here
</tls-auth>
key-direction 1
"""
        return config

    def _read_file_content(self, file_path: Path) -> str:
        with open(file_path, "r") as f:
            return f.read().strip()
