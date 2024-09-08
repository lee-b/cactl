from pathlib import Path
from typing import List

from ...exporter import Exporter
from ...db import DB
from ...crypto import Cert, CertPurpose, Key


class OpenVPNServerExporter(Exporter):
    def name(self) -> str:
        return "openvpn-server"

    def export(self, db: DB, entity_name: str, target_path: Path):
        entity = db.get_entity_by_id(entity_name)
        if not entity:
            raise ValueError(f"Entity '{entity_name}' not found")

        cert_chain = db.get_entity_certificate_chain(entity_name, purposes={CertPurpose.WEB_SERVER})
        if not cert_chain:
            raise ValueError(f"No valid certificate chain found for '{entity_name}'")

        server_cert = cert_chain[0]
        server_key = next((key for key in entity.keys if key.id == server_cert.key_id), None)
        if not server_key:
            raise ValueError(f"Private key not found for certificate '{server_cert.id}'")

        ca_cert = cert_chain[-1]  # The last certificate in the chain is the root CA

        config = self._generate_openvpn_config(entity_name, server_cert, server_key, ca_cert)

        config_path = target_path / f"{entity_name}_openvpn_server.conf"
        with open(config_path, "w") as f:
            f.write(config)

        print(f"OpenVPN server configuration exported to: {config_path}")

    def _generate_openvpn_config(self, server_name: str, server_cert: Cert, server_key: Key, ca_cert: Cert) -> str:
        config = f"""# OpenVPN Server Configuration for {server_name}

port 1194
proto udp
dev tun

ca {ca_cert.path}
cert {server_cert.path}
key {server_key.path}

dh dh2048.pem  # You need to generate this file separately with: openssl dhparam -out dh2048.pem 2048

server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt

push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 208.67.222.222"
push "dhcp-option DNS 208.67.220.220"

keepalive 10 120
cipher AES-256-GCM
auth SHA256

user nobody
group nogroup

persist-key
persist-tun

status openvpn-status.log
verb 3

# Uncomment this line to enable the use of a preshared key
# tls-auth ta.key 0  # You need to generate this key file separately

# Uncomment these lines if you want to enable client-to-client communication
# client-to-client
# push "route 10.8.0.0 255.255.255.0"

# Uncomment this line if you want to enable compression (not recommended for security reasons)
# comp-lzo

# Uncomment these lines and edit them if you want to use a CRL
# crl-verify crl.pem
"""
        return config

    def _read_file_content(self, file_path: Path) -> str:
        with open(file_path, "r") as f:
            return f.read().strip()
