from pathlib import Path
from typing import List

from ...exporter import Exporter
from ...db import DB
from ...crypto import Cert, CertPurpose, Key


class OpenVPNClientExporter(Exporter):
    def name(self) -> str:
        return "openvpn-client"

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

        # Create a directory for the OpenVPN Android client files
        openvpn_dir = target_path / f"{entity_name}_openvpn_client"
        openvpn_dir.mkdir(parents=True, exist_ok=True)

        # Write the certificate and key files
        self._write_file(openvpn_dir / "client.crt", self._read_file_content(client_cert.path))
        self._write_file(openvpn_dir / "client.key", self._read_file_content(client_key.path))
        self._write_file(openvpn_dir / "ca.crt", self._read_file_content(ca_cert.path))

        # Generate and write the TLS auth key
        tls_auth_key = self._generate_tls_auth_key()
        self._write_file(openvpn_dir / "ta.key", tls_auth_key)

        config = self._generate_openvpn_config(entity_name)

        config_path = openvpn_dir / f"{entity_name}_client.ovpn"
        self._write_file(config_path, config)

        print(f"OpenVPN client files exported to: {openvpn_dir}")
        print(f"OpenVPN client configuration: {config_path}")

    def _generate_openvpn_config(self, client_name: str) -> str:
        config = f"""# OpenVPN Client Configuration for {client_name}

client
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

ca ca.crt
cert client.crt
key client.key

tls-auth ta.key 1

# Uncomment this line if you want to enable compression (not recommended for security reasons)
# comp-lzo
"""
        return config

    def _read_file_content(self, file_path: Path) -> str:
        with open(file_path, "r") as f:
            return f.read().strip()

    def _write_file(self, file_path: Path, content: str):
        with open(file_path, "w") as f:
            f.write(content)

    def _generate_tls_auth_key(self) -> str:
        # This is a placeholder. In a real implementation, you would use a cryptographic
        # library or call an external command to generate a TLS auth key.
        return "# Placeholder for TLS auth key\n# Generate with: openvpn --genkey --secret ta.key"
