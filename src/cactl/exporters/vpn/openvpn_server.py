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

        # Create a directory for the OpenVPN server files
        openvpn_dir = target_path / f"{entity_name}_openvpn_server"
        openvpn_dir.mkdir(parents=True, exist_ok=True)

        # Write the certificate and key files
        self._write_file(openvpn_dir / "server.crt", self._read_file_content(server_cert.path))
        self._write_file(openvpn_dir / "server.key", self._read_file_content(server_key.path))
        self._write_file(openvpn_dir / "ca.crt", self._read_file_content(ca_cert.path))

        # Generate and write the Diffie-Hellman parameters
        dh_params = self._generate_dh_params()
        self._write_file(openvpn_dir / "dh2048.pem", dh_params)

        # Generate and write the TLS auth key
        tls_auth_key = self._generate_tls_auth_key()
        self._write_file(openvpn_dir / "ta.key", tls_auth_key)

        config = self._generate_openvpn_config(entity_name, openvpn_dir)

        config_path = openvpn_dir / f"{entity_name}_server.conf"
        self._write_file(config_path, config)

        print(f"OpenVPN server files exported to: {openvpn_dir}")
        print(f"OpenVPN server configuration: {config_path}")

    def _generate_openvpn_config(self, server_name: str, openvpn_dir: Path) -> str:
        config = f"""# OpenVPN Server Configuration for {server_name}

port 1194
proto udp
dev tun

ca {openvpn_dir}/ca.crt
cert {openvpn_dir}/server.crt
key {openvpn_dir}/server.key

dh {openvpn_dir}/dh2048.pem

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

tls-auth {openvpn_dir}/ta.key 0

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

    def _write_file(self, file_path: Path, content: str):
        with open(file_path, "w") as f:
            f.write(content)

    def _generate_dh_params(self) -> str:
        # This is a placeholder. In a real implementation, you would use a cryptographic
        # library or call an external command to generate Diffie-Hellman parameters.
        return "# Placeholder for Diffie-Hellman parameters\n# Generate with: openssl dhparam -out dh2048.pem 2048"

    def _generate_tls_auth_key(self) -> str:
        # This is a placeholder. In a real implementation, you would use a cryptographic
        # library or call an external command to generate a TLS auth key.
        return "# Placeholder for TLS auth key\n# Generate with: openvpn --genkey --secret ta.key"
