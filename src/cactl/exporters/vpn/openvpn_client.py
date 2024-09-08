from pathlib import Path
from typing import List
import subprocess

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

        # Create a directory for the OpenVPN client files
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

        # Generate a README.TXT file
        readme_content = self._generate_readme(entity_name)
        self._write_file(openvpn_dir / "README.TXT", readme_content)

        print(f"OpenVPN client files exported to: {openvpn_dir}")
        print(f"OpenVPN client configuration: {config_path}")
        print("Please refer to the README.TXT file for setup instructions.")

    def _generate_openvpn_config(self, client_name: str) -> str:
        config = f"""# OpenVPN Client Configuration for {client_name}

client
dev tun
proto udp

# Replace with your OpenVPN server's hostname or IP address
remote your-server-hostname-or-ip 1194

resolv-retry infinite
nobind
persist-key
persist-tun

ca ca.crt
cert client.crt
key client.key

remote-cert-tls server
tls-auth ta.key 1
cipher AES-256-GCM
auth SHA256

compress
verb 3

# Uncomment the following line if you want to enable LZO compression
# comp-lzo

# Uncomment the following lines if you want to use a proxy
# http-proxy-retry
# http-proxy [proxy server] [proxy port]

# Uncomment the following line if you want to use a proxy with authentication
# http-proxy-user-pass proxy-auth.txt
"""
        return config

    def _read_file_content(self, file_path: Path) -> str:
        with open(file_path, "r") as f:
            return f.read().strip()

    def _write_file(self, file_path: Path, content: str):
        with open(file_path, "w") as f:
            f.write(content)

    def _generate_tls_auth_key(self) -> str:
        try:
            result = subprocess.run(
                ["openvpn", "--genkey", "--secret", "/dev/stdout"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error generating TLS auth key: {e}")
            return "# Error generating TLS auth key. Please generate manually using: openvpn --genkey --secret ta.key"

    def _generate_readme(self, client_name: str) -> str:
        return f"""OpenVPN Client Setup Instructions for {client_name}

This directory contains the following files necessary for setting up your OpenVPN client:

1. {client_name}_client.ovpn: The main OpenVPN client configuration file
2. client.crt: The client's SSL certificate
3. client.key: The client's private key
4. ca.crt: The Certificate Authority (CA) certificate
5. ta.key: TLS authentication key

To set up your OpenVPN client:

1. Install OpenVPN client software:
   - Windows: Download and install OpenVPN GUI from https://openvpn.net/community-downloads/
   - macOS: Install Tunnelblick from https://tunnelblick.net/ or use Homebrew to install OpenVPN
   - Linux: Use your package manager to install OpenVPN (e.g., sudo apt-get install openvpn)

2. Copy all files in this directory to the appropriate location:
   - Windows: C:\\Program Files\\OpenVPN\\config\\
   - macOS (Tunnelblick): Drag the entire folder onto the Tunnelblick icon
   - Linux: /etc/openvpn/client/

3. Edit the {client_name}_client.ovpn file:
   - Replace 'your-server-hostname-or-ip' with your OpenVPN server's hostname or IP address

4. Connect to the VPN:
   - Windows: Right-click the OpenVPN GUI system tray icon and select the configuration file
   - macOS (Tunnelblick): Click the Tunnelblick icon in the menu bar and select the configuration
   - Linux: Run 'sudo openvpn --config /etc/openvpn/client/{client_name}_client.ovpn'

5. Enter your username and password if prompted (if your server uses additional authentication)

Troubleshooting:
- Ensure that the OpenVPN server is running and accessible
- Check your firewall settings to allow OpenVPN traffic (usually UDP port 1194)
- Verify that the server's hostname or IP address in the .ovpn file is correct
- If using a proxy, uncomment and configure the proxy settings in the .ovpn file

For more detailed instructions or troubleshooting, please refer to the OpenVPN documentation or contact your system administrator.
"""
