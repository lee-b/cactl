from pathlib import Path
from typing import List
import subprocess

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

        config = self._generate_openvpn_config(entity_name)
        config_path = openvpn_dir / f"{entity_name}_server.conf"
        self._write_file(config_path, config)

        # Generate a README.TXT file
        readme_content = self._generate_readme(entity_name)
        self._write_file(openvpn_dir / "README.TXT", readme_content)

        print(f"OpenVPN server files exported to: {openvpn_dir}")
        print(f"OpenVPN server configuration: {config_path}")
        print("Please refer to the README.TXT file for setup instructions.")

    def _generate_openvpn_config(self, server_name: str) -> str:
        config = f"""# OpenVPN Server Configuration for {server_name}

port 1194
proto udp
dev tun

ca ca.crt
cert server.crt
key server.key

dh dh2048.pem

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

tls-auth ta.key 0

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
        try:
            result = subprocess.run(
                ["openssl", "dhparam", "2048"],
                capture_output=True,
                text=True,
                check=True
            )
            return result.stdout
        except subprocess.CalledProcessError as e:
            print(f"Error generating Diffie-Hellman parameters: {e}")
            return "# Error generating Diffie-Hellman parameters. Please generate manually using: openssl dhparam -out dh2048.pem 2048"

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

    def _generate_readme(self, server_name: str) -> str:
        return f"""OpenVPN Server Setup Instructions for {server_name}

This directory contains the following files necessary for setting up your OpenVPN server:

1. {server_name}_server.conf: The main OpenVPN server configuration file
2. server.crt: The server's SSL certificate
3. server.key: The server's private key
4. ca.crt: The Certificate Authority (CA) certificate
5. dh2048.pem: Diffie-Hellman parameters for key exchange
6. ta.key: TLS authentication key

To set up your OpenVPN server:

1. Install OpenVPN on your server if you haven't already:
   sudo apt-get update
   sudo apt-get install openvpn

2. Copy all files in this directory to /etc/openvpn/ on your server:
   sudo cp * /etc/openvpn/

3. Ensure the configuration file has the correct name:
   sudo mv /etc/openvpn/{server_name}_server.conf /etc/openvpn/server.conf

4. Set the correct permissions:
   sudo chmod 600 /etc/openvpn/server.key
   sudo chmod 600 /etc/openvpn/ta.key

5. Enable IP forwarding:
   echo 'net.ipv4.ip_forward=1' | sudo tee -a /etc/sysctl.conf
   sudo sysctl -p

6. Configure your firewall to allow OpenVPN traffic. For example, if using UFW:
   sudo ufw allow 1194/udp
   sudo ufw allow OpenSSH

7. Start the OpenVPN service:
   sudo systemctl start openvpn@server
   sudo systemctl enable openvpn@server

8. Check the status of the OpenVPN service:
   sudo systemctl status openvpn@server

Your OpenVPN server should now be running. To connect clients, you'll need to create client configuration files and certificates. Refer to the OpenVPN documentation for more information on setting up clients.

Note: This setup provides a basic configuration. Depending on your specific needs and security requirements, you may need to make additional adjustments to the server configuration and network settings.
"""
