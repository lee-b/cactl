from pathlib import Path
from typing import List
import shutil

from ...exporter import Exporter
from ...db import DB
from ...crypto import Cert, CertPurpose, Key, Cipher


class NginxExporter(Exporter):
    def name(self) -> str:
        return "nginx"

    def export(self, db: DB, entity_name: str, target_path: Path):
        entity = db.get_entity_by_id(entity_name)
        if not entity:
            raise ValueError(f"Entity '{entity_name}' not found")

        cert_chain = db.get_entity_certificate_chain(entity_name, purposes={CertPurpose.WEB_SERVER, CertPurpose.INTERMEDIATE_CA, CertPurpose.ROOT_CA})
        if not cert_chain:
            raise ValueError(f"No valid certificate chain found for '{entity_name}'")

        server_cert = cert_chain[0]
        key = next((key for key in entity.keys if key.id == server_cert.key_id), None)
        if not key:
            raise ValueError(f"Private key not found for certificate '{server_cert.id}'")

        # Create a directory for the Nginx files
        nginx_dir = target_path / f"{entity_name}_nginx"
        nginx_dir.mkdir(parents=True, exist_ok=True)

        # Copy the server certificate and key to the Nginx directory
        new_cert_path = nginx_dir / f"{entity_name}_cert.pem"
        new_key_path = nginx_dir / f"{entity_name}_key.pem"
        shutil.copy(server_cert.path, new_cert_path)
        shutil.copy(key.path, new_key_path)

        # Write the certificate chain file
        chain_file = nginx_dir / f"{entity_name}_cert_chain.pem"
        self._write_cert_chain(chain_file, cert_chain)

        # Generate and write the Nginx configuration
        config = self._generate_nginx_config(entity_name, new_cert_path, new_key_path, chain_file, key)
        config_path = nginx_dir / f"{entity_name}_nginx.conf"
        self._write_file(config_path, config)

        # Generate a sample HTML file
        html_content = f"<html><body><h1>Welcome to {entity_name}</h1></body></html>"
        html_path = nginx_dir / "index.html"
        self._write_file(html_path, html_content)

        print(f"Nginx configuration files exported to: {nginx_dir}")
        print(f"  Configuration file: {config_path}")
        print(f"  Certificate chain: {chain_file}")
        print(f"  Server certificate: {new_cert_path}")
        print(f"  Private key: {new_key_path}")
        print(f"  Sample HTML file: {html_path}")
        print("\nTo use this configuration:")
        print(f"1. Copy the contents of {nginx_dir} to your Nginx server.")
        print(f"2. Update your main Nginx configuration to include {config_path}")
        print("3. Restart Nginx to apply the changes.")

    def _generate_nginx_config(self, server_name: str, cert_path: Path, key_path: Path, chain_path: Path, key: Key) -> str:
        ciphers = self._get_appropriate_ciphers(key)
        config = f"""
server {{
    listen 443 ssl;
    server_name {server_name};

    ssl_certificate {cert_path};
    ssl_certificate_key {key_path};
    ssl_trusted_certificate {chain_path};

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers {ciphers};

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    ssl_stapling on;
    ssl_stapling_verify on;

    # HSTS (optional, but recommended)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    # Other security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    root /var/www/html/{server_name};
    index index.html;

    location / {{
        try_files $uri $uri/ =404;
    }}
}}

server {{
    listen 80;
    server_name {server_name};
    return 301 https://$server_name$request_uri;
}}
"""
        return config

    def _get_appropriate_ciphers(self, key: Key) -> str:
        if key.length >= 4096:
            return "ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES256-GCM-SHA384"
        elif key.length >= 2048:
            return "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384"
        else:
            return "ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES128-GCM-SHA256"

    def _write_file(self, file_path: Path, content: str):
        with open(file_path, "w") as f:
            f.write(content)

    def _write_cert_chain(self, output_file: Path, cert_chain):
        pem_content = ""
        for cert in cert_chain:
            pem_content += self._read_file_content(cert.path) + "\n"
        self._write_file(output_file, pem_content.strip())

    def _read_file_content(self, file_path: Path) -> str:
        with open(file_path, "r") as f:
            return f.read().strip()
