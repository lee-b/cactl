from pathlib import Path
from typing import List

from ...exporter import Exporter
from ...db import DB
from ...crypto import Cert, CertPurpose, Key


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

        # Generate and write the Nginx configuration
        config = self._generate_nginx_config(entity_name, server_cert, key, cert_chain)
        config_path = nginx_dir / f"{entity_name}_nginx.conf"
        self._write_file(config_path, config)

        # Write the certificate chain file
        chain_file = nginx_dir / f"{entity_name}_cert_chain.pem"
        self._write_cert_chain(chain_file, cert_chain)

        print(f"Nginx configuration files exported to: {nginx_dir}")
        print(f"  Configuration file: {config_path}")
        print(f"  Certificate chain: {chain_file}")
        print(f"  Server certificate: {server_cert.path}")
        print(f"  Private key: {key.path}")

    def _generate_nginx_config(self, server_name: str, server_cert: Cert, key: Key, cert_chain: List[Cert]) -> str:
        config = f"""
server {{
    listen 443 ssl;
    server_name {server_name};

    ssl_certificate {server_cert.path};
    ssl_certificate_key {key.path};

    ssl_protocols TLSv1.2 TLSv1.3;
    ssl_prefer_server_ciphers on;
    ssl_ciphers ECDHE-ECDSA-AES128-GCM-SHA256:ECDHE-RSA-AES128-GCM-SHA256:ECDHE-ECDSA-AES256-GCM-SHA384:ECDHE-RSA-AES256-GCM-SHA384:ECDHE-ECDSA-CHACHA20-POLY1305:ECDHE-RSA-CHACHA20-POLY1305:DHE-RSA-AES128-GCM-SHA256:DHE-RSA-AES256-GCM-SHA384;

    ssl_session_cache shared:SSL:10m;
    ssl_session_timeout 10m;
    ssl_session_tickets off;

    ssl_stapling on;
    ssl_stapling_verify on;

    # Add intermediate certificates to the chain
    ssl_trusted_certificate {self._get_chain_path(cert_chain)};

    # HSTS (optional, but recommended)
    add_header Strict-Transport-Security "max-age=63072000; includeSubDomains; preload";

    # Other security headers
    add_header X-Frame-Options DENY;
    add_header X-Content-Type-Options nosniff;
    add_header X-XSS-Protection "1; mode=block";

    # Your website configuration goes here
    location / {{
        root /var/www/html;
        index index.html;
    }}
}}

server {{
    listen 80;
    server_name {server_name};
    return 301 https://$server_name$request_uri;
}}
"""
        return config

    def _get_chain_path(self, cert_chain: List[Cert]) -> str:
        # Assuming the first certificate in the chain is the server certificate,
        # and we want to include all intermediate certificates
        if len(cert_chain) > 1:
            return " ".join(str(cert.path) for cert in cert_chain[1:])
        return ""

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
