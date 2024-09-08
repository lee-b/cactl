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

        config = self._generate_nginx_config(entity_name, server_cert, key, cert_chain)

        config_path = target_path / f"{entity_name}_nginx.conf"
        with open(config_path, "w") as f:
            f.write(config)

        print(f"Nginx configuration exported to: {config_path}")

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
