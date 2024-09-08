from argparse import _SubParsersAction, Namespace
from datetime import datetime, timedelta
from typing import Optional

from ..backend import Backend
from ..db import DB, Entity
from ..subcommand import Subcommand
from ..crypto import CertPurpose, Cipher, Key, CertRequest, Cert


class NewServerSubcommand(Subcommand):
    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("new-server", help="Create a new server key and cert")
        subcmd.set_defaults(func=self.run)

        subcmd.add_argument("--with-intermediate-ca", type=str, help="Name of the intermediate CA to use for signing")
        subcmd.add_argument("server_hostname", type=str, help="Hostname of the server")
        subcmd.add_argument("--validity", type=int, default=365, help="Validity period in days (default: 365)")
        subcmd.add_argument("--key-type", type=str, choices=["RSA2048", "RSA4096"], default="RSA2048", help="Key type (default: RSA2048)")

    def run(self, ns: Namespace, db: DB, backend: Backend) -> int:
        server_hostname = ns.server_hostname
        intermediate_ca_name = ns.with_intermediate_ca
        validity_days = ns.validity
        key_type = Cipher[ns.key_type]

        # Check if the server already exists
        if server_hostname in db.get_servers():
            print(f"Error: Server '{server_hostname}' already exists.")
            return 1

        # Get the signing CA
        signing_ca = self._get_signing_ca(db, intermediate_ca_name)
        if not signing_ca:
            print("Error: No suitable CA found for signing.")
            return 1

        # Create a new server entity
        server_entity = Entity(name=server_hostname, can_sign=False, min_strength=key_type.value)
        db.add_server(server_entity)

        # Generate a new key for the server
        key = backend.gen_key(key_type)
        db.add_key(key, server_hostname)

        # Create a certificate request
        start_date = datetime.utcnow()
        end_date = start_date + timedelta(days=validity_days)
        cert_request = CertRequest(
            id=backend._generate_id(),
            purposes={CertPurpose.WEB_SERVER},
            start_date=start_date,
            end_date=end_date,
            file_format=key.file_format,
            path=key.path.with_suffix(".csr")
        )
        db.add_cert_request(cert_request, server_hostname)

        # Sign the certificate request
        cert = backend.sign_request(cert_request, signing_ca.keys[0])
        db.add_cert(cert, server_hostname)

        print(f"Successfully created new server '{server_hostname}':")
        print(f"  Key: {key.path}")
        print(f"  Certificate: {cert.path}")
        print(f"  Signed by: {signing_ca.name}")
        print(f"  Valid until: {end_date}")

        return 0

    def _get_signing_ca(self, db: DB, intermediate_ca_name: Optional[str]) -> Optional[Entity]:
        if intermediate_ca_name:
            ca = db.get_entity_by_id(intermediate_ca_name)
            if ca and ca.can_sign:
                return ca
            else:
                print(f"Error: Intermediate CA '{intermediate_ca_name}' not found or cannot sign.")
                return None
        else:
            # Try to get the default signing CA
            ca = db.get_default_signing_ca()
            if ca:
                return ca
            else:
                print("Error: No default signing CA found.")
                return None
