from argparse import _SubParsersAction, Namespace
from datetime import datetime, timedelta
from typing import Optional

from ..backend import Backend
from ..db import DB, Entity
from ..subcommand import Subcommand
from ..crypto import CertPurpose, Cipher, Key, CertRequest, Cert


class NewClientSubcommand(Subcommand):
    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("new-client", help="Create a new client key and cert")
        subcmd.set_defaults(func=self.run)

        subcmd.add_argument("--with-intermediate-ca", type=str, help="Name of the intermediate CA to use for signing")
        subcmd.add_argument("client_name", type=str, help="Name of the client")
        subcmd.add_argument("--validity", type=int, default=365, help="Validity period in days (default: 365)")
        subcmd.add_argument("--key-type", type=str, choices=["RSA2048", "RSA4096"], default="RSA2048", help="Key type (default: RSA2048)")
        subcmd.add_argument("--email", type=str, help="Email address for the client")

    def run(self, ns: Namespace, db: DB, backend: Backend) -> int:
        client_name = ns.client_name
        intermediate_ca_name = ns.with_intermediate_ca
        validity_days = ns.validity
        key_type = Cipher[ns.key_type]
        email = ns.email

        # Check if the client already exists
        if client_name in db.get_clients():
            print(f"Error: Client '{client_name}' already exists.")
            return 1

        # Get the signing CA
        signing_ca = self._get_signing_ca(db, intermediate_ca_name)
        if not signing_ca:
            print("Error: No suitable CA found for signing.")
            return 1

        # Create a new client entity
        client_entity = Entity(name=client_name, can_sign=False, min_strength=key_type.value)
        db.add_client(client_entity)

        # Generate a new key for the client
        key = backend.gen_key(key_type)
        db.add_key(key, client_name)

        # Create a certificate request
        start_date = datetime.utcnow()
        end_date = start_date + timedelta(days=validity_days)
        purposes = {CertPurpose.WEB_CLIENT}
        if email:
            purposes.add(CertPurpose.EMAIL_IDENTITY)
        
        cert_request = CertRequest(
            id=backend._generate_id(),
            purposes=purposes,
            start_date=start_date,
            end_date=end_date,
            file_format=key.file_format,
            path=key.path.with_suffix(".csr")
        )
        db.add_cert_request(cert_request, client_name)

        # Sign the certificate request
        cert = backend.sign_request(cert_request, signing_ca.keys[0])
        db.add_cert(cert, client_name)

        print(f"Successfully created new client '{client_name}':")
        print(f"  Key: {key.path}")
        print(f"  Certificate: {cert.path}")
        print(f"  Signed by: {signing_ca.name}")
        print(f"  Valid until: {end_date}")
        if email:
            print(f"  Email: {email}")

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
