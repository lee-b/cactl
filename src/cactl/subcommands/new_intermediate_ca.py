from argparse import _SubParsersAction, Namespace
from datetime import datetime, timedelta

from ..backend import Backend
from ..db import DB, Entity
from ..subcommand import Subcommand
from ..crypto import Cipher, CertPurpose, CertRequest, Key


class NewIntermediateCASubcommand(Subcommand):
    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("new-intermediate-ca", help="Create a new Intermediate (signing) CA")
        subcmd.set_defaults(func=self.run)

        subcmd.add_argument("intermediate_ca_name", type=str, help="Name of the new Intermediate CA")
        subcmd.add_argument("--parent-ca", type=str, help="Name of the parent CA (default: first root CA)")
        subcmd.add_argument("--key-size", type=int, choices=[2048, 4096], default=4096,
                            help="Key size in bits (default: 4096)")
        subcmd.add_argument("--validity", type=int, default=1825,
                            help="Validity period in days (default: 1825)")

    def run(self, ns: Namespace, db: DB, backend: Backend) -> int:
        # Get the parent CA
        parent_ca_name = ns.parent_ca or db.get_CAs()[0]
        parent_ca = db.get_entity_by_id(parent_ca_name)
        if not parent_ca:
            print(f"Error: Parent CA '{parent_ca_name}' not found.")
            return 1

        # Create a new Intermediate CA entity
        intermediate_ca = Entity(
            name=ns.intermediate_ca_name,
            can_sign=True,
            min_strength=ns.key_size,
            parent_id=parent_ca.name
        )

        # Generate a new key
        cipher = Cipher.RSA2048 if ns.key_size == 2048 else Cipher.RSA4096
        key = backend.gen_key(cipher)

        # Add the key to the entity and the database
        intermediate_ca.add_key(key)
        db.add_key(key, intermediate_ca.name)

        # Create a certificate request
        start_date = datetime.utcnow()
        end_date = start_date + timedelta(days=ns.validity)
        cert_request = CertRequest(
            id=f"{intermediate_ca.name}_request",
            purposes={CertPurpose.INTERMEDIATE_CA},
            start_date=start_date,
            end_date=end_date,
            file_format=key.file_format,
            path=key.path.with_suffix(".csr")
        )

        # Sign the certificate request using the parent CA's key
        parent_key = parent_ca.keys[0]  # Assuming the first key is the signing key
        cert = backend.sign_request(cert_request, parent_key)

        # Add the certificate to the entity and the database
        intermediate_ca.add_cert(cert)
        db.add_cert(cert, intermediate_ca.name)

        # Add the Intermediate CA to the database
        db.add_intermediate_CA(intermediate_ca)

        print(f"Intermediate CA '{intermediate_ca.name}' created successfully.")
        print(f"Parent CA: {parent_ca.name}")
        print(f"Key ID: {key.id}")
        print(f"Certificate ID: {cert.id}")
        print(f"Validity: {cert.start_date} to {cert.end_date}")

        return 0
