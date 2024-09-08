from argparse import _SubParsersAction, Namespace
from datetime import datetime, timedelta

from ..backend import Backend
from ..db import DB, Entity
from ..subcommand import Subcommand
from ..crypto import Cipher, CertPurpose, CertRequest, Key


class NewRootCASubcommand(Subcommand):
    def augment_subcommands(self, subparsers: _SubParsersAction):
        subcmd = subparsers.add_parser("new-root-ca", help="Create a new Root CA")
        subcmd.set_defaults(func=self.run)

        subcmd.add_argument("root_ca_name", type=str, help="Name of the new Root CA")
        subcmd.add_argument("--key-size", type=int, choices=[2048, 4096], default=4096,
                            help="Key size in bits (default: 4096)")
        subcmd.add_argument("--validity", type=int, default=3650,
                            help="Validity period in days (default: 3650)")

    def run(self, ns: Namespace, db: DB, backend: Backend) -> int:
        # Create a new Root CA entity
        root_ca = Entity(
            name=ns.root_ca_name,
            can_sign=True,
            min_strength=ns.key_size
        )

        # Generate a new key
        cipher = Cipher.RSA2048 if ns.key_size == 2048 else Cipher.RSA4096
        key = backend.gen_key(cipher)

        # Add the key to the entity and the database
        root_ca.add_key(key)
        db.add_key(key, root_ca.name)

        # Create a certificate request
        start_date = datetime.utcnow()
        end_date = start_date + timedelta(days=ns.validity)
        cert_request = CertRequest(
            id=f"{root_ca.name}_request",
            purposes={CertPurpose.ROOT_CA},
            start_date=start_date,
            end_date=end_date,
            file_format=key.file_format,
            path=key.path.with_suffix(".csr")
        )

        # Sign the certificate request
        cert = backend.sign_request(cert_request, key)

        # Add the certificate to the entity and the database
        root_ca.add_cert(cert)
        db.add_cert(cert, root_ca.name)

        # Add the Root CA to the database
        db.add_CA(root_ca)

        print(f"Root CA '{root_ca.name}' created successfully.")
        print(f"Key ID: {key.id}")
        print(f"Certificate ID: {cert.id}")
        print(f"Validity: {cert.start_date} to {cert.end_date}")

        return 0
