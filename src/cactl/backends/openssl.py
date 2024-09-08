import os
from datetime import datetime
from pathlib import Path
from subprocess import check_output, CalledProcessError
from typing import List

from cactl.crypto import Cert, CertRequest, Cipher, Key, FileFormat, CertPurpose
from ..backend import Backend


class OpenSSLBackend(Backend):
    def gen_key(self, cipher: Cipher) -> Key:
        key_id = self._generate_id()
        key_path = Path(f"{key_id}.key")
        key_length = self._get_key_length(cipher)

        openssl_cmd = [
            "openssl", "genpkey",
            "-algorithm", "RSA",
            "-pkeyopt", f"rsa_keygen_bits:{key_length}",
            "-out", str(key_path)
        ]

        try:
            check_output(openssl_cmd)
        except CalledProcessError as e:
            raise RuntimeError(f"Failed to generate key: {e}")

        return Key(key_id, key_path, FileFormat.PEM, key_length)

    def sign_request(self, request: CertRequest, signing_key: Key) -> Cert:
        cert_id = self._generate_id()
        cert_path = Path(f"{cert_id}.crt")

        openssl_cmd = [
            "openssl", "x509",
            "-req",
            "-in", str(request._path),
            "-CA", str(signing_key._path),
            "-CAkey", str(signing_key._path),
            "-CAcreateserial",
            "-out", str(cert_path),
            "-days", str(self._calculate_days(request._start_date, request._end_date)),
            "-sha256"
        ]

        openssl_cmd.extend(self._get_purpose_extensions(request._purposes))

        try:
            check_output(openssl_cmd)
        except CalledProcessError as e:
            raise RuntimeError(f"Failed to sign certificate: {e}")

        return Cert(
            cert_id,
            request._format,
            cert_path,
            signing_key,
            request._purposes,
            request._start_date,
            request._end_date
        )

    def _generate_id(self) -> str:
        return os.urandom(16).hex()

    def _get_key_length(self, cipher: Cipher) -> int:
        return int(cipher.name[3:])

    def _calculate_days(self, start_date: datetime, end_date: datetime) -> int:
        return (end_date - start_date).days

    def _get_purpose_extensions(self, purposes: set[CertPurpose]) -> List[str]:
        extensions = []
        for purpose in purposes:
            if purpose == CertPurpose.ROOT_CA:
                extensions.extend(["-extensions", "v3_ca"])
            elif purpose == CertPurpose.INTERMEDIATE_CA:
                extensions.extend(["-extensions", "v3_intermediate_ca"])
            elif purpose == CertPurpose.WEB_SERVER:
                extensions.extend(["-extensions", "server_cert"])
            elif purpose == CertPurpose.WEB_CLIENT:
                extensions.extend(["-extensions", "usr_cert"])
            elif purpose == CertPurpose.EMAIL_IDENTITY:
                extensions.extend(["-extensions", "email_cert"])
            elif purpose == CertPurpose.OBJECT_SIGNING:
                extensions.extend(["-extensions", "codesigning_cert"])
            elif purpose == CertPurpose.TIMESTAMPING:
                extensions.extend(["-extensions", "timestamping_cert"])
        return extensions
