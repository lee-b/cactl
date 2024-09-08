from cactl.crypto import Cert, CertRequest, Cipher, Key
from subprocess import check_output

from ..backend import Backend


class OpenSSLBackend(Backend):
    def gen_key(self, cipher: Cipher) -> Key:
        raise NotImplementedError()

    def sign_request(self, request: CertRequest, signing_key: Key) -> Cert:
        raise NotImplementedError()
