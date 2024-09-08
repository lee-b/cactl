from .crypto import Cert, CertRequest, Key, Cipher


class Backend:
    def gen_key(self, cipher: Cipher) -> Key:
        raise NotImplementedError()

    def sign_request(self, request: CertRequest, signing_key: Key) -> Cert:
        raise NotImplementedError()
