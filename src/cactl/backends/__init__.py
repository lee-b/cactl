from argparse import Namespace

from ..backend import Backend

from .openssl import OpenSSLBackend


def get_backend(conf: Namespace) -> Backend:
    return OpenSSLBackend()
