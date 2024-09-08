from pathlib import Path
from typing import Optional, Set
from enum import Enum, auto, unique
from datetime import datetime as DateTime


@unique
class FileFormat(Enum):
    PEM = auto()
    DER = auto()


class Key:
    def __init__(self, id: str, path: Optional[Path], file_format: FileFormat, length: int):
        self._id = id
        self._file_format = file_format
        self._path = path
        self._length = length


@unique
class CertPurpose(Enum):
    """
    Purpose of the certificate.
    """
    ROOT_CA = auto()
    INTERMEDIATE_CA = auto()
    WEB_SERVER = auto()
    WEB_CLIENT = auto()
    EMAIL_IDENTITY = auto()
    OBJECT_SIGNING = auto()
    TIMESTAMPING = auto()


class CertRequest:
    def __init__(self, id: str, purposes: Set[CertPurpose], start_date: DateTime, end_date: DateTime, file_format: FileFormat, path: Path):
        self._id = id
        self._purposes = purposes
        self._start_date = start_date
        self._end_date = end_date
        self._format = file_format
        self._path = Path # path to the actual csr file, containing the public key and metadata


class Cert:
    def __init__(self, id: str, file_format: FileFormat, path: Path, key: Key, purposes: Set[CertPurpose], start_date: DateTime, end_date: DateTime):
        self._id = id
        self._file_format = file_format
        self._path = path
        self._key = key
        self._start_date = start_date
        self._end_date = end_date
        self._purposes = purposes


@unique
class Cipher(Enum):
    RSA1024 = auto()
    RSA2048 = auto()
    RSA4096 = auto()
