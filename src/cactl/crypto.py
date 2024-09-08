from pathlib import Path
from typing import Optional, Set
from enum import Enum, auto, unique
from datetime import datetime as DateTime
from pydantic import BaseModel, Field


@unique
class FileFormat(Enum):
    PEM = auto()
    DER = auto()


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


@unique
class Cipher(Enum):
    RSA1024 = auto()
    RSA2048 = auto()
    RSA4096 = auto()


class Key(BaseModel):
    id: str
    path: Optional[Path]
    file_format: FileFormat
    length: int


class CertRequest(BaseModel):
    id: str
    purposes: Set[CertPurpose]
    start_date: DateTime
    end_date: DateTime
    file_format: FileFormat
    path: Path


class Cert(BaseModel):
    id: str
    file_format: FileFormat
    path: Path
    key_id: str
    purposes: Set[CertPurpose]
    start_date: DateTime
    end_date: DateTime
