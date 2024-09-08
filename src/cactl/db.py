import os
import dbm
import json
import logging
from enum import Enum, auto, unique
from pathlib import Path
from typing import List, Tuple

from .crypto import Key, Cert, CertPurpose
from .entity import EntityID, Entity, EntityChain


logger = logging.getLogger(__name__)


@unique
class DBKey(Enum):
    DB_VERSION = auto()
    ROOT_CAS = auto()
    INTERMEDIATE_CAS = auto()
    SERVERS = auto()
    CLIENTS = auto()
    ENTITY_TUPLES = auto() # json-encoded Tuple[EntityID, Entity]


class DBM:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._dbm_handle = dbm.open(self._dbm_path, 'w')

    def __del__(self):
        self._dbm_handle.close()

    def ensure_exists(self):
        if not self._path.exists():
            try:
                os.makedirs(self._path)
                self._dbm_handle = dbm.open(self._dbm_path, 'n')
                db_version = "1.0"

                self._dbm_handle[self.DBKey.VERSION.name] = db_version.encode()

            except IOError:
                try:
                    os.unlink(self._path)
                except IOError:
                    pass

            logger.info(f"Initialized new database, version {db_version}, at {self._dbm_path}")

    def _put_str(self, key: DBKey, value: str):
        self._dbm_handle[str(key.name)] = value.encode()

    def _get_str(self, key: str) -> str:
        return self._dbm_handle[str(key.name)].decode()

    def _put_int(self, key: str, value: int):
        self._put_str(str(value))

    def _get_int(self, key: str) -> int:
        return int(self._get_db_str(key))

    def _put_real(self, key: str, value: float):
        self._put_str(str(value))

    def _get_real(self, key: str) -> float:
        return float(self._get_db_str(key))

    def _put_bool(self, key: str, value: bool):
        self._put_str("True" if value else "False")

    def _get_bool(self, key: str) -> int:
        return self._get_str(key) == 'True'



class DB:
    def __init__(self, db_dir_path: Path):
        self._path = db_dir_path
        self._dbm_path = self._path / 'db.dbm'
        self._dbm = DBM(self._dbm_path)

        db_version = self._get_db_str(DBKey.DB_VERSION)

        if db_version != "1.0":
            raise ValueError(f"DB version {db_version} not recognised!")
        else:
            logger.info(f"Loaded database, version {db_version}, from {self._dbm_path}")

    def get_CAs(self) -> List[EntityID]:
        raise NotImplementedError()

    def get_intermediate_CAs(self) -> List[EntityID]:
        raise NotImplementedError()

    def get_servers(self) -> List[EntityID]:
        raise NotImplementedError()

    def get_clients(self) -> List[EntityID]:
        raise NotImplementedError()

    def get_emails(self) -> List[EntityID]:
        raise NotImplementedError()

    def get_entities(self) -> List[EntityID]:
        return (
            self.get_CAs()
            + self.get_intermediate_CAs()
            + self.get_servers()
            + self.get_clients()
            + self.get_emails()
        )

    def get_entity_certificate_chain(self, end_entity_id: EntityID) -> List[Cert]:
        raise NotImplementedError()

    def get_default_signing_ca(self) -> Entity:
        raise NotImplementedError()

    def get_entity_by_id(self, entity_id: EntityID) -> Entity:
        raise NotImplementedError()
