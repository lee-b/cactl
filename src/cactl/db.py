import os
import dbm
import json
import logging
from enum import Enum, auto, unique
from pathlib import Path
from typing import List, Tuple, Optional

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
    EMAILS = auto()
    ENTITY_TUPLES = auto() # json-encoded Tuple[EntityID, Entity]


class DBM:
    def __init__(self, path: Path) -> None:
        self._path = path
        self._dbm_handle = dbm.open(str(self._path), 'c')

    def __del__(self):
        self._dbm_handle.close()

    def ensure_exists(self):
        if not self._path.exists():
            try:
                os.makedirs(self._path.parent, exist_ok=True)
                self._dbm_handle = dbm.open(str(self._path), 'n')
                db_version = "1.0"

                self._dbm_handle[DBKey.DB_VERSION.name] = db_version.encode()

            except IOError:
                try:
                    os.unlink(self._path)
                except IOError:
                    pass

            logger.info(f"Initialized new database, version {db_version}, at {self._path}")

    def _put_str(self, key: DBKey, value: str):
        self._dbm_handle[key.name] = value.encode()

    def _get_str(self, key: DBKey) -> str:
        return self._dbm_handle[key.name].decode()

    def _put_int(self, key: DBKey, value: int):
        self._put_str(key, str(value))

    def _get_int(self, key: DBKey) -> int:
        return int(self._get_str(key))

    def _put_real(self, key: DBKey, value: float):
        self._put_str(key, str(value))

    def _get_real(self, key: DBKey) -> float:
        return float(self._get_str(key))

    def _put_bool(self, key: DBKey, value: bool):
        self._put_str(key, "True" if value else "False")

    def _get_bool(self, key: DBKey) -> bool:
        return self._get_str(key) == 'True'

    def _put_list(self, key: DBKey, value: List):
        self._put_str(key, json.dumps(value))

    def _get_list(self, key: DBKey) -> List:
        return json.loads(self._get_str(key))

    def _put_dict(self, key: DBKey, value: dict):
        self._put_str(key, json.dumps(value))

    def _get_dict(self, key: DBKey) -> dict:
        return json.loads(self._get_str(key))


class DB:
    def __init__(self, db_dir_path: Path):
        self._path = db_dir_path / 'db.dbm'
        self._dbm = DBM(self._path)
        self._dbm.ensure_exists()

        db_version = self._dbm._get_str(DBKey.DB_VERSION)

        if db_version != "1.0":
            raise ValueError(f"DB version {db_version} not recognised!")
        else:
            logger.info(f"Loaded database, version {db_version}, from {self._path}")

    def get_CAs(self) -> List[EntityID]:
        return self._dbm._get_list(DBKey.ROOT_CAS)

    def get_intermediate_CAs(self) -> List[EntityID]:
        return self._dbm._get_list(DBKey.INTERMEDIATE_CAS)

    def get_servers(self) -> List[EntityID]:
        return self._dbm._get_list(DBKey.SERVERS)

    def get_clients(self) -> List[EntityID]:
        return self._dbm._get_list(DBKey.CLIENTS)

    def get_emails(self) -> List[EntityID]:
        return self._dbm._get_list(DBKey.EMAILS)

    def get_entities(self) -> List[EntityID]:
        return (
            self.get_CAs()
            + self.get_intermediate_CAs()
            + self.get_servers()
            + self.get_clients()
            + self.get_emails()
        )

    def get_entity_certificate_chain(self, end_entity_id: EntityID) -> List[Cert]:
        entity_tuples = self._dbm._get_dict(DBKey.ENTITY_TUPLES)
        chain = []
        current_entity_id = end_entity_id

        while current_entity_id:
            entity_data = entity_tuples.get(current_entity_id)
            if not entity_data:
                break

            entity = Entity(**entity_data)
            cert = entity.get_certs()[0]  # Assuming the first cert is the main one
            chain.append(cert)

            if entity.can_sign():
                current_entity_id = entity_data.get('parent_id')
            else:
                break

        return list(reversed(chain))

    def get_default_signing_ca(self) -> Optional[Entity]:
        cas = self.get_CAs()
        if cas:
            return self.get_entity_by_id(cas[0])
        return None

    def get_entity_by_id(self, entity_id: EntityID) -> Optional[Entity]:
        entity_tuples = self._dbm._get_dict(DBKey.ENTITY_TUPLES)
        entity_data = entity_tuples.get(entity_id)
        if entity_data:
            return Entity(**entity_data)
        return None

    def add_entity(self, entity: Entity, entity_type: DBKey):
        entity_id = entity._name
        entity_tuples = self._dbm._get_dict(DBKey.ENTITY_TUPLES)
        entity_tuples[entity_id] = entity.__dict__
        self._dbm._put_dict(DBKey.ENTITY_TUPLES, entity_tuples)

        entity_list = self._dbm._get_list(entity_type)
        entity_list.append(entity_id)
        self._dbm._put_list(entity_type, entity_list)

    def add_CA(self, ca: Entity):
        self.add_entity(ca, DBKey.ROOT_CAS)

    def add_intermediate_CA(self, ca: Entity):
        self.add_entity(ca, DBKey.INTERMEDIATE_CAS)

    def add_server(self, server: Entity):
        self.add_entity(server, DBKey.SERVERS)

    def add_client(self, client: Entity):
        self.add_entity(client, DBKey.CLIENTS)

    def add_email(self, email: Entity):
        self.add_entity(email, DBKey.EMAILS)
