import os
import dbm
import json
import logging
from enum import Enum, auto, unique
from pathlib import Path
from typing import List, Tuple, Optional, Dict
from datetime import datetime as DateTime

from .crypto import Key, Cert, CertPurpose, FileFormat
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
    ENTITY_TUPLES = auto()
    KEYS = auto()
    CERTS = auto()


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
                self._put_dict(DBKey.KEYS, {})
                self._put_dict(DBKey.CERTS, {})
                self._put_dict(DBKey.ENTITY_TUPLES, {})
                for key in [DBKey.ROOT_CAS, DBKey.INTERMEDIATE_CAS, DBKey.SERVERS, DBKey.CLIENTS, DBKey.EMAILS]:
                    self._put_list(key, [])

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

            entity = self._deserialize_entity(entity_data)
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
            return self._deserialize_entity(entity_data)
        return None

    def add_entity(self, entity: Entity, entity_type: DBKey):
        entity_id = entity._name
        entity_tuples = self._dbm._get_dict(DBKey.ENTITY_TUPLES)
        entity_tuples[entity_id] = self._serialize_entity(entity)
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

    def _serialize_key(self, key: Key) -> Dict:
        return {
            'id': key._id,
            'path': str(key._path) if key._path else None,
            'file_format': key._file_format.name,
            'length': key._length
        }

    def _deserialize_key(self, key_data: Dict) -> Key:
        return Key(
            id=key_data['id'],
            path=Path(key_data['path']) if key_data['path'] else None,
            file_format=FileFormat[key_data['file_format']],
            length=key_data['length']
        )

    def _serialize_cert(self, cert: Cert) -> Dict:
        return {
            'id': cert._id,
            'file_format': cert._file_format.name,
            'path': str(cert._path),
            'key_id': cert._key._id,
            'start_date': cert._start_date.isoformat(),
            'end_date': cert._end_date.isoformat(),
            'purposes': [purpose.name for purpose in cert._purposes]
        }

    def _deserialize_cert(self, cert_data: Dict) -> Cert:
        return Cert(
            id=cert_data['id'],
            file_format=FileFormat[cert_data['file_format']],
            path=Path(cert_data['path']),
            key=self.get_key_by_id(cert_data['key_id']),
            start_date=DateTime.fromisoformat(cert_data['start_date']),
            end_date=DateTime.fromisoformat(cert_data['end_date']),
            purposes=set(CertPurpose[purpose] for purpose in cert_data['purposes'])
        )

    def _serialize_entity(self, entity: Entity) -> Dict:
        return {
            'name': entity._name,
            'can_sign': entity._can_sign,
            'min_strength': entity._min_strength,
            'key_ids': [key._id for key in entity.get_keys()],
            'cert_ids': [cert._id for cert in entity.get_certs()],
            'parent_id': entity._parent_id if hasattr(entity, '_parent_id') else None
        }

    def _deserialize_entity(self, entity_data: Dict) -> Entity:
        entity = Entity(
            name=entity_data['name'],
            can_sign=entity_data['can_sign'],
            min_strength=entity_data['min_strength']
        )
        entity._keys = [self.get_key_by_id(key_id) for key_id in entity_data['key_ids']]
        entity._certs = [self.get_cert_by_id(cert_id) for cert_id in entity_data['cert_ids']]
        entity._parent_id = entity_data.get('parent_id')
        return entity

    def add_key(self, key: Key):
        keys = self._dbm._get_dict(DBKey.KEYS)
        keys[key._id] = self._serialize_key(key)
        self._dbm._put_dict(DBKey.KEYS, keys)

    def get_key_by_id(self, key_id: str) -> Optional[Key]:
        keys = self._dbm._get_dict(DBKey.KEYS)
        key_data = keys.get(key_id)
        if key_data:
            return self._deserialize_key(key_data)
        return None

    def add_cert(self, cert: Cert):
        certs = self._dbm._get_dict(DBKey.CERTS)
        certs[cert._id] = self._serialize_cert(cert)
        self._dbm._put_dict(DBKey.CERTS, certs)

    def get_cert_by_id(self, cert_id: str) -> Optional[Cert]:
        certs = self._dbm._get_dict(DBKey.CERTS)
        cert_data = certs.get(cert_id)
        if cert_data:
            return self._deserialize_cert(cert_data)
        return None
