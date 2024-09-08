import json
import logging
from enum import Enum
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime

from pydantic import BaseModel, Field

from .crypto import CertPurpose, FileFormat

logger = logging.getLogger(__name__)

class DBKey(str, Enum):
    DB_VERSION = "db_version"
    ROOT_CAS = "root_cas"
    INTERMEDIATE_CAS = "intermediate_cas"
    SERVERS = "servers"
    CLIENTS = "clients"
    EMAILS = "emails"
    ENTITY_TUPLES = "entity_tuples"
    KEYS = "keys"
    CERTS = "certs"

class Key(BaseModel):
    id: str
    path: Optional[Path]
    file_format: FileFormat
    length: int

class Cert(BaseModel):
    id: str
    file_format: FileFormat
    path: Path
    key_id: str
    start_date: datetime
    end_date: datetime
    purposes: List[CertPurpose]

class Entity(BaseModel):
    name: str
    can_sign: bool
    min_strength: int
    key_ids: List[str] = Field(default_factory=list)
    cert_ids: List[str] = Field(default_factory=list)
    parent_id: Optional[str] = None

class DB:
    def __init__(self, db_dir_path: Path):
        self._path = db_dir_path
        self._path.mkdir(parents=True, exist_ok=True)
        self._db_file = self._path / "db.json"
        self._data: Dict = {}
        self._load_or_create_db()

    def _load_or_create_db(self):
        if self._db_file.exists():
            with open(self._db_file, "r") as f:
                self._data = json.load(f)
            logger.info(f"Loaded database from {self._db_file}")
        else:
            self._data = {
                DBKey.DB_VERSION: "1.0",
                DBKey.ROOT_CAS: [],
                DBKey.INTERMEDIATE_CAS: [],
                DBKey.SERVERS: [],
                DBKey.CLIENTS: [],
                DBKey.EMAILS: [],
                DBKey.ENTITY_TUPLES: {},
                DBKey.KEYS: {},
                DBKey.CERTS: {},
            }
            self._save_db()
            logger.info(f"Initialized new database at {self._db_file}")

    def _save_db(self):
        with open(self._db_file, "w") as f:
            json.dump(self._data, f, indent=2, default=str)

    def get_CAs(self) -> List[str]:
        return self._data[DBKey.ROOT_CAS]

    def get_intermediate_CAs(self) -> List[str]:
        return self._data[DBKey.INTERMEDIATE_CAS]

    def get_servers(self) -> List[str]:
        return self._data[DBKey.SERVERS]

    def get_clients(self) -> List[str]:
        return self._data[DBKey.CLIENTS]

    def get_emails(self) -> List[str]:
        return self._data[DBKey.EMAILS]

    def get_entities(self) -> List[str]:
        return (
            self.get_CAs()
            + self.get_intermediate_CAs()
            + self.get_servers()
            + self.get_clients()
            + self.get_emails()
        )

    def get_entity_certificate_chain(self, end_entity_id: str) -> List[Cert]:
        entity_tuples = self._data[DBKey.ENTITY_TUPLES]
        chain = []
        current_entity_id = end_entity_id

        while current_entity_id:
            entity_data = entity_tuples.get(current_entity_id)
            if not entity_data:
                break

            entity = Entity.parse_obj(entity_data)
            cert = self.get_cert_by_id(entity.cert_ids[0])  # Assuming the first cert is the main one
            if cert:
                chain.append(cert)

            if entity.can_sign:
                current_entity_id = entity.parent_id
            else:
                break

        return list(reversed(chain))

    def get_default_signing_ca(self) -> Optional[Entity]:
        cas = self.get_CAs()
        if cas:
            return self.get_entity_by_id(cas[0])
        return None

    def get_entity_by_id(self, entity_id: str) -> Optional[Entity]:
        entity_data = self._data[DBKey.ENTITY_TUPLES].get(entity_id)
        if entity_data:
            return Entity.parse_obj(entity_data)
        return None

    def add_entity(self, entity: Entity, entity_type: DBKey):
        entity_id = entity.name
        self._data[DBKey.ENTITY_TUPLES][entity_id] = entity.dict()
        self._data[entity_type].append(entity_id)
        self._save_db()

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

    def add_key(self, key: Key):
        self._data[DBKey.KEYS][key.id] = key.dict()
        self._save_db()

    def get_key_by_id(self, key_id: str) -> Optional[Key]:
        key_data = self._data[DBKey.KEYS].get(key_id)
        if key_data:
            return Key.parse_obj(key_data)
        return None

    def add_cert(self, cert: Cert):
        self._data[DBKey.CERTS][cert.id] = cert.dict()
        self._save_db()

    def get_cert_by_id(self, cert_id: str) -> Optional[Cert]:
        cert_data = self._data[DBKey.CERTS].get(cert_id)
        if cert_data:
            return Cert.parse_obj(cert_data)
        return None
