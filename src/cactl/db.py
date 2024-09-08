import json
import logging
from pathlib import Path
from typing import List, Optional, Dict
from datetime import datetime

from pydantic import BaseModel, Field

from .crypto import CertPurpose, FileFormat

logger = logging.getLogger(__name__)

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
    CURRENT_VERSION = "1.0"

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
            self._validate_version()
            logger.info(f"Loaded database from {self._db_file}")
        else:
            self._data = {
                "version": self.CURRENT_VERSION,
                "root_cas": [],
                "intermediate_cas": [],
                "servers": [],
                "clients": [],
                "emails": [],
                "entities": {},
                "keys": {},
                "certs": {},
            }
            self._save_db()
            logger.info(f"Initialized new database at {self._db_file}")

    def _validate_version(self):
        db_version = self._data.get("version")
        if db_version != self.CURRENT_VERSION:
            raise ValueError(f"Unsupported database version: {db_version}. Expected: {self.CURRENT_VERSION}")

    def _save_db(self):
        with open(self._db_file, "w") as f:
            json.dump(self._data, f, indent=2, default=str)

    def get_CAs(self) -> List[str]:
        return self._data["root_cas"]

    def get_intermediate_CAs(self) -> List[str]:
        return self._data["intermediate_cas"]

    def get_servers(self) -> List[str]:
        return self._data["servers"]

    def get_clients(self) -> List[str]:
        return self._data["clients"]

    def get_emails(self) -> List[str]:
        return self._data["emails"]

    def get_entities(self) -> List[str]:
        return (
            self.get_CAs()
            + self.get_intermediate_CAs()
            + self.get_servers()
            + self.get_clients()
            + self.get_emails()
        )

    def get_entity_certificate_chain(self, end_entity_id: str) -> List[Cert]:
        entities = self._data["entities"]
        chain = []
        current_entity_id = end_entity_id

        while current_entity_id:
            entity_data = entities.get(current_entity_id)
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
        entity_data = self._data["entities"].get(entity_id)
        if entity_data:
            return Entity.parse_obj(entity_data)
        return None

    def add_entity(self, entity: Entity, entity_type: str):
        entity_id = entity.name
        self._data["entities"][entity_id] = entity.dict()
        self._data[entity_type].append(entity_id)
        self._save_db()

    def add_CA(self, ca: Entity):
        self.add_entity(ca, "root_cas")

    def add_intermediate_CA(self, ca: Entity):
        self.add_entity(ca, "intermediate_cas")

    def add_server(self, server: Entity):
        self.add_entity(server, "servers")

    def add_client(self, client: Entity):
        self.add_entity(client, "clients")

    def add_email(self, email: Entity):
        self.add_entity(email, "emails")

    def add_key(self, key: Key):
        self._data["keys"][key.id] = key.dict()
        self._save_db()

    def get_key_by_id(self, key_id: str) -> Optional[Key]:
        key_data = self._data["keys"].get(key_id)
        if key_data:
            return Key.parse_obj(key_data)
        return None

    def add_cert(self, cert: Cert):
        self._data["certs"][cert.id] = cert.dict()
        self._save_db()

    def get_cert_by_id(self, cert_id: str) -> Optional[Cert]:
        cert_data = self._data["certs"].get(cert_id)
        if cert_data:
            return Cert.parse_obj(cert_data)
        return None
