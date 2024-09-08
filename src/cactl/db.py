import json
import logging
from pathlib import Path
from typing import List, Optional, Dict, Set
from datetime import datetime, timedelta

from pydantic import BaseModel, Field

from .crypto import CertPurpose, FileFormat, Key, Cert, CertRequest, Revocation
from .backend import Backend

logger = logging.getLogger(__name__)

class Entity(BaseModel):
    name: str
    can_sign: bool
    min_strength: int
    keys: List[Key] = Field(default_factory=list)
    certs: List[Cert] = Field(default_factory=list)
    cert_requests: List[CertRequest] = Field(default_factory=list)
    revocations: List[Revocation] = Field(default_factory=list)
    parent_id: Optional[str] = None

class DB:
    CURRENT_VERSION = "1.2"

    def __init__(self, db_dir_path: Path, backend: Backend):
        self._path = db_dir_path
        self._path.mkdir(parents=True, exist_ok=True)
        self._db_file = self._path / "db.json"
        self._data: Dict = {}
        self._backend = backend
        self._load_or_create_db()

    def _load_or_create_db(self):
        if self._db_file.exists():
            with open(self._db_file, "r") as f:
                self._data = json.load(f)
            self._validate_version()
            self._convert_ids_to_objects()
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
                "cert_requests": {},
                "revocations": {},
            }
            self._save_db()
            logger.info(f"Initialized new database at {self._db_file}")

    def _validate_version(self):
        db_version = self._data.get("version")
        if db_version != self.CURRENT_VERSION:
            raise ValueError(f"Unsupported database version: {db_version}. Expected: {self.CURRENT_VERSION}")

    def _convert_ids_to_objects(self):
        for entity_data in self._data["entities"].values():
            entity_data["keys"] = [self._data["keys"][key_id] for key_id in entity_data["key_ids"]]
            entity_data["certs"] = [self._data["certs"][cert_id] for cert_id in entity_data["cert_ids"]]
            entity_data["cert_requests"] = [self._data["cert_requests"][req_id] for req_id in entity_data.get("cert_request_ids", [])]
            entity_data["revocations"] = [self._data["revocations"][rev_id] for rev_id in entity_data.get("revocation_ids", [])]
            del entity_data["key_ids"]
            del entity_data["cert_ids"]
            if "cert_request_ids" in entity_data:
                del entity_data["cert_request_ids"]
            if "revocation_ids" in entity_data:
                del entity_data["revocation_ids"]

    def _save_db(self):
        save_data = self._data.copy()
        for entity_data in save_data["entities"].values():
            entity_data["key_ids"] = [key.id for key in entity_data["keys"]]
            entity_data["cert_ids"] = [cert.id for cert in entity_data["certs"]]
            entity_data["cert_request_ids"] = [req.id for req in entity_data["cert_requests"]]
            entity_data["revocation_ids"] = [rev.id for rev in entity_data["revocations"]]
            del entity_data["keys"]
            del entity_data["certs"]
            del entity_data["cert_requests"]
            del entity_data["revocations"]
        with open(self._db_file, "w") as f:
            json.dump(save_data, f, indent=2, default=str)

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

    def get_entity_certificate_chain(self, end_entity_id: str, purposes: Optional[Set[CertPurpose]] = None) -> List[Cert]:
        entities = self._data["entities"]
        chain = []
        current_entity_id = end_entity_id

        while current_entity_id:
            entity_data = entities.get(current_entity_id)
            if not entity_data:
                break

            entity = Entity.parse_obj(entity_data)
            cert = self._get_or_create_cert(entity, purposes)
            if cert:
                chain.append(cert)

            if entity.can_sign:
                current_entity_id = entity.parent_id
            else:
                break

        return list(reversed(chain))

    def _get_or_create_cert(self, entity: Entity, purposes: Optional[Set[CertPurpose]]) -> Optional[Cert]:
        if purposes:
            existing_cert = next((cert for cert in entity.certs if purposes.issubset(cert.purposes)), None)
            if existing_cert:
                return existing_cert

        # Create a new certificate if it doesn't exist
        key = entity.keys[0] if entity.keys else self._create_key(entity)
        cert_request = self._create_cert_request(entity, key, purposes)
        signing_ca = self.get_default_signing_ca() if not entity.can_sign else entity
        cert = self._backend.sign_request(cert_request, signing_ca.keys[0])
        self.add_cert(cert, entity.name)
        return cert

    def _create_key(self, entity: Entity) -> Key:
        key = self._backend.gen_key(entity.min_strength)
        self.add_key(key, entity.name)
        return key

    def _create_cert_request(self, entity: Entity, key: Key, purposes: Optional[Set[CertPurpose]]) -> CertRequest:
        if not purposes:
            purposes = {CertPurpose.ROOT_CA} if entity.can_sign else {CertPurpose.WEB_SERVER}
        
        start_date = datetime.utcnow()
        end_date = start_date + timedelta(days=365)  # Default to 1 year validity
        
        cert_request = CertRequest(
            id=self._backend._generate_id(),
            purposes=purposes,
            start_date=start_date,
            end_date=end_date,
            file_format=key.file_format,
            path=key.path.with_suffix(".csr")
        )
        self.add_cert_request(cert_request, entity.name)
        return cert_request

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

    def add_key(self, key: Key, entity_id: str):
        self._data["keys"][key.id] = key.dict()
        entity = self.get_entity_by_id(entity_id)
        if entity:
            entity.keys.append(key)
            self._data["entities"][entity_id] = entity.dict()
        self._save_db()

    def get_key_by_id(self, key_id: str) -> Optional[Key]:
        key_data = self._data["keys"].get(key_id)
        if key_data:
            return Key.parse_obj(key_data)
        return None

    def add_cert(self, cert: Cert, entity_id: str):
        self._data["certs"][cert.id] = cert.dict()
        entity = self.get_entity_by_id(entity_id)
        if entity:
            entity.certs.append(cert)
            self._data["entities"][entity_id] = entity.dict()
        self._save_db()

    def get_cert_by_id(self, cert_id: str) -> Optional[Cert]:
        cert_data = self._data["certs"].get(cert_id)
        if cert_data:
            return Cert.parse_obj(cert_data)
        return None

    def add_cert_request(self, cert_request: CertRequest, entity_id: str):
        self._data["cert_requests"][cert_request.id] = cert_request.dict()
        entity = self.get_entity_by_id(entity_id)
        if entity:
            entity.cert_requests.append(cert_request)
            self._data["entities"][entity_id] = entity.dict()
        self._save_db()

    def get_cert_request_by_id(self, cert_request_id: str) -> Optional[CertRequest]:
        cert_request_data = self._data["cert_requests"].get(cert_request_id)
        if cert_request_data:
            return CertRequest.parse_obj(cert_request_data)
        return None

    def add_revocation(self, revocation: Revocation, entity_id: str):
        self._data["revocations"][revocation.id] = revocation.dict()
        entity = self.get_entity_by_id(entity_id)
        if entity:
            entity.revocations.append(revocation)
            self._data["entities"][entity_id] = entity.dict()
        self._save_db()

    def get_revocation_by_id(self, revocation_id: str) -> Optional[Revocation]:
        revocation_data = self._data["revocations"].get(revocation_id)
        if revocation_data:
            return Revocation.parse_obj(revocation_data)
        return None
