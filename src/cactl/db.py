from pathlib import Path
from typing import List, Tuple

from .crypto import Key, Cert, CertPurpose


class Entity:
    def __init__(self, name: str, can_sign: bool, min_strength: int):
        self._name = name
        self._can_sign = can_sign
        self._min_strength = min_strength

    def can_sign(self) -> bool:
        return self._can_sign

    def get_keys(self) -> List[Key]:
        raise NotImplementedError()
    
    def get_certs(self) -> List[Cert]:
        raise NotImplementedError()

    def certs_for_purpose(self, cert_purpose: CertPurpose) -> List[Cert]:
        raise NotImplementedError()


class EntityChain:
    def __init__(self, entities: List[Entity]):
        self._entities = entities
    
    def entity_certs_for_purpose(self, cert_purpose: CertPurpose) -> List[Tuple[Entity, Cert]]:
        raise NotImplementedError()


class DB:
    def __init__(self, db_dir_path: Path):
        self._path = db_dir_path

    def get_CAs(self) -> List[str]:
        return []

    def get_intermediate_CAs(self) -> List[str]:
        return []

    def get_servers(self) -> List[str]:
        return []

    def get_clients(self) -> List[str]:
        return []

    def get_entities(self) -> List[str]:
        return (
            self.get_CAs()
            + self.get_intermediate_CAs()
            + self.get_servers()
            + self.get_clients()
        )

    def get_entity_chain(self, entity_name: str) -> List[Entity]:
        raise NotImplementedError()

    def get_default_signing_ca(self) -> Entity:
        raise NotImplementedError()

    def get_entity_by_name(self, entity_name: str) -> Entity:
        return Entity(entity_name)
