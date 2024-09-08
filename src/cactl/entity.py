from typing import List, Tuple
from .crypto import Cert, CertPurpose


EntityID = str


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
