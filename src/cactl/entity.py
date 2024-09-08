from typing import List, Tuple, Optional
from .crypto import Key, Cert, CertPurpose


EntityID = str


class Entity:
    def __init__(self, name: str, can_sign: bool, min_strength: int):
        self._name = name
        self._can_sign = can_sign
        self._min_strength = min_strength
        self._keys: List[Key] = []
        self._certs: List[Cert] = []
        self._parent_id: Optional[EntityID] = None

    def can_sign(self) -> bool:
        return self._can_sign

    def get_keys(self) -> List[Key]:
        return self._keys

    def get_certs(self) -> List[Cert]:
        return self._certs

    def certs_for_purpose(self, cert_purpose: CertPurpose) -> List[Cert]:
        return [cert for cert in self._certs if cert_purpose in cert._purposes]

    def add_key(self, key: Key):
        self._keys.append(key)

    def add_cert(self, cert: Cert):
        self._certs.append(cert)

    def set_parent_id(self, parent_id: EntityID):
        self._parent_id = parent_id


class EntityChain:
    def __init__(self, entities: List[Entity]):
        self._entities = entities
    
    def entity_certs_for_purpose(self, cert_purpose: CertPurpose) -> List[Tuple[Entity, Cert]]:
        result = []
        for entity in self._entities:
            certs = entity.certs_for_purpose(cert_purpose)
            result.extend([(entity, cert) for cert in certs])
        return result
