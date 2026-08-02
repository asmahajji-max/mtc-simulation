"""
core/models.py

Ce module définit les structures de données (dataclasses) utilisées dans
toute la simulation de l'architecture Merkle Tree Certificates (MTC).

Chaque classe correspond à un concept précis du protocole, tel que défini
dans le draft IETF "Merkle Tree Certificates"
(draft-ietf-plants-merkle-tree-certs).
"""

from dataclasses import dataclass, field
from datetime import datetime
from typing import Optional, List


@dataclass
class RSAIdentity:
    """Identité RSA classique d'un site : clés + certificat X.509."""
    private_key_pem: bytes
    public_key_pem: bytes
    certificate_pem: bytes
    serial_number: int


@dataclass
class MLDSAIdentity:
    """Identité post-quantique ML-DSA d'un site (pas de certificat X.509)."""
    private_key_pem: bytes
    public_key_pem: bytes
    algorithm: str = "ML-DSA-65"


@dataclass
class TBSCertificateLogEntry:
    """Structure officielle spec MTC, devient une feuille du Merkle Tree."""
    version: int
    issuer: str
    subject: str
    not_before: datetime
    not_after: datetime
    subject_public_key_info_hash: bytes
    extensions: dict = field(default_factory=dict)


@dataclass
class MerkleNode:
    """Nœud de l'arbre de Merkle (feuille ou intermédiaire)."""
    hash_value: bytes
    is_leaf: bool
    left: Optional["MerkleNode"] = None
    right: Optional["MerkleNode"] = None
    site_id: Optional[str] = None


@dataclass
class TreeHead:
    """Racine du Merkle Tree signée par la MTCA."""
    root_hash: bytes
    tree_size: int
    timestamp: datetime
    signature: bytes
    signer_id: str = "MTCA-Simulator-Root"


@dataclass
class InclusionProof:
    """
    Représente la preuve qu'une feuille donnée (un site) appartient bien
    à l'arbre dont la racine est certifiée par un TreeHead donné.

    sibling_hashes contient des paires (hash, position) : la position
    ("LEFT" ou "RIGHT") indique de quel côté ce voisin doit être combiné
    lors de la reconstruction du chemin vers la racine.
    """
    leaf_index: int
    leaf_hash: bytes
    sibling_hashes: List[tuple] = field(default_factory=list)  # [(bytes, str), ...]
    tree_size: int = 0


@dataclass
class Site:
    """Objet racine représentant un site web dans la simulation."""
    domain: str
    rsa_identity: Optional[RSAIdentity] = None
    mldsa_identity: Optional[MLDSAIdentity] = None
    log_entry: Optional[TBSCertificateLogEntry] = None
    inclusion_proof: Optional[InclusionProof] = None