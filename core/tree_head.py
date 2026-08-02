
import subprocess
import datetime
from pathlib import Path

from core.models import MerkleNode, TreeHead

MTCA_DIR = Path("data/mtca")
MTCA_PRIVATE_KEY_PATH = MTCA_DIR / "mtca_mldsa_private.pem"
MTCA_PUBLIC_KEY_PATH = MTCA_DIR / "mtca_mldsa_public.pem"

MTCA_SIGNER_ID = "MTCA-Simulator-Root"


def _get_or_create_mtca_keypair(algorithm: str = "ML-DSA-65") -> None:
    
    MTCA_DIR.mkdir(parents=True, exist_ok=True)

    if MTCA_PRIVATE_KEY_PATH.exists() and MTCA_PUBLIC_KEY_PATH.exists():
        return  

    result = subprocess.run(
        ["openssl", "genpkey", "-algorithm", algorithm, "-out", str(MTCA_PRIVATE_KEY_PATH)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Erreur OpenSSL (génération clé MTCA) : {result.stderr}")

    result = subprocess.run(
        ["openssl", "pkey", "-in", str(MTCA_PRIVATE_KEY_PATH), "-pubout", "-out", str(MTCA_PUBLIC_KEY_PATH)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Erreur OpenSSL (extraction clé publique MTCA) : {result.stderr}")


def _serialize_tree_head_message(root_hash: bytes, tree_size: int, timestamp: datetime.datetime) -> bytes:
  
    parts = [
        root_hash.hex(),
        str(tree_size),
        timestamp.isoformat(),
    ]
    return "|".join(parts).encode("utf-8")


def create_tree_head(root: MerkleNode, tree_size: int) -> TreeHead:
   
    _get_or_create_mtca_keypair()

    timestamp = datetime.datetime.now(datetime.timezone.utc)
    message = _serialize_tree_head_message(root.hash_value, tree_size, timestamp)

    message_path = MTCA_DIR / "_tmp_message.bin"
    signature_path = MTCA_DIR / "_tmp_signature.bin"
    message_path.write_bytes(message)

    result = subprocess.run(
        [
            "openssl", "pkeyutl", "-sign",
            "-inkey", str(MTCA_PRIVATE_KEY_PATH),
            "-rawin", "-in", str(message_path),
            "-out", str(signature_path),
        ],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Erreur OpenSSL (signature Tree Head) : {result.stderr}")

    signature = signature_path.read_bytes()

    
    message_path.unlink(missing_ok=True)
    signature_path.unlink(missing_ok=True)

    return TreeHead(
        root_hash=root.hash_value,
        tree_size=tree_size,
        timestamp=timestamp,
        signature=signature,
        signer_id=MTCA_SIGNER_ID,
    )


def verify_tree_head(tree_head: TreeHead) -> bool:
    
    if not MTCA_PUBLIC_KEY_PATH.exists():
        raise RuntimeError("Clé publique de la MTCA introuvable.")

    message = _serialize_tree_head_message(
        tree_head.root_hash, tree_head.tree_size, tree_head.timestamp
    )

    message_path = MTCA_DIR / "_tmp_verify_message.bin"
    signature_path = MTCA_DIR / "_tmp_verify_signature.bin"
    message_path.write_bytes(message)
    signature_path.write_bytes(tree_head.signature)

    result = subprocess.run(
        [
            "openssl", "pkeyutl", "-verify",
            "-pubin", "-inkey", str(MTCA_PUBLIC_KEY_PATH),
            "-rawin", "-in", str(message_path),
            "-sigfile", str(signature_path),
        ],
        capture_output=True,
        text=True,
    )

    message_path.unlink(missing_ok=True)
    signature_path.unlink(missing_ok=True)

    
    return result.returncode == 0