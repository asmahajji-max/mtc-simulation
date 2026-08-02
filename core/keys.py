import subprocess
from pathlib import Path

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core.models import RSAIdentity, MLDSAIdentity

KEYS_DIR = Path("data/keys")


def generate_rsa_keypair(site_domain: str, key_size: int = 2048) -> RSAIdentity:
    
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=key_size,
    )
    public_key = private_key.public_key()

    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption(),
    )
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo,
    )
    
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    (KEYS_DIR / f"{site_domain}_rsa_private.pem").write_bytes(private_pem)
    (KEYS_DIR / f"{site_domain}_rsa_public.pem").write_bytes(public_pem)

    return RSAIdentity(
        private_key_pem=private_pem,
        public_key_pem=public_pem,
        certificate_pem=b"",
        serial_number=0,
    )

def generate_mldsa_keypair(site_domain: str, algorithm: str = "ML-DSA-65") -> MLDSAIdentity:
    
    KEYS_DIR.mkdir(parents=True, exist_ok=True)
    private_path = KEYS_DIR / f"{site_domain}_mldsa_private.pem"
    public_path = KEYS_DIR / f"{site_domain}_mldsa_public.pem"

    result = subprocess.run(
        ["openssl", "genpkey", "-algorithm", algorithm, "-out", str(private_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Erreur OpenSSL (génération clé privée) : {result.stderr}")

    result = subprocess.run(
        ["openssl", "pkey", "-in", str(private_path), "-pubout", "-out", str(public_path)],
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        raise RuntimeError(f"Erreur OpenSSL (extraction clé publique) : {result.stderr}")

    return MLDSAIdentity(
        private_key_pem=private_path.read_bytes(),
        public_key_pem=public_path.read_bytes(),
        algorithm=algorithm,
    )