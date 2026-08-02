

import datetime
from pathlib import Path

from cryptography import x509
from cryptography.x509.oid import NameOID
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa

from core.models import RSAIdentity

CA_DIR = Path("data/ca")
CA_PRIVATE_KEY_PATH = CA_DIR / "ca_private.pem"
CA_CERT_PATH = CA_DIR / "ca_certificate.pem"


def _generate_ca_keypair():
    
    CA_DIR.mkdir(parents=True, exist_ok=True)

    if CA_PRIVATE_KEY_PATH.exists():
        private_key = serialization.load_pem_private_key(
            CA_PRIVATE_KEY_PATH.read_bytes(),
            password=None,
        )
    else:
        private_key = rsa.generate_private_key(public_exponent=65537, key_size=4096)
        CA_PRIVATE_KEY_PATH.write_bytes(
            private_key.private_bytes(
                encoding=serialization.Encoding.PEM,
                format=serialization.PrivateFormat.PKCS8,
                encryption_algorithm=serialization.NoEncryption(),
            )
        )

    return private_key


def _get_or_create_ca_certificate(ca_private_key):
  
    if CA_CERT_PATH.exists():
        return x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())

    subject = issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MTC-Simulator Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ENSI stage d'été Simulation"),
    ])

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(ca_private_key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=3650)
        )
        .add_extension(x509.BasicConstraints(ca=True, path_length=None), critical=True)
        .sign(ca_private_key, hashes.SHA256())
    )

    CA_CERT_PATH.write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    return cert


def sign_certificate_for_site(domain: str, site_public_key_pem: bytes) -> RSAIdentity:
    
    ca_private_key = _generate_ca_keypair()
    _get_or_create_ca_certificate(ca_private_key)

    site_public_key = serialization.load_pem_public_key(site_public_key_pem)

    subject = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, domain),
    ])
    issuer = x509.Name([
        x509.NameAttribute(NameOID.COMMON_NAME, "MTC-Simulator Root CA"),
        x509.NameAttribute(NameOID.ORGANIZATION_NAME, "ENSI stage d'été Simulation"),
    ])

    serial = x509.random_serial_number()

    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(issuer)
        .public_key(site_public_key)
        .serial_number(serial)
        .not_valid_before(datetime.datetime.now(datetime.timezone.utc))
        .not_valid_after(
            datetime.datetime.now(datetime.timezone.utc) + datetime.timedelta(days=365)
        )
        .add_extension(
            x509.SubjectAlternativeName([x509.DNSName(domain)]),
            critical=False,
        )
        .sign(ca_private_key, hashes.SHA256())
    )

    cert_pem = cert.public_bytes(serialization.Encoding.PEM)

    certs_dir = Path("data/certs")
    certs_dir.mkdir(parents=True, exist_ok=True)
    (certs_dir / f"{domain}_cert.pem").write_bytes(cert_pem)

    return RSAIdentity(
        private_key_pem=b"",
        public_key_pem=site_public_key_pem,
        certificate_pem=cert_pem,
        serial_number=serial,
    )