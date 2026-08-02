
import json
from pathlib import Path
from typing import List
from datetime import datetime
from core.models import Site, RSAIdentity, MLDSAIdentity, TBSCertificateLogEntry


REGISTRY_PATH = Path("data/sites_registry.json")


def _site_to_dict(site: Site) -> dict:
    
    return {
        "domain": site.domain,
        "rsa_identity": {
            "private_key_pem": site.rsa_identity.private_key_pem.decode(),
            "public_key_pem": site.rsa_identity.public_key_pem.decode(),
            "certificate_pem": site.rsa_identity.certificate_pem.decode(),
            "serial_number": site.rsa_identity.serial_number,
        } if site.rsa_identity else None,
        "mldsa_identity": {
            "private_key_pem": site.mldsa_identity.private_key_pem.decode(),
            "public_key_pem": site.mldsa_identity.public_key_pem.decode(),
            "algorithm": site.mldsa_identity.algorithm,
        } if site.mldsa_identity else None,
        "log_entry": {
            "version": site.log_entry.version,
            "issuer": site.log_entry.issuer,
            "subject": site.log_entry.subject,
            "not_before": site.log_entry.not_before.isoformat(),
            "not_after": site.log_entry.not_after.isoformat(),
            "subject_public_key_info_hash": site.log_entry.subject_public_key_info_hash.hex(),
            "extensions": site.log_entry.extensions,
            } if site.log_entry else None,
        }


def _dict_to_site(data: dict) -> Site:

    site = Site(domain=data["domain"])

    if data.get("rsa_identity"):
        r = data["rsa_identity"]
        site.rsa_identity = RSAIdentity(
            private_key_pem=r["private_key_pem"].encode(),
            public_key_pem=r["public_key_pem"].encode(),
            certificate_pem=r["certificate_pem"].encode(),
            serial_number=r["serial_number"],
        )

    if data.get("mldsa_identity"):
        m = data["mldsa_identity"]
        site.mldsa_identity = MLDSAIdentity(
            private_key_pem=m["private_key_pem"].encode(),
            public_key_pem=m["public_key_pem"].encode(),
            algorithm=m["algorithm"],
        )
    if data.get("log_entry"):
        le = data["log_entry"]
        site.log_entry = TBSCertificateLogEntry(
            version=le["version"],
            issuer=le["issuer"],
            subject=le["subject"],
            not_before=datetime.fromisoformat(le["not_before"]),
            not_after=datetime.fromisoformat(le["not_after"]),
            subject_public_key_info_hash=bytes.fromhex(le["subject_public_key_info_hash"]),
            extensions=le["extensions"],
    )

    return site


def load_sites() -> List[Site]:
   
    if not REGISTRY_PATH.exists():
        return []

    with open(REGISTRY_PATH, "r", encoding="utf-8") as f:
        data = json.load(f)

    return [_dict_to_site(entry) for entry in data]


def save_sites(sites: List[Site]) -> None:
    
    REGISTRY_PATH.parent.mkdir(parents=True, exist_ok=True)
    data = [_site_to_dict(site) for site in sites]

    with open(REGISTRY_PATH, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)


def add_site(site: Site) -> List[Site]:
    
    sites = load_sites()

    if any(s.domain == site.domain for s in sites):
        raise ValueError(f"Le site '{site.domain}' existe déjà dans le registre.")

    sites.append(site)
    save_sites(sites)
    return sites