

import hashlib
import datetime

from core.models import Site, TBSCertificateLogEntry

MTCA_ISSUER_NAME = "MTCA-Simulator-Root"


def create_log_entry(site: Site, validity_days: int = 365) -> TBSCertificateLogEntry:
    
    if site.mldsa_identity is None:
        raise ValueError(
            f"Le site '{site.domain}' n'a pas encore de clé ML-DSA. "
            "Génère-la d'abord avec generate_mldsa_keypair()."
        )

    public_key_hash = hashlib.sha256(site.mldsa_identity.public_key_pem).digest()

    now = datetime.datetime.now(datetime.timezone.utc)

    return TBSCertificateLogEntry(
        version=1,
        issuer=MTCA_ISSUER_NAME,
        subject=site.domain,
        not_before=now,
        not_after=now + datetime.timedelta(days=validity_days),
        subject_public_key_info_hash=public_key_hash,
        extensions={},
    )