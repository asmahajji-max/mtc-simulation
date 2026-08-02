
from dataclasses import dataclass

from core.models import Site, TreeHead, InclusionProof, TBSCertificateLogEntry

@dataclass
class TLSBundle:
    domain: str
    rsa_certificate_pem: bytes
    mldsa_public_key_pem: bytes
    log_entry: TBSCertificateLogEntry  
    inclusion_proof: InclusionProof
    tree_head: TreeHead  

def get_tls_bundle(site: Site, inclusion_proof: InclusionProof, tree_head: TreeHead) -> TLSBundle:
    if site.rsa_identity is None or not site.rsa_identity.certificate_pem:
        raise ValueError(f"Le site '{site.domain}' n'a pas de certificat RSA valide.")
    if site.mldsa_identity is None:
        raise ValueError(f"Le site '{site.domain}' n'a pas de clé ML-DSA.")
    if site.log_entry is None:
        raise ValueError(f"Le site '{site.domain}' n'a pas de TBSCertificateLogEntry.")

    return TLSBundle(
        domain=site.domain,
        rsa_certificate_pem=site.rsa_identity.certificate_pem,
        mldsa_public_key_pem=site.mldsa_identity.public_key_pem,
        log_entry=site.log_entry,
        inclusion_proof=inclusion_proof,
        tree_head=tree_head,
    )