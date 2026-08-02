
import hashlib

from cryptography import x509
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import hashes
from cryptography.exceptions import InvalidSignature

from core.server import TLSBundle
from core.merkle_tree import hash_log_entry
from core.tree_head import verify_tree_head, MTCA_PUBLIC_KEY_PATH
from pathlib import Path

CA_CERT_PATH = Path("data/ca/ca_certificate.pem")

def verify_rsa_certificate(cert_pem: bytes) -> bool:
    """
    Étape A : vérifie que le certificat RSA du site a bien été signé
    par notre CA (chaîne de confiance classique).
    """
    try:
        site_cert = x509.load_pem_x509_certificate(cert_pem)
        ca_cert = x509.load_pem_x509_certificate(CA_CERT_PATH.read_bytes())
        ca_public_key = ca_cert.public_key()

        ca_public_key.verify(
            site_cert.signature,
            site_cert.tbs_certificate_bytes,
            padding.PKCS1v15(),
            site_cert.signature_hash_algorithm,
        )
        return True
    except InvalidSignature:
        return False
    except Exception:
        return False


def verify_mldsa_key_matches_log_entry(mldsa_public_key_pem: bytes, log_entry) -> bool:
    
    recalculated_hash = hashlib.sha256(mldsa_public_key_pem).digest()
    return recalculated_hash == log_entry.subject_public_key_info_hash


def verify_full_handshake(bundle: TLSBundle) -> dict:
    
    report = {"domain": bundle.domain, "steps": [], "success": False}

    def log_step(name: str, ok: bool):
        report["steps"].append({"name": name, "ok": ok})

    
    rsa_ok = verify_rsa_certificate(bundle.rsa_certificate_pem)
    log_step("Certificat RSA signe par la CA", rsa_ok)
    if not rsa_ok:
        return report

   
    key_match_ok = verify_mldsa_key_matches_log_entry(bundle.mldsa_public_key_pem, bundle.log_entry)
    log_step("Cle ML-DSA correspond au hash declare", key_match_ok)
    if not key_match_ok:
        return report

    recalculated_leaf_hash = hash_log_entry(bundle.log_entry)
    leaf_matches_proof = recalculated_leaf_hash == bundle.inclusion_proof.leaf_hash
    log_step("Feuille recalculee correspond a la preuve", leaf_matches_proof)
    if not leaf_matches_proof:
        return report

  
    current_hash = recalculated_leaf_hash
    for sibling_hash, position in bundle.inclusion_proof.sibling_hashes:
        if position == "RIGHT":
            combined = current_hash + sibling_hash
        else:
            combined = sibling_hash + current_hash
        current_hash = hashlib.sha256(combined).digest()


    root_matches = current_hash == bundle.tree_head.root_hash
    log_step("Racine recalculee correspond au Tree Head", root_matches)
    if not root_matches:
        return report

 
    signature_ok = verify_tree_head(bundle.tree_head)
    log_step("Signature ML-DSA du Tree Head valide", signature_ok)
    if not signature_ok:
        return report

    report["success"] = True
    return report

def print_verification_report(report: dict) -> None:
    """Affiche le rapport de vérification de façon lisible, étape par étape."""
    print(f"\n=== Verification du site : {report['domain']} ===")
    for step in report["steps"]:
        symbol = "OK " if step["ok"] else "FAIL"
        print(f"  [{symbol}] {step['name']}")

    if report["success"]:
        print("=> ACCES AUTORISE : le site est authentifie avec succes.\n")
    else:
        print("=> ACCES REFUSE : la verification a echoue.\n")