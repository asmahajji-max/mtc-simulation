

from core.models import Site, RSAIdentity
from core.keys import generate_rsa_keypair, generate_mldsa_keypair
from core.rsa_ca import sign_certificate_for_site
from core.mtca import create_log_entry
from core.registry import load_sites, add_site


def list_sites():
    sites = load_sites()
    if not sites:
        print("\nAucun site enregistré pour l'instant.\n")
        return

    print(f"\n{len(sites)} site(s) enregistré(s) :")
    for i, site in enumerate(sites, start=1):
        has_rsa = "OUI" if site.rsa_identity and site.rsa_identity.certificate_pem else "NON"
        has_mldsa = "OUI" if site.mldsa_identity else "NON"
        has_log_entry = "OUI" if site.log_entry else "NON"
        print(f"  {i}. {site.domain}  [Certificat RSA: {has_rsa}]  [ML-DSA: {has_mldsa}]  [Log Entry MTC: {has_log_entry}]")
    print()


def create_new_site():
    domain = input("\nNom de domaine du nouveau site (ex: site11.example.com) : ").strip()

    if not domain:
        print("Domaine vide, annulation.\n")
        return

    try:
        print(f"[+] Le site genere sa paire de cles RSA...")
        rsa_keys = generate_rsa_keypair(domain)

        print(f"[+] La CA signe le certificat X.509 pour {domain}...")
        signed_identity = sign_certificate_for_site(domain, rsa_keys.public_key_pem)

        complete_rsa_identity = RSAIdentity(
            private_key_pem=rsa_keys.private_key_pem,
            public_key_pem=rsa_keys.public_key_pem,
            certificate_pem=signed_identity.certificate_pem,
            serial_number=signed_identity.serial_number,
        )

        print(f"[+] Le site genere sa paire de cles ML-DSA...")
        mldsa_keys = generate_mldsa_keypair(domain)

        site = Site(domain=domain)
        site.rsa_identity = complete_rsa_identity
        site.mldsa_identity = mldsa_keys

        print(f"[+] La MTCA cree la TBSCertificateLogEntry pour {domain}...")
        site.log_entry = create_log_entry(site)

        all_sites = add_site(site)
        print(f"Site '{domain}' cree avec certificat signe et log entry MTC. Total : {len(all_sites)} site(s).\n")

    except ValueError as e:
        print(f"Erreur : {e}\n")
    except RuntimeError as e:
        print(f"Erreur OpenSSL : {e}\n")


def main_menu():
    while True:
        print("=== Simulateur MTC ===")
        print("1. Lister les sites existants")
        print("2. Ajouter un nouveau site")
        print("3. Quitter")

        choice = input("\nChoix : ").strip()

        if choice == "1":
            list_sites()
        elif choice == "2":
            create_new_site()
        elif choice == "3":
            print("Au revoir.")
            break
        else:
            print("Choix invalide, reessaie.\n")


if __name__ == "__main__":
    main_menu()