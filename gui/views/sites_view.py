
from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QListWidget, QPushButton, QInputDialog, QMessageBox
)

from core.models import Site, RSAIdentity
from core.keys import generate_rsa_keypair, generate_mldsa_keypair
from core.rsa_ca import sign_certificate_for_site
from core.mtca import create_log_entry
from core.registry import load_sites, add_site


class SitesView(QWidget):
    

    def __init__(self, on_sites_changed=None, parent=None):
        super().__init__(parent)
        self.on_sites_changed = on_sites_changed

        layout = QVBoxLayout()

        self.site_list = QListWidget()
        layout.addWidget(self.site_list)

        self.add_button = QPushButton("+ Ajouter un site")
        self.add_button.clicked.connect(self._on_add_site_clicked)
        layout.addWidget(self.add_button)

        self.setLayout(layout)

        self.refresh()

    def refresh(self) -> None:
        
        self.site_list.clear()
        sites = load_sites()

        if not sites:
            self.site_list.addItem("Aucun site enregistre pour l'instant.")
            return

        for site in sites:
            has_rsa = "OUI" if site.rsa_identity and site.rsa_identity.certificate_pem else "NON"
            has_mldsa = "OUI" if site.mldsa_identity else "NON"
            has_log_entry = "OUI" if site.log_entry else "NON"
            label = f"{site.domain}   [RSA: {has_rsa}]  [ML-DSA: {has_mldsa}]  [Log Entry: {has_log_entry}]"
            self.site_list.addItem(label)

    def _on_add_site_clicked(self) -> None:
        
        domain, ok = QInputDialog.getText(
            self, "Ajouter un site", "Nom de domaine (ex: site11.example.com) :"
        )

        if not ok or not domain.strip():
            return  # annule ou champ vide

        domain = domain.strip()

        try:
            rsa_keys = generate_rsa_keypair(domain)
            signed_identity = sign_certificate_for_site(domain, rsa_keys.public_key_pem)

            complete_rsa_identity = RSAIdentity(
                private_key_pem=rsa_keys.private_key_pem,
                public_key_pem=rsa_keys.public_key_pem,
                certificate_pem=signed_identity.certificate_pem,
                serial_number=signed_identity.serial_number,
            )

            mldsa_keys = generate_mldsa_keypair(domain)

            site = Site(domain=domain)
            site.rsa_identity = complete_rsa_identity
            site.mldsa_identity = mldsa_keys
            site.log_entry = create_log_entry(site)

            add_site(site)

            QMessageBox.information(
                self, "Site cree",
                f"Le site '{domain}' a ete cree avec succes\n"
                f"(certificat RSA signe + log entry MTC)."
            )

            self.refresh()

            if self.on_sites_changed:
                self.on_sites_changed()

        except ValueError as e:
            QMessageBox.warning(self, "Erreur", str(e))
        except RuntimeError as e:
            QMessageBox.critical(self, "Erreur OpenSSL", str(e))