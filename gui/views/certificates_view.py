
from cryptography.hazmat.primitives import serialization
from PySide6.QtWidgets import (
    QWidget, QHBoxLayout, QVBoxLayout, QListWidget, QTextEdit, QLabel
)
from cryptography import x509

from core.registry import load_sites


class CertificatesView(QWidget):
   
    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QHBoxLayout()

        left_layout = QVBoxLayout()
        left_layout.addWidget(QLabel("Sites :"))
        self.site_list = QListWidget()
        self.site_list.currentRowChanged.connect(self._on_site_selected)
        left_layout.addWidget(self.site_list)

        right_layout = QVBoxLayout()
        right_layout.addWidget(QLabel("Details du certificat X.509 :"))
        self.details = QTextEdit()
        self.details.setReadOnly(True)
        self.details.setStyleSheet("font-family: Consolas, monospace;")
        right_layout.addWidget(self.details)

        layout.addLayout(left_layout, 1)
        layout.addLayout(right_layout, 2)
        self.setLayout(layout)

        self._sites = []
        self.refresh()

    def refresh(self) -> None:
       
        self.site_list.clear()
        self.details.clear()
        self._sites = load_sites()

        for site in self._sites:
            self.site_list.addItem(site.domain)

    def _on_site_selected(self, row: int) -> None:
       
        if row < 0 or row >= len(self._sites):
            self.details.clear()
            return

        site = self._sites[row]

        if site.rsa_identity is None or not site.rsa_identity.certificate_pem:
            self.details.setText(f"Le site '{site.domain}' n'a pas de certificat RSA.")
            return

        cert = x509.load_pem_x509_certificate(site.rsa_identity.certificate_pem)
        public_key_pem = cert.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        ).decode()
        text = (
            f"Subject         : {cert.subject.rfc4514_string()}\n"
            f"Issuer          : {cert.issuer.rfc4514_string()}\n"
            f"Serial Number   : {cert.serial_number}\n"
            f"Valid From      : {cert.not_valid_before_utc}\n"
            f"Valid Until     : {cert.not_valid_after_utc}\n"
            f"Signature Algo  : {cert.signature_algorithm_oid._name}\n"
            f"Public Key Size : {cert.public_key().key_size} bits (RSA)\n"
            f"\nCle publique RSA (PEM) :\n{public_key_pem}"
)
        self.details.setText(text)