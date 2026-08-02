

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QHBoxLayout, QComboBox, QPushButton,
    QTextEdit, QLabel
)
from PySide6.QtGui import QColor

from core.registry import load_sites
from core.merkle_tree import create_all_leaves, build_merkle_tree, generate_inclusion_proof
from core.tree_head import create_tree_head
from core.server import get_tls_bundle
from core.client import verify_full_handshake


class VerificationView(QWidget):
   

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout()

        selector_layout = QHBoxLayout()
        selector_layout.addWidget(QLabel("Site a verifier :"))
        self.site_selector = QComboBox()
        selector_layout.addWidget(self.site_selector)

        self.refresh_button = QPushButton("Rafraichir la liste")
        self.refresh_button.clicked.connect(self.refresh)
        selector_layout.addWidget(self.refresh_button)

        self.simulate_button = QPushButton("Simuler le handshake")
        self.simulate_button.clicked.connect(self._on_simulate_clicked)
        selector_layout.addWidget(self.simulate_button)

        layout.addLayout(selector_layout)

        self.report_display = QTextEdit()
        self.report_display.setReadOnly(True)
        self.report_display.setStyleSheet("font-family: Consolas, monospace; font-size: 13px;")
        layout.addWidget(self.report_display)

        self.setLayout(layout)

        self.refresh()

    def refresh(self) -> None:
       
        self.site_selector.clear()
        sites = load_sites()
        for site in sites:
            self.site_selector.addItem(site.domain)

    def _on_simulate_clicked(self) -> None:
        
        domain = self.site_selector.currentText()
        if not domain:
            self.report_display.setText("Aucun site selectionne.")
            return

        sites = load_sites()
        target_site = next((s for s in sites if s.domain == domain), None)
        if target_site is None:
            self.report_display.setText(f"Site '{domain}' introuvable.")
            return

        leaves = create_all_leaves(sites)
        root = build_merkle_tree(leaves)
        tree_head = create_tree_head(root, len(leaves))
        proof = generate_inclusion_proof(root, domain, len(leaves))
        bundle = get_tls_bundle(target_site, proof, tree_head)

        report = verify_full_handshake(bundle)
        self._display_report(report)

    def _display_report(self, report: dict) -> None:
        """Affiche le rapport avec un code couleur simple (HTML basique)."""
        lines = [f"<b>=== Verification du site : {report['domain']} ===</b><br>"]

        for step in report["steps"]:
            if step["ok"]:
                lines.append(f'<span style="color:#66bb6a;">[OK]</span> {step["name"]}<br>')
            else:
                lines.append(f'<span style="color:#ef5350;">[FAIL]</span> {step["name"]}<br>')

        lines.append("<br>")
        if report["success"]:
            lines.append('<b style="color:#66bb6a;">ACCES AUTORISE : le site est authentifie avec succes.</b>')
        else:
            lines.append('<b style="color:#ef5350;">ACCES REFUSE : la verification a echoue.</b>')

        self.report_display.setHtml("".join(lines))