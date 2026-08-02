

import sys
from PySide6.QtWidgets import QApplication, QMainWindow, QTabWidget

from gui.views.sites_view import SitesView
from gui.views.certificates_view import CertificatesView
from gui.views.merkle_tree_view import MerkleTreeView
from gui.views.verification_view import VerificationView


class MainWindow(QMainWindow):
    """Fenetre principale du simulateur MTC."""

    def __init__(self):
        super().__init__()
        self.setWindowTitle("Simulateur MTC - Merkle Tree Certificates")
        self.resize(1100, 750)

        self.tabs = QTabWidget()
        self.setCentralWidget(self.tabs)

        self.sites_view = SitesView(on_sites_changed=self._refresh_other_tabs)
        self.certificates_view = CertificatesView()
        self.merkle_tree_view = MerkleTreeView()
        self.verification_view = VerificationView()

        self.tabs.addTab(self.sites_view, "Sites")
        self.tabs.addTab(self.certificates_view, "Certificats")
        self.tabs.addTab(self.merkle_tree_view, "Merkle Tree")
        self.tabs.addTab(self.verification_view, "Verification")

 
        self.tabs.currentChanged.connect(self._on_tab_changed)

    def _refresh_other_tabs(self) -> None:
        """Appele par SitesView apres l'ajout reussi d'un nouveau site."""
        self.certificates_view.refresh()
        self.merkle_tree_view.refresh()
        self.verification_view.refresh()

    def _on_tab_changed(self, index: int) -> None:
        """Rafraichit l'onglet qui vient d'etre affiche."""
        widget = self.tabs.widget(index)
        if hasattr(widget, "refresh"):
            widget.refresh()


def run_app():
    """Point d'entree pour lancer l'application graphique."""
    app = QApplication(sys.argv)
    window = MainWindow()
    window.show()
    sys.exit(app.exec())


if __name__ == "__main__":
    run_app()