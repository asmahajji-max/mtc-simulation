

from PySide6.QtWidgets import (
    QWidget, QVBoxLayout, QPushButton, QGraphicsScene, QGraphicsView,
    QGraphicsRectItem, QGraphicsTextItem, QGraphicsLineItem, QLabel
)
from PySide6.QtGui import QColor, QBrush, QPen
from PySide6.QtCore import Qt

from core.registry import load_sites
from core.merkle_tree import create_all_leaves, build_merkle_tree
from core.tree_head import create_tree_head

NODE_WIDTH = 140
NODE_HEIGHT = 50
LEVEL_HEIGHT = 110
LEAF_SPACING = 170


class MerkleTreeView(QWidget):
    

    def __init__(self, parent=None):
        super().__init__(parent)

        layout = QVBoxLayout()

        self.info_label = QLabel("Aucun arbre construit pour l'instant.")
        layout.addWidget(self.info_label)

        self.refresh_button = QPushButton("Reconstruire l'arbre")
        self.refresh_button.clicked.connect(self.refresh)
        layout.addWidget(self.refresh_button)

        self.scene = QGraphicsScene()
        self.view = QGraphicsView(self.scene)
        self.view.setRenderHint(self.view.renderHints())
        layout.addWidget(self.view)

        self.setLayout(layout)

        self.root = None
        self.tree_head = None
        self.refresh()

    def refresh(self) -> None:
        
        self.scene.clear()
        sites = load_sites()

        if not sites:
            self.info_label.setText("Aucun site enregistre - impossible de construire un arbre.")
            return

        leaves = create_all_leaves(sites)
        self.root = build_merkle_tree(leaves)
        self.tree_head = create_tree_head(self.root, len(leaves))

        self.info_label.setText(
            f"Arbre construit : {len(leaves)} feuille(s)  |  "
            f"Root hash : {self.tree_head.root_hash.hex()[:16]}...  |  "
            f"Signe par : {self.tree_head.signer_id}"
        )

        positions = {}
        self._compute_layout(self.root, depth=0, x_counter=[0], positions=positions)
        self._draw_node(self.root, positions)

        self.view.setSceneRect(self.scene.itemsBoundingRect())

    def _compute_layout(self, node, depth, x_counter, positions) -> float:
        
        if node.is_leaf:
            x = x_counter[0] * LEAF_SPACING
            x_counter[0] += 1
            positions[id(node)] = (x, depth * LEVEL_HEIGHT)
            return x

        left_x = self._compute_layout(node.left, depth + 1, x_counter, positions)
        right_x = self._compute_layout(node.right, depth + 1, x_counter, positions)
        x = (left_x + right_x) / 2
        positions[id(node)] = (x, depth * LEVEL_HEIGHT)
        return x

    def _draw_node(self, node, positions) -> None:
        """Dessine recursivement un noeud (rectangle + texte) et ses liens."""
        x, y = positions[id(node)]

        color = QColor("#2e7d32") if node.is_leaf else QColor("#37474f")
        if node is self.root:
            color = QColor("#b71c1c")  
        rect = QGraphicsRectItem(x, y, NODE_WIDTH, NODE_HEIGHT)
        rect.setBrush(QBrush(color))
        rect.setPen(QPen(Qt.white))
        self.scene.addItem(rect)

        label_top = node.site_id if node.is_leaf else ("RACINE" if node is self.root else "NOEUD")
        label_hash = node.hash_value.hex()[:12] + "..."
        text = QGraphicsTextItem(f"{label_top}\n{label_hash}")
        text.setDefaultTextColor(Qt.white)
        text.setPos(x + 5, y + 5)
        self.scene.addItem(text)

        if not node.is_leaf:
            for child in (node.left, node.right):
                cx, cy = positions[id(child)]
                line = QGraphicsLineItem(
                    x + NODE_WIDTH / 2, y + NODE_HEIGHT,
                    cx + NODE_WIDTH / 2, cy
                )
                line.setPen(QPen(Qt.gray, 2))
                self.scene.addItem(line)
                self._draw_node(child, positions)