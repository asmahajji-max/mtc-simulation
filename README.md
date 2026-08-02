# MTC Simulation

Simulation d'une architecture Merkle Tree Certificate (MTC) avec un design hybride RSA + ML-DSA, développée dans le cadre d'un Projet de Fin d'Études (PFE) sur la sécurité post-quantique des certificats numériques.

À propos

Les certificats numériques classiques (X.509) reposent sur des algorithmes comme RSA, vulnérables face aux futurs ordinateurs quantiques. L'architecture MTC (Merkle Tree Certificate) propose une alternative : au lieu de signer chaque certificat individuellement, les certificats sont regroupés dans un arbre de Merkle, dont seule la racine (Tree Head) est signée. Ce projet simule cette architecture avec un design hybride combinant RSA et ML-DSA (algorithme de signature post-quantique standardisé par le NIST).

# Fonctionnalités
🔑 Génération de clés hybrides (RSA + ML-DSA) par site
🏛️ Autorité de certification (RSA CA) émettant des certificats X.509
📜 Autorité MTCA (Merkle Tree Certificate Authority) créant des entrées de log
🌳 Construction et gestion de l'arbre de Merkle
✅ Génération et vérification de preuves d'inclusion (inclusion proofs)
📡 Distribution et validation du Tree Head
🔒 Simulation du handshake TLS avec certificats hybrides
🖥️ Interface graphique (GUI) pour visualiser les certificats, l'arbre de Merkle et le processus de vérification
Stack technique
# Composant	Technologie
Langage	Python
Cryptographie classique	cryptography (RSA, X.509)
Cryptographie post-quantique	OpenSSL 4.0.1 (ML-DSA, via subprocess)
Arbre de Merkle	hashlib
Interface graphique	PySide6
# Structure du projet
core/       → logique métier (clés, CA, MTCA, arbre de Merkle, TLS)
gui/        → interface graphique et vues
data/       → clés, certificats et registre générés
main.py     → point d'entrée de l'application
# Installation
bash
git clone https://github.com/asmahajji-max/mtc-simulation.git
cd mtc-simulation
python -m venv venv
venv\Scripts\activate
pip install -r requirements.txt
# Utilisation
bash
python main.py
