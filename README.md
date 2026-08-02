# MTC Simulation

Simulation d'une architecture Merkle Tree Certificate (MTC) avec un design hybride RSA + ML-DSA, réalisée dans le cadre d'un Projet de Fin d'Études (PFE) sur la sécurité post-quantique des certificats numériques.

# Description

Ce projet implémente et simule les composants clés de l'architecture MTC :

Génération de clés hybrides (RSA + ML-DSA)
Autorité de certification (RSA CA)
Autorité MTCA (Merkle Tree Certificate Authority) et création d'entrées de log
Construction de l'arbre de Merkle (Merkle Tree)
Preuves d'inclusion (inclusion proofs)
Distribution du Tree Head
Simulation du handshake TLS avec certificats hybrides
Interface graphique (GUI) pour visualiser les certificats, l'arbre de Merkle et la vérification

# Architecture

core/
  ├── models.py         # Modèles de données
  ├── keys.py           # Génération de clés (RSA + ML-DSA)
  ├── rsa_ca.py         # Autorité de certification RSA
  ├── mtca.py           # Autorité MTCA
  ├── merkle_tree.py    # Construction de l'arbre de Merkle
  ├── tree_head.py      # Gestion du Tree Head
  ├── registry.py       # Registre des sites
  ├── client.py         # Simulation client TLS
  └── server.py         # Simulation serveur TLS

gui/
  ├── main_window.py
  └── views/
      ├── certificates_view.py
      ├── merkle_tree_view.py
      ├── sites_view.py
      └── verification_view.py

data/
  ├── ca/               # Clés et certificat de la CA racine
  ├── certs/            # Certificats émis
  ├── keys/             # Clés RSA et ML-DSA par site
  └── mtca/             # Clés de l'autorité MTCA
# Outils et technologies
Python avec cryptography (RSA, X.509)
OpenSSL 4.0.1 pour ML-DSA (appelé via subprocess)
hashlib pour la construction de l'arbre de Merkle
PySide6 pour l'interface graphique
