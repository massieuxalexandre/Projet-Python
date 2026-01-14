# Projet : Analyse des Avis et Alertes ANSSI avec Enrichissement des CVE

Ce projet est un outil de veille cybersécurité automatisé permettant de surveiller les vulnérabilités informatiques. Il extrait les flux du CERT-FR, enrichit les données CVE via des API tierces (MITRE, FIRST.org) et permet une notification ciblée par email.

## Fonctionnalités

* **Extraction des Flux** : Récupération automatisée des avis et alertes depuis les flux RSS officiels du CERT-FR.
* **Enrichissement CVE** :
    * Interrogation de l'API MITRE pour obtenir les descriptions, les types de failles (CWE) et les produits affectés.
    * Récupération du score EPSS via l'API de FIRST pour évaluer la probabilité d'exploitation réelle.
* **Analyse de Données** : Génération d'un fichier `alertes_enrichies.csv` pour un traitement statistique et graphique.

## Système de Notification par Email

Le script inclut un module de notification automatisé :

* **Types d'alertes disponibles** :
    * **Quotidiennes** : Récapitulatif des vulnérabilités publiées au cours des dernières 24 heures.
    * **Par Gravité** : Filtrage selon un seuil de score CVSS (de 0.0 à 10.0) défini par l'utilisateur.
    * **Par Éditeur** : Surveillance spécifique d'un acteur du marché (ex: Microsoft, Cisco, Citrix).
    * **Par Produit** : Ciblage précis d'un logiciel ou matériel particulier (ex: Chrome, Windows 10).

## Analyse et Visualisation (notebook.ipynb)

Le fichier `notebook.ipynb` permet de transformer les données brutes consolidées en informations exploitables :

* **Corrélation CVSS vs EPSS** : Analyse entre la sévérité et la probabilité réelle d'exploitation pour identifier les failles prioritaires.
* **Statistiques Produits et Éditeurs** : Identification des solutions les plus fréquemment affectées pour orienter les politiques de mise à jour.
* **Répartition des Failles (CWE)** : Visualisation des types de vulnérabilités dominants.
* **Top Menaces** : Liste des vulnérabilités présentant les scores EPSS les plus élevés.

## Installation et Utilisation

**Dépendances** :
   ```bash
   pip install requests feedparser pandas matplotlib
```
   ### Script Principal (main.py)
Lancez l'exécution pour mettre à jour la base de données locale et accéder au menu interactif :
```bash
python main.py
