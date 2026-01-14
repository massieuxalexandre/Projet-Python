# Analyseur et Notificateur de Failles de Sécurité (CERT-FR)

Ce projet est un outil de veille automatisé permettant de surveiller les vulnérabilités informatiques. Il extrait les flux du CERT-FR, enrichit les données CVE via des API tierces et permet une notification ciblée par email.

## Fonctionnalités

* **Extraction des Flux** : Récupération automatisée des avis et alertes depuis les flux RSS officiels du CERT-FR.
* **Enrichissement CVE** :
    * Interrogation de l'API MITRE pour obtenir les descriptions, les types de failles (CWE) et les produits affectés.
    * Récupération du score EPSS via l'API de FIRST.org pour évaluer la probabilité d'exploitation réelle.
* **Analyse et Visualisation** :
    * Export des données au format CSV pour traitement statistique.
    * Visualisation graphique via un Notebook Jupyter (corrélations CVSS/EPSS, top produits, répartition des failles).
* **Système d'Alerte** : Envoi de rapports personnalisés par email selon des critères définis : quotidien, seuil de gravité CVSS, éditeur ou produit spécifique.

## Installation

1.  **Dépendances Python** :
    Le projet nécessite les bibliothèques suivantes : `requests`, `feedparser`, `pandas`, `matplotlib`.
    ```bash
    pip install requests feedparser pandas matplotlib
    ```

2.  **Configuration** :
    Le script utilise un serveur SMTP (Gmail par défaut) pour l'envoi des alertes. Les identifiants sont configurés dans la fonction `send_email` du fichier principal.

## Utilisation

### Script Principal (main.py)
Lancez l'exécution pour mettre à jour la base de données locale et accéder au menu interactif :
```bash
python main.py
