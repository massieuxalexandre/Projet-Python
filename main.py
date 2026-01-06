import feedparser
import requests
import re
import smtplib
from email.mime.text import MIMEText
import pandas as pd
import json

# lien avec les json
def from_json(filename):
    with open(filename, 'r', encoding='utf-8') as f:
        data = json.load(f)
    return data

def to_json(data, filename):
    with open(filename, 'w', encoding='utf-8') as f:
        json.dump(data, f, ensure_ascii=False, indent=4)


# Etape 1 : Extraction des Flux RSS

# fonction à utiliser de temps en temps pour ne pas spammer le site
def extraire_rss():
    alertes = []
    url_rss = "https://www.cert.ssi.gouv.fr/feed/"
    rss_feed = feedparser.parse(url_rss)
    for entry in rss_feed.entries:
        if "avis" in entry.link or "alerte" in entry.link: # garder que avis et alertes 
            alertes.append({
                "titre": entry.title,
                "description": entry.description,
                "lien": entry.link,
                "date": entry.published
            })

    # enregistrer les alertes dans un JSON
    to_json(alertes, 'alertes.json')

    return alertes


# Etape 2 : Extraction des CVE

def extraire_cve_alertes(alertes):
    ref_cves = []
    cve_list = []

    for alerte in alertes:
        url_cve = alerte["lien"]
        url_cve += "json/"
        response = requests.get(url_cve)
        data = response.json()
        ref_cves.append(list(data["cves"]))
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list.append(list(set(re.findall(cve_pattern, str(data)))))

    return ref_cves, cve_list




# Etape 3 : Enrichissement des CVE

def enrichir_cve(cve_list):
    cve_enrichi = []
    for cve in cve_list:
        for cve_id in cve:
            url_api_cve = f"https://cveawg.mitre.org/api/cve/{cve_id}"
            response = requests.get(url_api_cve)
            data = response.json()
            # Extraire la description
            description = data.get("containers", {}).get("cna", {}).get("descriptions", [{}])[0].get("value")
            # Extraire le score CVSS
            #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
            #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
            cvss_score = data.get("containers", {}).get("cna", {}).get("metrics", [{}])[0].get("cvssV3_1", {}).get("baseScore")
            cwe = "Non disponible"
            cwe_desc="Non disponible"
            problemtype = data.get("containers", {}).get("cna", {}).get("problemTypes", {})
            if problemtype and "descriptions" in problemtype[0]:
                cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
                cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")
            # Extraire les produits affectés
            affected = data.get("containers", {}).get("cna", {}).get("affected", [])
            for product in affected:
                vendor = product.get("vendor", "")
                product_name = product.get("product", "")
                versions = [v["version"] for v in product.get("versions", []) if v.get("status", "") == "affected"]
                print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")
            # Afficher les résultats
            # print(f"CVE : {cve_id}")
            # print(f"Description : {description}")
            # print(f"Score CVSS : {cvss_score}")
            # print(f"Type CWE : {cwe}")
            # print(f"CWE Description : {cwe_desc}")


            url_api_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            # Requête GET pour récupérer les données JSON
            response = requests.get(url_api_epss)
            data = response.json()
            # Extraire le score EPSS
            epss_data = data.get("data", [])
            if epss_data:
                epss_score = epss_data[0]["epss"]
                # print(f"CVE : {cve_id}")
                # print(f"Score EPSS : {epss_score}")
            else:
                # print(f"Aucun score EPSS trouvé pour {cve_id}")
                epss_score = None
                
            
            cve_enrichi.append({
                "cve_id": cve_id,
                "description": description,
                "cvss_score": cvss_score,
                "cwe": cwe,
                "cwe_desc": cwe_desc,
                "epss_score": epss_score,
                "editeur": vendor,
                "produit": product_name,
                "versions_affectees": versions
            })
    
    return cve_enrichi





# Etape 4 : Consolidation des données
def condolider_donnees(alertes, cve_enrichi):
    alertes_enrichies = []

    for alerte, cve_donnee in zip(alertes, cve_enrichi):
        alertes_enrichies.append(zip(alerte, cve_donnee))

    # enregistrer les alertes dans un JSON
    to_json(alertes_enrichies, 'alertes_enrichies.json')

    return True



# Etape 6 : Génération d'alertess et notification email

def send_email(to_email, subject, body):
    from_email = "votre_email@gmail.com"
    password = "mot_de_passe_application"
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()


# alertes = extraire_rss() # a utiliser de temps en temps pour pas spammer le site
alertes = from_json("alertes.json") # pour charger les aloertes localement
ref_cves, cve_list = extraire_cve_alertes(alertes)


cve_enrichi = enrichir_cve(cve_list)

condolider_donnees(alertes, cve_enrichi)

 
# send_email("destinataire@email.com", "alertes CVE critique", "Mettez à jour votre serveur Apache immédiatement.")