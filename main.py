import feedparser
import requests
import re
import smtplib
from email.mime.text import MIMEText
import pandas as pd
import json



# Etape 1 : Extraction des Flux RSS

# fonction à utiliser de temps en temps pour ne pas spammer le site
def extraire_rss():
    alertes = []
    url_rss = "https://www.cert.ssi.gouv.fr/feed/"
    rss_feed = feedparser.parse(url_rss)
    for entry in rss_feed.entries:
        alertes.append({
            "titre": entry.title,
            "description": entry.description,
            "lien": entry.link,
            "date": entry.published
        })

    # enregistrer les alertes dans un JSON
    with open('alertes.json', 'w', encoding='utf-8') as f:
        json.dump(alertes, f, ensure_ascii=False, indent=4)

    return alertes


def charger_alertes_json():
    with open('alertes.json', 'r', encoding='utf-8') as f:
        alertes = json.load(f)
    return alertes

# alertes = extraire_rss() # a utiliser de temps en temps pour pas spammer le site
alertes = charger_alertes_json() # pour charger les aloertes localement





# Etape 2 : Extraction des CVE

def extraire_cve_alertes():
    ref_cves = []
    cve_list = []

    for alerte in alertes:
        url_cve = alerte.get("lien", "")
        url_cve = "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/" # test
        url_cve += "json/"
        response = requests.get(url_cve)
        data = response.json()
        ref_cves.append(list(data["cves"]))
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list.append(list(set(re.findall(cve_pattern, str(data)))))

    return ref_cves, cve_list

ref_cves, cve_list = extraire_cve_alertes()
print("Références CVE extraites des alertes :")
for refs in ref_cves:
    print(refs)

# url = "https://www.cert.ssi.gouv.fr/alerte/CERTFR-2024-ALE-001/json/"
# response = requests.get(url)
# data = response.json()
# #Extraction des CVE reference dans la clé cves du dict data
# ref_cves=list(data["cves"])
# #attention il s’agit d’une liste des dictionnaires avec name et url comme clés
# print( "CVE référencés ", ref_cves)
# # Extraction des CVE avec une regex
# cve_pattern = r"CVE-\d{4}-\d{4,7}"
# cve_list = list(set(re.findall(cve_pattern, str(data))))
# print("CVE trouvés :", cve_list)


# # Etape 3 : Enrichissement des CVE
# # - Connexion à l'API CVE
# cve_id = "CVE-2023-24488"
# url_api_cve = f"https://cveawg.mitre.org/api/cve/{cve_id}"
# response = requests.get(url_api_cve)
# data = response.json()
# # Extraire la description
# description = data["containers"]["cna"]["descriptions"][0]["value"]
# # Extraire le score CVSS
# #ATTENTION tous les CVE ne contiennent pas nécessairement ce champ, gérez l’exception,
# #ou peut etre au lieu de cvssV3_0 c’est cvssV3_1 ou autre clé
# cvss_score =data["containers"]["cna"]["metrics"][0]["cvssV3_1"]["baseScore"]
# cwe = "Non disponible"
# cwe_desc="Non disponible"
# problemtype = data["containers"]["cna"].get("problemTypes", {})
# if problemtype and "descriptions" in problemtype[0]:
#     cwe = problemtype[0]["descriptions"][0].get("cweId", "Non disponible")
#     cwe_desc=problemtype[0]["descriptions"][0].get("description", "Non disponible")
# # Extraire les produits affectés
# affected = data["containers"]["cna"]["affected"]
# for product in affected:
#     vendor = product["vendor"]
#     product_name = product["product"]
#     versions = [v["version"] for v in product["versions"] if v["status"] == "affected"]
#     print(f"Éditeur : {vendor}, Produit : {product_name}, Versions : {', '.join(versions)}")
# # Afficher les résultats
# print(f"CVE : {cve_id}")
# print(f"Description : {description}")
# print(f"Score CVSS : {cvss_score}")
# print(f"Type CWE : {cwe}")
# print(f"CWE Description : {cwe_desc}")


# # - Connexion à l'API EPSS
# # URL de l'API EPSS pour récupérer la probabilité d'exploitation
# cve_id = "CVE-2023-46805"
# url_api_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
# # Requête GET pour récupérer les données JSON
# response = requests.get(url_api_epss)
# data = response.json()
# # Extraire le score EPSS
# epss_data = data.get("data", [])
# if epss_data:
#     epss_score = epss_data[0]["epss"]
#     print(f"CVE : {cve_id}")
#     print(f"Score EPSS : {epss_score}")
# else:
#     print(f"Aucun score EPSS trouvé pour {cve_id}")


# Etape 4 : Consolidation des données




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
    
# send_email("destinataire@email.com", "alertes CVE critique", "Mettez à jour votre serveur Apache immédiatement.")