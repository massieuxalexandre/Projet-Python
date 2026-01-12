import feedparser
import requests
import re
import smtplib
from email.mime.text import MIMEText
import pandas as pd
import json
from datetime import datetime, timedelta, timezone

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
    url_rss_avis = "https://www.cert.ssi.gouv.fr/avis/feed/"
    url_rss_alerte = "https://www.cert.ssi.gouv.fr/alerte/feed/"
    headers = {'User-Agent': 'Mozilla/5.0'} # pour pas être ban de leur site
    response_avis = requests.get(url_rss_avis, headers=headers, timeout=10)
    rss_feed_avis = feedparser.parse(response_avis.content)
    response_alerte = requests.get(url_rss_alerte, headers=headers, timeout=10)
    rss_feed_alerte = feedparser.parse(response_alerte.content)
    
    for entry in rss_feed_avis.entries:
        alertes.append({
            "titre": entry.title,
            "type": "Avis",
            "description": entry.description,
            "lien": entry.link,
            "date": entry.published
        })

    for entry in rss_feed_alerte.entries:
        alertes.append({
            "titre": entry.title,
            "type": "Alerte",
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
        response_avis = requests.get(url_cve)
        data = response_avis.json()
        ref_cves.append(list(data["cves"]))
        cve_pattern = r"CVE-\d{4}-\d{4,7}"
        cve_list.append(list(set(re.findall(cve_pattern, str(data)))))

    return ref_cves, cve_list




# Etape 3 : Enrichissement des CVE
def gravite_cvss(score):
    if score is None:
        return "Non disponible"
    elif 0 <= float(score) < 4.0:
        return "Faible"
    elif 4.0 <= float(score) < 7.0:
        return "Moyenne"
    elif 7.0 <= float(score) < 9.0:
        return "Élevée"
    elif 9.0 <= float(score) <= 10.0:
        return "Critique"
    else:
        return "Non disponible"

def gravite_epss(score):
    if score is None:
        return "Non disponible"
    elif 0 <= float(score) < 0.2:
        return "Faible"
    elif 0.2 <= float(score) < 0.5:
        return "Moyenne"
    elif 0.5 <= float(score) < 0.8:
        return "Élevée"
    elif 0.8 <= float(score) <= 1.0:
        return "Critique"
    else:
        return "Non disponible"


def enrichir_cve(cve_list):
    cve_enrichi = []
    for cve in cve_list:
        if len(cve) >= 1:
            cve_id = cve[0]
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


            url_api_epss = f"https://api.first.org/data/v1/epss?cve={cve_id}"
            # Requête GET pour récupérer les données JSON
            response_avis = requests.get(url_api_epss)
            data = response_avis.json()
            # Extraire le score EPSS
            epss_data = data.get("data", [])
            if epss_data:
                epss_score = epss_data[0]["epss"]
            else:
                epss_score = None
                
            
            cve_enrichi.append({
                "cve_id": cve_id,
                "description": description,
                "cwe": cwe,
                "nature de la faille": cwe_desc,
                "cvss_score": cvss_score,
                "gravite_cvss": gravite_cvss(cvss_score),
                "epss_score": epss_score,
                "gravite_epss": gravite_epss(epss_score),
                "editeur": vendor,
                "produit": product_name,
                "versions_affectees": versions
            })

        else:
            cve_enrichi.append({
                "cve_id": None,
                "description": None,
                "cwe": None,
                "nature de la faille": None,
                "cvss_score": None,
                "gravite_cvss": None,
                "epss_score": None,
                "gravite_epss": None,
                "editeur": None,
                "produit": None,
                "versions_affectees": None
            })
            
    
    return cve_enrichi




# Etape 4 : Consolidation des données
def condolider_donnees(alertes, cve_enrichi):
    alertes_enrichies = []

    for i in range(len(alertes)):
        alertes_enrichies.append({
            "alerte": alertes[i],
            "cve_enrichi": cve_enrichi[i]
        })

    to_json(alertes_enrichies, 'alertes_enrichies.json')

    return alertes_enrichies

def dataframe_alertes(alertes_enrichies):
    rows = []
    for key in alertes_enrichies:
        alerte_info = key["alerte"]
        cve_info = key["cve_enrichi"]
        row = {
            "Titre Alerte": alerte_info["titre"],
            "Type": alerte_info["type"],
            "Description": alerte_info["description"],
            "Lien": alerte_info["lien"],
            "Date": alerte_info["date"],
            "CVE ID": cve_info["cve_id"],
            "Description CVE": cve_info["description"],
            "CWE": cve_info["cwe"],
            "Nature de la faille": cve_info["nature de la faille"],
            "Score CVSS": cve_info["cvss_score"],
            "Gravité CVSS": cve_info["gravite_cvss"],
            "Score EPSS": cve_info["epss_score"],
            "Gravité EPSS": cve_info["gravite_epss"],
            "Éditeur": cve_info["editeur"],
            "Produit": cve_info["produit"],
            "Versions Affectées": ", ".join(cve_info["versions_affectees"]) if cve_info["versions_affectees"] else "Non disponible"
        }
        rows.append(row)
    
    df = pd.DataFrame(rows)
    df.to_csv('alertes_enrichies.csv', index=False)

    return df

# Etape 6 : Génération d'alertess et notification email

def send_email(to_email, subject, body):
    from_email = "projet.info92@gmail.com"
    password = "hfphdjyiddkfyqvv"
    msg = MIMEText(body)
    msg['From'] = from_email
    msg['To'] = to_email
    msg['Subject'] = subject
    server = smtplib.SMTP('smtp.gmail.com', 587)
    server.starttls()
    server.login(from_email, password)
    server.sendmail(from_email, to_email, msg.as_string())
    server.quit()


def alerter(alertes_enrichies, quotidiennes=None, seuil_gravite_cvss=None, editeur=None, produit=None, email=None):
    if quotidiennes:
        for key in alertes_enrichies:
            if datetime.strptime(key["alerte"]["date"], "%a, %d %b %Y %H:%M:%S %z") == datetime.now(timezone.utc) - timedelta(days=1):
                cve_details = "\n".join(f"{cle}: {val}" for cle, val in key['cve_enrichi'].items())
                send_email(email, key["alerte"]["titre"], f"Une alerte de sécurité a été détectée aujourd'hui. \n\n{key['alerte']['description']}\n\nLien : {key['alerte']['lien']}\n\nDétails CVE :\n\n{cve_details}")
        print(f"Si des alertes ont eu lieues aujourd'hui, elles vous ont été envoyées")


    elif seuil_gravite_cvss:
        for key in alertes_enrichies:
            if key["cve_enrichi"]["cvss_score"] is not None:
                if float(key["cve_enrichi"]["cvss_score"]) >= seuil_gravite_cvss:
                    cve_details = "\n".join(f"{cle}: {val}" for cle, val in key['cve_enrichi'].items())
                    send_email(email, key["alerte"]["titre"], f"Une alerte de sécurité de gravité CVSS {key['cve_enrichi']['cvss_score']} a été détectée. \n\n{key['alerte']['description']}\n\nLien : {key['alerte']['lien']}\n\nDétails CVE :\n\n{cve_details}")
        print(f"Si des alertes ont un score CVSS >= à {seuil_gravite_cvss}, elles vous ont été envoyées")

    elif editeur:
        for key in alertes_enrichies:
            if key["cve_enrichi"]["editeur"] == editeur:
                cve_details = "\n".join(f"{cle}: {val}" for cle, val in key['cve_enrichi'].items())
                send_email(email, key["alerte"]["titre"], f"Une alerte conernant l'editeur {editeur} a été détectée. \n\n{key['alerte']['description']}\n\nLien : {key['alerte']['lien']}\n\nDétails CVE :\n\n{cve_details}")
        print(f"Si des alertes concernent l'editeur {editeur}, elles vous ont été envoyées")

       
    elif produit:
        for key in alertes_enrichies:
            if key["cve_enrichi"]["produit"] == produit:
                cve_details = "\n".join(f"{cle}: {val}" for cle, val in key['cve_enrichi'].items())
                send_email(email, key["alerte"]["titre"], f"Une alerte conernant le produit {produit} a été détectée. \n\n{key['alerte']['description']}\n\nLien : {key['alerte']['lien']}\n\nDétails CVE :\n\n{cve_details}")
        print(f"Si des alertes concernent le produit {produit}, elles vous ont été envoyées")






print("Extraction des alertes...")
alertes = extraire_rss() # a utiliser de temps en temps pour pas spammer le site
# alertes = from_json("alertes.json") # pour charger les aloertes localement
print("Extraction des CVE des alertes...")
ref_cves, cve_list = extraire_cve_alertes(alertes)

print("Enrichissement des CVE...")
cve_enrichi = enrichir_cve(cve_list)

print("Consolidation des données et creéation du dataframe...")
alertes_enrichies = condolider_donnees(alertes, cve_enrichi)
# alertes_enrichies = from_json("alertes_enrichies.json") # pour charger les alertes enrichies localement

df_alertes = dataframe_alertes(alertes_enrichies)

while True:
    print("Choisissez le type d'alerte à recevoir :")
    print("1. Quotidiennes")
    print("2. Niveau de gravité")
    print("3. Par éditeur")
    print("4. Par produit")
    print("5. Quitter")
    choix = input()
    if choix == "5":
        print()
        print("Au revoir")
        break

    elif choix in ["1", "2", "3", "4"]:
        print()
        print("Quel est votre adresse email ?")
        email = input()
        print()
            
        if choix == "1":
            alerter(alertes_enrichies, quotidiennes=True, email=email)
            

        elif choix == "2":
            print("A partir de quel seuil de gravité CVSS voulez-vous recevoir les alertes ? (0.0 à 10.0)")
            seuil = float(input())
            print()
            alerter(alertes_enrichies, seuil_gravite_cvss=seuil, email=email)
            

        elif choix == "3":
            print(df_alertes.get("Éditeur").unique())
            print()
            print("De quel éditeur ci-dessus voulez-vous recevoir les alertes ? (copiez-collez le nom)")
            editeur = input()
            print()
            alerter(alertes_enrichies, editeur=editeur, email=email)
            

        elif choix == "4":
            print(df_alertes["Produit"].unique())
            print()
            print("De quel produit ci-dessus voulez-vous recevoir les alertes ? (copiez-collez le nom)")
            produit = input()
            print()
            alerter(alertes_enrichies, produit=produit, email=email)
            

        print()
        print("Voulez-vous vous inscrire à nouveau ?")
        print("1. Oui")
        print("2. Non")
        inscrire = input()
        if inscrire == "2":
            break
