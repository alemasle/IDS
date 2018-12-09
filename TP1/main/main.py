#!/usr/bin/env python3
import os
import logging
import sys
import datetime
import certstream
import whois
import requests
import csv
import urllib.request
from tld import get_tld
from bs4 import BeautifulSoup
from stix2 import MemoryStore, Indicator

# ne pas toucher, le fichier site-database sera ecrase sinon
mem = MemoryStore()
GREEN = "\033[38;5;2m" # Clean
RED = "\033[38;5;1m" # Phishing
LIGHT_RED = "\033[38;5;9m" # Grand danger
GRAY = "\033[38;5;7m" # En calcul
WHITE = "\033[0m" # Reset

fname = open("list-fr.csv", 'r')
file = csv.reader(fname)
dico = {'0':['o'],'I':['l','1'],'8':['b'],'1':['l','i'],'5':['s'],'i':['j'],'j':['i']}
motCle = {'google': 30 , 'apple':20, 'appleid': 30,'facebook': 30,'yahoo':20 ,'youtube': 25,'dailymotion': 20,'instagram':30,'twitter':30,\
'pinterest':20,'linkedin':30,'netflix':30,'hotmail': 20,'outlook':35,'laposte':35,'free': 35,'orange': 35,'sfr': 35,'bouygues': 35,'bouyguestelecom': 35,\
'paypal': 40 ,'steam': 35,'deezer': 35,'spotify': 35,'account':25,'connexion': 25,'youporn':35, 'pornhub': 35, 'redtube': 30,'xhamster':30,'xnxx':30,\
'xvideos':30,'amazon': 35,'leboncoin': 35,'live': 35,'livejasmin': 25,'cdiscount': 30,'labanquepostal': 40,'ebay':35,'msn':30,'pole-emploi':30,\
'twitch':25,'credit-agricole':35,'github':25,'bongacams':30,'fnac':35,'boulanger':35,'caf':40,'ameli':40,'impot':40,'tresor-publique':40,'cartegrise':40,\
'cartevital':40, 'westernunion':45,'alibaba': 30, 'onedrive':25, 'dropbox':25,'jacquieetmichel':25, 'authentication': 30, 'authentification': 30, 'auth':30,\
'freeboxos':20}

def mots_suspects(url):
    score = 0
    parse = get_tld(url, as_object=True, fix_protocol=True)
    sub = parse.subdomain
    for w in motCle.keys():
        if w in parse.domain and parse.domain not in w:
            score += motCle.get(w)
        elif w in sub:
            score += motCle.get(w)
    return score

def verif_url(url):
    fname.seek(0)
    score = 10000000000
    site = ""
    for rows in file:
        row = rows[1]
        diff = 0
        if url in row or row in url:
            return 0,row
        for u,r in zip(url,row):
            if u != r :
                diff += 1
        diff += abs(len(row) - len(url))
        if diff < score:
            score = diff
            # on cherche le plus petit difference, donc le site plus ressemblant
            site = row
        if score <= 1:
            return score,site
    return score,site

def verif_url_alter(url):
    # liste de caractere semblable
    score,site = verif_url(url)
    tmpURL = url
    if score <=1 :
        return modif_score(score/len(url)),site
    for k in dico.keys():
        if k in url:
            for v in dico.get(k):
                tmpURL = url.replace(k,v)
                tmpScore,tmpSite = verif_url(tmpURL)
                if tmpScore<score:
                    score = tmpScore
                    site = tmpSite
                if score <=1 :
                    return modif_score(score/len(url)),site
    return modif_score(score/len(url)),site

def modif_score(sc):
    if sc == 1:
        return 0
    if sc > 0.75:
        return 10
    if sc > 0.5:
        return 25
    if sc > 0.25 :
        return 75
    if sc == 0 :
        return 100
    return 90

"""
Retourne la difference entre les possesseurs de domaine
"""
def check_whois(url_catch, url_potentielle):
    assert url_catch != "" and url_catch is not None, "aucune url en parametre"
    assert url_potentielle != "" and url_potentielle is not None, "aucune url devinee"

    score = 0
    creation_date = None
    creation_date_fake = None

    try:

        domain_url_catch = get_tld(url_catch, as_object=True, fix_protocol=True)
        domain_url_potentielle = get_tld(url_potentielle, as_object=True, fix_protocol=True)

        domain = whois.query(domain_url_catch.fld)
        domain2 = whois.query(domain_url_potentielle.fld)

        if domain is not None and domain2 is not None:
            if domain.registrar == domain2.registrar:
                score = 0
            elif domain.registrar.lower() == domain2.registrar.lower():
                score = 25
            else:
                score = 50  # Completement different nom de createur

            creation_date_fake = domain.creation_date
            creation_date = domain2.creation_date
        else:
            if domain is None:
                score = 70

    except Exception as e:
        # print(e)
        score = 0

    return score, creation_date, creation_date_fake

def antivirus(url):
    score = 0

    """ Envoie au scan """
    params = {'apikey': '0ff3d543572fa3481217448a0a711b43883e42ba77a7a210cac7bb0d620a0c61', 'url':'{}'.format(url)}
    response = requests.post('https://www.virustotal.com/vtapi/v2/url/scan', data=params, timeout=3.5)
    try:
        json_response = response.json()
        if json_response["response_code"] < 1: # url scan error
            return 0

        """ Recupere le resultat """
        params2 = {'apikey': '0ff3d543572fa3481217448a0a711b43883e42ba77a7a210cac7bb0d620a0c61', 'resource':'{}'.format(url)}
        response2 = requests.post('https://www.virustotal.com/vtapi/v2/url/report', data=params2, timeout=3.5)
        json_response2 = response2.json()
        if json_response2['response_code'] < 1: # url error
            return 0

        nb_positive = json_response2["positives"]
        total = json_response2["total"]

        ratio = (nb_positive/total) * 100

        score = ratio_to_score(ratio)

    except Exception as e: # Cas d'erreur
        score = 0

    return score

def ratio_to_score(ratio):
    if ratio >= 80:
        score = 100
    elif ratio >= 70:
        score = 90
    elif ratio >= 60:
        score = 85
    elif ratio >= 50:
        score = 80
    elif ratio >= 40:
        score = 75
    elif ratio >= 30:
        score = 70
    elif ratio >= 20:
        score = 65
    elif ratio >= 10:
        score = 60
    elif ratio >= 9:
        score = 50
    elif ratio >= 8:
        score = 40
    elif ratio >= 7:
        score = 30
    elif ratio >= 6:
        score = 20
    elif ratio >= 5:
        score = 10
    else:
        score = 0
    return score

def check_domain_date(date, date_fake):
    score_domain = 0
    if date is None:
        # print("pas de date de création du nom de domaine officiel")
        return score_domain
    if date_fake is None:
        # print("pas de date de création du nom de domaine ciblé (possible phishing)")
        return 100
    if date.date() > date_fake.date() or date.date() < date_fake.date():
        # print("Les dates ne sont pas pareils")
        score_domain = 100
    return score_domain

def require_ident(url):
    score = 0
    score_js = 0
    url_scan = url
    if "http://" not in url_scan:
        url_scan = "http://" + url_scan
    try:
        with urllib.request.urlopen(url_scan, timeout=3.5) as u:
            lu = u.read().decode()
            soup = BeautifulSoup(lu, "html.parser")

            score_js = js_check(soup, url)

            user = soup.find_all(id="username")
            if user == []:
                user = soup.find_all(id="login")
            if user == []:
                user = soup.find_all(id="Email")

            passwd = soup.find_all(id="password")
            if passwd == []:
                passwd = soup.find_all(id="passwd")

            submit = soup.find_all(type="submit")

            if user != [] and passwd != [] and submit != []:
                score = 100

            elif user != [] and passwd == [] and submit != []:
                score = 70

            elif user == [] and passwd != [] and submit != []:
                score = 80

            elif user != [] and passwd != [] and submit == []:
                score = 80

            elif user != [] and passwd == [] and submit == []:
                score = 50

            elif user == [] and passwd != [] and submit == []:
                score = 50

    except Exception as e:
        score = 0

    return score, score_js

def js_check(soup_p, url_b):
    score = 0
    if soup_p is None:
        return score
    script_bal = soup_p.find_all('script',{"src": True})
    if script_bal == []:
        return score
    for url in script_bal:
        url_to_check = get_tld(url, as_object=True, fix_protocol=True)
        url_ref = get_tld(url_b, as_object=True, fix_protocol=True)
        if url_to_check.fld is not url_ref.fld:
            return 100
    return score

def isPhishing(score):
    #score max : 2266
    if score <= 70:
        return False,"Danger Faible"
    if score <= 125:
        return False, "Danger " + GRAY + "Intermediaire" + WHITE
    if score <= 150:
        return True,"Danger " + RED + "Eleve" + WHITE
    return True,"Danger " + LIGHT_RED + "Tres Eleve" + WHITE

# main function get new URL and check if the website is a phishing site

def main(message, context):

    if message['message_type'] == "heartbeat":
        return

    if message['message_type'] == "certificate_update":
        all_domains = message['data']['leaf_cert']['all_domains']

    if len(all_domains) == 0:
        return
    else:
        domain = all_domains[0]

    rows, columns = os.popen('stty size', 'r').read().split()

    print(" " * int(columns), end='\r')
    print(WHITE + domain, end='\r')

    url = ""
    sp = domain.split('.')
    if "fr" not in sp:
        return
    else:
        url = all_domains[0]
        if url.startswith("*."):
            url = url[2:]

    print(" " * int(columns), end='\r')
    print(GRAY + url + WHITE, end="\r") # URL acceptee et en attente
    # start of url check
    score = 0
    # Detect phishing

    # etape 1 : Verification de l'url
    sc, site = verif_url_alter(url)
    score += (sc * 1) #max:100
    assert site != "" and site != None, "Aucun site correspondant"
    # etape 2 : Verification de la distance syntaxique de l'auteur
    score_whois, date_off, date_fake = check_whois(url, site)
    score_whois = score_whois * 0.3 # max: 21
    score += score_whois
    # etape 3 : Verification par virustotal
    score_antivirus = antivirus(url)
    score_antivirus = (score_antivirus * 1)
    score += score_antivirus # max: 100
    # etape 4 - 5 : Verification de la presence d'un formulaire "login/password" et d'import javascript externe
    score_ident, score_js = require_ident(url)
    score_ident = score_ident * 0.5
    score_js = score_js * 0.5
    score += score_ident # max: 50
    score += score_js # max: 50
    # etape 6 : Verification date de creation des domaines officiels et scanne
    score_domain_date = check_domain_date(date_off, date_fake)
    score_domain_date = score_domain_date * 0.2
    score += score_domain_date # max: 20
    # etape 7: Verification de mots suspects dans l'url
    score_suspects = mots_suspects(url)
    score += (score_suspects * 1) # max: 1925   # 3 mots en moyenne ?
    #score max : 2266
    b,s = isPhishing(score)

    if b:
        print(RED + url + WHITE + " : " + s + " (score=%.2f -- mot-suspects:%.2f url:%.2f whois:%.2f antivirus:%.2f identifiants:%.2f javascript:%.2f date_domaines:%.2f)" % (score, score_suspects, sc, score_whois, score_antivirus, score_ident, score_js, score_domain_date))
        date = datetime.datetime.now().strftime('%m/%d/%y %H:%M:%S')
        date_until_valid = datetime.datetime.now() + datetime.timedelta(days=30)
        # add in STIXv2.0 file
        indicator = Indicator(
            name = "Malicious site (phishing)",
            labels = ["malicious-activity"],
            pattern = "[url:value = '{}']".format(url),
            created = "{}".format(date),
            valid_from = "{}".format(date),
            valid_until = "{}".format(date_until_valid),
            description = "score=%.2f -- mot-suspects:%.2f url:%.2f whois:%.2f antivirus:%.2f identifiants:%.2f javascript:%.2f date_domaines:%.2f)" % (score, score_suspects, sc, score_whois, score_antivirus, score_ident, score_js, score_domain_date)
        )
        mem.add(indicator)
        mem.save_to_file("../database/site_database{}.json".format(datetime.datetime.now().date())) #end of the function, if the site is a phishing site (score > 0) -> write in STIXv2.0 file

    else:
        print(GREEN + url + WHITE + " : " + s + " (score=%.2f)" % score)
    print(WHITE)


if __name__ == "__main__" :
    certstream.listen_for_events(main, "wss://certstream.calidog.io")

#
