import os
import re
import json
import time
import hashlib
import urllib.parse
import urllib.request
from datetime import datetime, timezone, timedelta
from pathlib import Path

TOKEN = os.environ["TELEGRAM_BOT_TOKEN"]
CHAT_ID = os.environ["TELEGRAM_CHAT_ID"]
STATE_FILE = Path("seen.json")

# Nombre maximal d'alertes par exécution
MAX_ALERTS = 8

# Requêtes GDELT : quatre types d'incidents
SEARCHES = {
    "Drones": '("drone attack" OR "drone incursion" OR "drone strike" OR "drone interception" OR "drone intrusion")',
    "Attentats": '("terror attack" OR "terrorist attack" OR "terrorist shooting" OR attentat)',
    "Sabotages": '("infrastructure sabotage" OR "railway sabotage" OR "cable sabotage" OR "pipeline explosion")',
    "Militaire": '("airspace violation" OR "missile strike" OR "military incursion" OR "missile interception")',
}

# Recherche des publications des organismes via GDELT
SOURCE_SEARCHES = {
    "OTAN": '(domain:nato.int OR domain:nato.int)',
    "Europol": 'domain:europol.europa.eu',
    "Liveuamap": 'domain:liveuamap.com',
}

# Noms géographiques présents dans les titres
EUROPE = [
    "europe", "european", "européen", "nato", "otan",
    "ukraine", "ukrainian", "kyiv", "kiev", "kharkiv", "odesa",
    "russia", "russian", "russie", "moscow", "moscou",
    "poland", "polish", "pologne", "warsaw", "varsovie",
    "france", "french", "paris", "germany", "german",
    "allemagne", "berlin", "belgium", "belgique",
    "netherlands", "pays-bas", "amsterdam",
    "united kingdom", "britain", "british", "london",
    "royaume-uni", "italy", "italie", "rome",
    "spain", "espagne", "madrid", "portugal",
    "sweden", "suède", "finland", "finlande",
    "norway", "norvège", "denmark", "danemark",
    "estonia", "estonie", "latvia", "lettonie",
    "lithuania", "lituanie", "baltic", "baltique",
    "romania", "roumanie", "moldova", "moldavie",
    "belarus", "biélorussie", "slovakia", "slovaquie",
    "czech", "tchéquie", "austria", "autriche",
    "hungary", "hongrie", "bulgaria", "bulgarie",
    "greece", "grèce", "croatia", "croatie",
    "serbia", "serbie", "bosnia", "bosnie",
    "albania", "albanie", "kosovo", "montenegro",
    "slovenia", "slovénie", "switzerland", "suisse",
    "ireland", "irlande", "iceland", "islande",
    "cyprus", "chypre", "malta", "malte",
    "north macedonia", "macédoine",
    "luxembourg", "liechtenstein", "andorra",
    "andorre", "monaco", "san marino", "vatican",
    "turkey", "türkiye", "turquie", "ankara",
    "georgia", "géorgie", "armenia", "arménie",
    "azerbaijan", "azerbaïdjan",
]

P1 = [
    "killed", "dead", "fatalities", "mass casualties",
    "people injured", "civilian casualties",
    "attentat meurtrier", "morts", "tués",
    "terror attack", "terrorist attack",
    "major explosion", "massive drone attack",
    "critical infrastructure attacked",
]

P2 = [
    "drone", "missile", "explosion", "sabotage",
    "airspace", "intercepted", "interception",
    "evacuation", "airport closed",
    "terrorist", "attentat", "incursion",
    "frappe", "attaque", "explosif",
]

P3 = [
    "investigation", "suspected", "warning",
    "threat", "security alert", "military exercise",
    "enquête", "suspicion", "menace",
]

def request(url, data=None):
    req = urllib.request.Request(
        url, data=data,
        headers={"User-Agent": "EuropeOSINTMonitor/1.0"}
    )
    with urllib.request.urlopen(req, timeout=30) as response:
        return json.loads(response.read().decode("utf-8"))

def fetch_articles(query):
    params = urllib.parse.urlencode({
        "query": query,
        "mode": "artlist",
        "format": "json",
        "timespan": "2h",
        "sort": "datedesc",
        "maxrecords": "75",
    })
    url = "https://api.gdeltproject.org/api/v2/doc/doc?" + params
    result = request(url)
    return result.get("articles", [])

def matches(text, terms):
    text = text.lower()
    return any(
        re.search(r"(?<!\w)" + re.escape(term) + r"(?!\w)", text)
        for term in terms
    )

def classify(title):
    if matches(title, P1):
        return "P1", "🔴"
    if matches(title, P2):
        return "P2", "🟠"
    return "P3", "🔵"

def article_date(value):
    try:
        return datetime.strptime(
            value, "%Y%m%dT%H%M%SZ"
        ).replace(tzinfo=timezone.utc)
    except (ValueError, TypeError):
        return None

def send_telegram(message):
    url = f"https://api.telegram.org/bot{TOKEN}/sendMessage"
    payload = urllib.parse.urlencode({
        "chat_id": CHAT_ID,
        "text": message,
        "disable_web_page_preview": "true",
    }).encode()
    request(url, payload)

def main():
    send_telegram("✅ TEST : mon bot OSINT fonctionne !")
    now = datetime.now(timezone.utc)
    cutoff = now - timedelta(hours=2)

    if STATE_FILE.exists():
        try:
            seen = json.loads(STATE_FILE.read_text())
        except (ValueError, OSError):
            seen = {}
    else:
        seen = {}

    # Conservation des identifiants pendant sept jours
    seen = {
        key: value for key, value in seen.items()
        if isinstance(value, (int, float))
        and value > now.timestamp() - 7 * 86400
    }

    results = {}
    searches = {**SEARCHES, **SOURCE_SEARCHES}

    for source, query in searches.items():
        try:
            articles = fetch_articles(query)
            print(f"{source}: {len(articles)} résultats")
            for article in articles:
                url = article.get("url", "")
                title = article.get("title", "").strip()
                published = article_date(article.get("seendate"))

                if not url or not title or not published:
                    continue
                if published < cutoff:
                    continue

                # Filtrage Europe : indication géographique dans le titre
                if not matches(title, EUROPE):
                    continue

                uid = hashlib.sha256(
                    url.encode("utf-8")
                ).hexdigest()

                if uid in seen:
                    continue

                level, emoji = classify(title)

                # Recherche principale : éviter les articles
                # sans mot-clé d'incident dans leur titre
                if level == "P3" and not matches(title, P3):
                    continue

                if uid not in results:
                    results[uid] = {
                        "title": title,
                        "url": url,
                        "published": published,
                        "level": level,
                        "emoji": emoji,
                        "source": article.get("domain", source),
                    }
        except Exception as error:
            print(f"Erreur source {source}: {error}")

        time.sleep(2)

    priority = {"P1": 0, "P2": 1, "P3": 2}
    ordered = sorted(
        results.items(),
        key=lambda entry: (
            priority[entry[1]["level"]],
            -entry[1]["published"].timestamp()
        )
    )

    sent = 0
    for uid, article in ordered[:MAX_ALERTS]:
        message = (
            f'{article["emoji"]} ALERTE OSINT {article["level"]}\n\n'
            f'{article["title"]}\n\n'
            f'Source : {article["source"]}\n'
            f'Publication : {article["published"].strftime("%d/%m/%Y %H:%M UTC")}\n'
            f'Statut : signalement à vérifier\n\n'
            f'{article["url"]}'
        )

        try:
            send_telegram(message)
            seen[uid] = now.timestamp()
            sent += 1
        except Exception as error:
            print(f"Erreur Telegram: {error}")

    STATE_FILE.write_text(
        json.dumps(seen, indent=2), encoding="utf-8"
    )
    print(f"{sent} notifications envoyées")

if __name__ == "__main__":
    main()
