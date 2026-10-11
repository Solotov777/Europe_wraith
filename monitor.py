"""OSINT presse: signalements ≠ événements confirmés. Python standard library."""
import hashlib
import json
import os
import re
import sys
import time
import unicodedata
import urllib.error
import urllib.parse
import urllib.request
import xml.etree.ElementTree as ET
from datetime import datetime, timedelta, timezone
from email.utils import parsedate_to_datetime
from pathlib import Path

ROOT = Path(__file__).resolve().parent
CONFIG = json.loads((ROOT / 'locations.json').read_text(encoding='utf-8'))
STATE = ROOT / 'seen.json'
NOW = datetime.now(timezone.utc)
LOOKBACK_HOURS = 26
MAX_ALERTS = 12
QUERY = '(Ukraine OR Ukrainian OR Russia OR Russian OR Poland OR Baltic OR Romania OR Bulgaria OR Moldova OR Finland OR "Black Sea" OR "Baltic Sea") (drone OR missile OR strike OR sabotage OR airspace OR attack OR explosion OR offensive)'
RSS = {
    'BBC Europe': 'https://feeds.bbci.co.uk/news/world/europe/rss.xml',
    'BBC Monde': 'https://feeds.bbci.co.uk/news/world/rss.xml',
    'Google News Ukraine': 'https://news.google.com/rss/search?' + urllib.parse.urlencode({'q': '(Ukraine OR Russia) (drone OR missile OR strike OR offensive) when:1d', 'hl': 'en', 'gl': 'GB', 'ceid': 'GB:en'}),
    'Google News Europe securite': 'https://news.google.com/rss/search?' + urllib.parse.urlencode({'q': '(Poland OR Baltic OR Romania OR Bulgaria OR Europe) (drone OR airspace OR sabotage OR missile) when:1d', 'hl': 'en', 'gl': 'GB', 'ceid': 'GB:en'}),
}
P1 = ['killed', 'dead', 'fatalities', 'mass casualty', 'many injured', 'massive attack', 'large-scale attack', 'major explosion', 'tués', 'morts', 'attentat meurtrier']
P2 = ['drone', 'uav', 'shahed', 'missile', 'explosion', 'sabotage', 'strike', 'shelling', 'attack', 'incursion', 'airspace', 'intercept', 'terror', 'offensive', 'frappe', 'attaque', 'bombard', 'mine', 'explosif', 'intrusion']
P3 = ['investigation', 'suspected', 'warning', 'threat', 'military aid', 'ceasefire', 'sanction', 'negotiat', 'peace talks', 'enquête', 'menace', 'troops', 'frontline', 'security alert']


def norm(s):
    s = ''.join(c for c in unicodedata.normalize('NFKD', str(s).casefold()) if not unicodedata.combining(c))
    return re.sub(r'\s+', ' ', s)


def contains(text, terms):
    t = norm(text)
    return any(re.search(r'(?<![a-z0-9])' + re.escape(norm(x)) + r'(?![a-z0-9])', t) for x in terms)


def geography(text):
    # Longest match first avoids 'UK' / short place names spuriously matching words.
    for group, tag in [('priority_countries', 'renforcée'), ('secondary_countries', 'ciblée')]:
        for country, aliases in CONFIG[group].items():
            if contains(text, [a for a in aliases if len(norm(a).strip()) >= 4]):
                return country, tag
    if contains(text, [x for x in CONFIG['maritime'] if len(x) >= 5]):
        return 'Zone maritime', 'maritime'
    return None, None


def get_bytes(url, data=None):
    req = urllib.request.Request(url, data=data, headers={'User-Agent': 'EuropeOSINTPersonalMonitor/3.0', 'Accept': 'application/rss+xml, application/xml, application/json, */*'})
    with urllib.request.urlopen(req, timeout=25) as resp:
        return resp.read(2_000_000)


def read_gdelt():
    params = urllib.parse.urlencode({'query': QUERY, 'mode': 'artlist', 'format': 'json', 'timespan': '24h', 'sort': 'datedesc', 'maxrecords': '150'})
    url = 'https://api.gdeltproject.org/api/v2/doc/doc?' + params
    for attempt in range(2):
        try:
            data = json.loads(get_bytes(url))
            rows = []
            for a in data.get('articles', []):
                dt = datetime.strptime(a['seendate'], '%Y%m%dT%H%M%SZ').replace(tzinfo=timezone.utc)
                rows.append({'title': a.get('title', ''), 'url': a.get('url', ''), 'date': dt, 'source': 'GDELT / ' + a.get('domain', 'presse')})
            return rows
        except urllib.error.HTTPError as ex:
            if ex.code != 429 or attempt == 1:
                raise
            print('GDELT limite les requêtes (429), nouvel essai après 35 s')
            time.sleep(35)
    return []


def read_rss(url, label):
    root = ET.fromstring(get_bytes(url))
    result = []
    for item in root.findall('.//item'):
        title = item.findtext('title', default='').strip()
        link = item.findtext('link', default='').strip()
        date = item.findtext('pubDate', default='').strip()
        if not date:
            continue
        try:
            dt = parsedate_to_datetime(date).astimezone(timezone.utc)
        except (TypeError, ValueError, IndexError):
            continue
        result.append({'title': title, 'url': link, 'date': dt, 'source': label})
    return result



# Recherches géographiques tournantes : incluent chaque localité du fichier.
# Deux groupes interrogés par exécution afin de limiter les erreurs 429.
def geo_search_groups():
    chunks = []
    for group in ('priority_countries', 'secondary_countries'):
        for country, aliases in CONFIG[group].items():
            # Variantes orthographiques contenues dans locations.json ; évite
            # les mots très courts qui provoquent trop de faux positifs.
            places = list(dict.fromkeys(
                x for x in aliases if len(norm(x).strip()) >= 4
            ))
            for i in range(0, len(places), 7):
                chunks.append((country, places[i:i+7]))
    marine = [x for x in CONFIG['maritime'] if len(norm(x).strip()) >= 5]
    for i in range(0, len(marine), 7):
        chunks.append(('Zones maritimes', marine[i:i+7]))
    return chunks


def read_geo_rss(country, places):
    # Intègre les lieux à la recherche, pas seulement au filtrage après collecte.
    place_query = ' OR '.join('"' + p.replace('"', '') + '"' for p in places)
    incident_query = '(drone OR missile OR attack OR strike OR explosion OR sabotage OR airspace OR terror OR bombing OR incursion)'
    query = '(' + place_query + ') ' + incident_query + ' when:1d'
    url = 'https://news.google.com/rss/search?' + urllib.parse.urlencode({
        'q': query, 'hl': 'en', 'gl': 'GB', 'ceid': 'GB:en'
    })
    return read_rss(url, 'Google News zones / ' + country)

def post_telegram(message):
    token = os.environ['TELEGRAM_BOT_TOKEN']
    chat_id = os.environ['TELEGRAM_CHAT_ID']
    payload = urllib.parse.urlencode({'chat_id': chat_id, 'text': message, 'disable_web_page_preview': 'true'}).encode()
    try:
        response = json.loads(get_bytes('https://api.telegram.org/bot' + token + '/sendMessage', payload))
        if not response.get('ok'):
            raise RuntimeError(response.get('description', 'Erreur Telegram'))
    except urllib.error.HTTPError as e:
        details = e.read().decode('utf-8', 'replace')[:400]
        raise RuntimeError(f'Telegram HTTP {e.code}: {details}') from None


def canonical(url):
    parsed = urllib.parse.urlsplit(url)
    return parsed.netloc.lower() + parsed.path.rstrip('/').lower()


def main():
    if os.environ.get('TEST_TELEGRAM', 'false').lower() == 'true':
        post_telegram('✅ TEST : Europe OSINT V3 connecté à Telegram.')
        print('Test Telegram transmis')
        return
    try:
        state = json.loads(STATE.read_text(encoding='utf-8')) if STATE.exists() else {}
    except (ValueError, OSError):
        state = {}
    seen = {k: v for k, v in state.get('seen', {}).items() if isinstance(v, (int, float)) and v >= NOW.timestamp() - 90*86400}
    sources_ok = 0
    errors = []
    articles = []
    # RSS prioritized even if GDELT is limited.
    for name, url in RSS.items():
        try:
            batch = read_rss(url, name)
            sources_ok += 1
            articles.extend(batch)
            print(f'OK {name}: {len(batch)} publications')
        except Exception as ex:
            errors.append(f'{name}: {ex}')
            print(f'ERREUR {name}: {ex}', file=sys.stderr)
    # Rotation de groupes géographiques : cycle complet sur plusieurs passages.
    # L'état ne dépend pas d'un cache GitHub pour la rotation.
    groups = geo_search_groups()
    tick = int(NOW.timestamp() // 1800)
    geo_count = min(2, len(groups))
    for offset in range(geo_count):
        idx = (tick * geo_count + offset) % len(groups)
        country, places = groups[idx]
        name = f'Geo {idx+1}/{len(groups)} {country}'
        try:
            batch = read_geo_rss(country, places)
            sources_ok += 1
            articles.extend(batch)
            print(f'OK {name}: {len(batch)} publications; lieux: {", ".join(places)}')
        except Exception as ex:
            errors.append(f'{name}: {ex}')
            print(f'ERREUR {name}: {ex}', file=sys.stderr)
        time.sleep(1)
    try:
        batch = read_gdelt()
        articles.extend(batch)
        sources_ok += 1
        print(f'OK GDELT: {len(batch)} publications')
    except Exception as ex:
        errors.append(f'GDELT: {ex}')
        print(f'ERREUR GDELT: {ex}', file=sys.stderr)

    if not sources_ok:
        raise RuntimeError('PANNE : aucun flux disponible. Aucune surveillance effective.')

    candidates = []
    batch_seen = set()
    for a in articles:
        if not a['url'] or not a['title'] or not NOW-timedelta(hours=LOOKBACK_HOURS) <= a['date'] <= NOW+timedelta(minutes=10):
            continue
        place, zone = geography(a['title'])
        if not place:
            continue
        title = a['title']
        if contains(title, P1):
            level = 'P1'
        elif contains(title, P2):
            level = 'P2'
        elif contains(title, P3):
            level = 'P3'
        else:
            continue
        key = hashlib.sha256(canonical(a['url']).encode()).hexdigest()
        if key in seen or key in batch_seen:
            continue
        batch_seen.add(key)
        candidates.append((key, level, place, zone, a))
    rank = {'P1': 0, 'P2': 1, 'P3': 2}
    candidates.sort(key=lambda x: (rank[x[1]], -x[4]['date'].timestamp()))
    print(f'Sources disponibles : {sources_ok}/{len(RSS)+1+geo_count}; groupes geographiques totaux : {len(groups)}; articles bruts : {len(articles)}; nouveaux candidats : {len(candidates)}')
    successes = 0
    for key, level, place, zone, a in candidates[:MAX_ALERTS]:
        emoji = {'P1': '🔴', 'P2': '🟠', 'P3': '🔵'}[level]
        message = (f'{emoji} VEILLE OSINT {level} — {place}\n\n{a["title"][:280]}\n\n'
                   f'Zone : {zone}\nSource : {a["source"]}\n'
                   f'Publication/indexation : {a["date"]:%Y-%m-%d %H:%M UTC}\n'
                   'Heure de l’événement : non établie\n'
                   'Statut : publication détectée ; événement et auteur NON vérifiés\n'
                   f'{a["url"]}')
        post_telegram(message)
        seen[key] = NOW.timestamp()
        successes += 1
        time.sleep(0.3)
    state = {'seen': seen, 'last_run_utc': NOW.isoformat(), 'sources_ok': sources_ok, 'errors': errors, 'last_articles': len(articles), 'last_sent': successes}
    STATE.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding='utf-8')
    print(f'NOTIFICATIONS ENVOYÉES : {successes}')
    if errors:
        print('ATTENTION : sources partielles indisponibles : ' + '; '.join(errors))


if __name__ == '__main__':
    main()
