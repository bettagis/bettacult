import sys
import os
sys.path.append(os.path.dirname(__file__))
import os
import re
import json
import requests
from bs4 import BeautifulSoup
from typing import List, Dict, Any, Optional
from urllib.parse import urljoin
import uuid
from datetime import datetime, timedelta
from dateutil import parser as dateutil_parser


# Config
URLS_FILE = "scraper/urls.txt"
OUTPUT_PATH = "site/events.json"
EXCLUDE_PATTERNS = ["/progetti/", "casadeljazz", "auditorium"]

def is_excluded(url: str) -> bool:
    url = url.lower()
    return any(p in url for p in EXCLUDE_PATTERNS)

def read_urls(path: str) -> List[str]:
    urls = []
    with open(path, encoding="utf-8") as f:
        for line in f:
            line = line.strip()
            if line and not line.startswith("#"):
                urls.append(line)
    return urls

def extract_jsonld_events(soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
    events = []
    for script in soup.find_all("script", type="application/ld+json"):
        try:
            data = json.loads(script.string)
            if isinstance(data, list):
                for e in data:
                    if isinstance(e, dict) and (e.get("@type") == "Event" or e.get("@type") == "TheaterEvent"):
                        e["source_url"] = base_url
                        events.append(e)
            elif isinstance(data, dict):
                if data.get("@type") == "Event" or data.get("@type") == "TheaterEvent":
                    data["source_url"] = base_url
                    events.append(data)
                elif "event" in data and isinstance(data["event"], list):
                    for e in data["event"]:
                        if isinstance(e, dict):
                            e["source_url"] = base_url
                            events.append(e)
        except Exception as ex:
            print(f"[WARN] Impossibile fare parse JSON-LD in {base_url}: {ex}")
    return events

def fallback_extract_events(soup: BeautifulSoup, base_url: str) -> List[Dict[str, Any]]:
    events = []
    cards = soup.find_all("div", class_=re.compile("card|evento|event-item|spettacolo", re.I))
    for card in cards:
        title = card.find("h2") or card.find("h3")
        desc = card.find("p")
        start = card.find("time")
        link = card.find("a", href=True)
        raw = {
            "name": title.text.strip() if title else "",
            "description": desc.text.strip() if desc else "",
            "startDate": start["datetime"] if start and start.has_attr("datetime") else "",
            "url": urljoin(base_url, link["href"]) if link else base_url,
        }
        events.append(raw)
    return events

def parse_date_to_dt(date_str: Optional[str]) -> Optional[datetime]:
    if not date_str or not isinstance(date_str, str):
        return None
    try:
        return dateutil_parser.parse(date_str)
    except (ValueError, TypeError):
        return None

def normalize_event(raw: Dict[str, Any], source_url: str) -> Dict[str, Any]:
    title = raw.get("name") or raw.get("headline") or ""
    now = datetime.now()
    start_val = raw.get("startDate") or raw.get("start") or (raw.get("raw", {}).get("startDate") if isinstance(raw.get("raw"), dict) else None)
    end_val = raw.get("endDate") or raw.get("end") or (raw.get("raw", {}).get("endDate") if isinstance(raw.get("raw"), dict) else None)

    if not start_val or not isinstance(start_val, str) or len(start_val) < 8:
        desc = raw.get("description", "")
        if not desc and isinstance(raw.get("raw"), dict):
            desc = raw["raw"].get("description", "")
        from utils_date_parsing import extract_dates_from_desc
        try:
            dates = extract_dates_from_desc(desc)
        except Exception:
            dates = []
        if dates:
            start_val = dates[0].isoformat()
            end_val = dates[-1].isoformat() if len(dates) > 1 else None
        else:
            # Fallback legacy: usa ancora dateparser solo se la funzione custom non trova nulla
            from dateparser.search import search_dates
            try:
                found = search_dates(desc, languages=['it'], settings={'PREFER_DATES_FROM': 'future'})
                dates = [t for (_, t) in found or [] if isinstance(t, datetime)]
                if dates:
                    start_val = dates[0].isoformat()
                    end_val = dates[-1].isoformat() if len(dates) > 1 else None
                else:
                    start_val = None
                    end_val = None
            except Exception:
                start_val = None
                end_val = None

    start_dt = parse_date_to_dt(start_val)
    end_dt = parse_date_to_dt(end_val)
    if start_dt and start_dt.year > 2100:
        start_dt = None
    if end_dt and end_dt.year > 2100:
        end_dt = None
    if start_dt and end_dt:
        date_diff = (end_dt - start_dt).days
        if date_diff < 0 or date_diff > 15:
            end_dt = None
    description = raw.get("description") or ""
    url = raw.get("url") or raw.get("sameAs") or raw.get("mainEntityOfPage") or raw.get("@id") or source_url
    location_raw = raw.get("location") or {}
    if isinstance(location_raw, str):
        location = {"name": location_raw, "address": None}
    else:
        loc_name = None
        loc_address = None
        if isinstance(location_raw, dict):
            loc_name = location_raw.get("name")
            address = location_raw.get("address")
            if isinstance(address, dict):
                addr_parts = []
                for k in ("streetAddress", "postalCode", "addressLocality", "addressRegion", "addressCountry"):
                    v = address.get(k)
                    if v:
                        addr_parts.append(v)
                loc_address = ", ".join(addr_parts) if addr_parts else None
            elif isinstance(address, str):
                loc_address = address
        location = {"name": loc_name, "address": loc_address}
    uid_source = f"{source_url}|{title}|{start_dt.isoformat() if start_dt else ''}"
    uid = str(uuid.uuid5(uuid.NAMESPACE_URL, uid_source))
    return {
        "id": uid,
        "title": title,
        "start": start_dt.isoformat() if start_dt else None,
        "end": end_dt.isoformat() if end_dt else None,
        "description": description,
        "location": location,
        "url": url,
        "source": source_url,
        "raw": raw
    }

def main():
    os.makedirs(os.path.dirname(OUTPUT_PATH), exist_ok=True)
    all_events = []
    urls = read_urls(URLS_FILE)
    for url in urls:
        print(f"[INFO] Parsing {url}")
        try:
            r = requests.get(url, timeout=20)
            r.raise_for_status()
            soup = BeautifulSoup(r.text, "html.parser")
            events = extract_jsonld_events(soup, url)
            if not events:
                print(f"[WARN] Nessun evento JSON-LD, provo fallback HTML su {url}")
                events = fallback_extract_events(soup, url)
            print(f"[INFO] {len(events)} eventi grezzi trovati in {url}")
            for e in events:
                try:
                    event_url = e.get("url") or e.get("sameAs") or e.get("mainEntityOfPage") or ""
                    if is_excluded(event_url):
                        continue
                    norm = normalize_event(e, url)
                    if norm["title"] and norm["start"]:
                        all_events.append(norm)
                except Exception as ex2:
                    print(f"[WARN] Normalize fallito su evento in {url}: {ex2}")
        except Exception as ex:
            print(f"[ERROR] Parse fallita per {url}: {ex}")

    with open(OUTPUT_PATH, "w", encoding="utf-8") as f:
        json.dump(all_events, f, ensure_ascii=False, indent=2)
    print(f"Salvati {len(all_events)} eventi totali in {OUTPUT_PATH}")

if __name__ == "__main__":
    main()
