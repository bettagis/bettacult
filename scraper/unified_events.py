#!/usr/bin/env python3
"""
unified_events.py

Estende l'estrazione aggiungendo miglioramenti:
 - filtro più accurato dei link (evita link di navigazione)
 - estrazione titolo più robusta (meta og:title, <title>, h1/h2, selettori 'title')
 - parsing date con dateparser (supporto italiano)
 - pattern più larghi per teatrodiroma
"""
from __future__ import annotations
import argparse
import json
import sys
from typing import List, Dict, Any, Optional, Tuple
import requests
from bs4 import BeautifulSoup
import dateparser
from dateparser.search import search_dates
from datetime import datetime
import uuid
from icalendar import Calendar, Event as ICalEvent
import re
from urllib.parse import urljoin, urlparse

USER_AGENT = "rome-events-bot/1.0"

NAV_TEXT_BLACKLIST = {
    "navigazione principale", "cerca", "cerca un evento", "eventi passati",
    "vedi tutti", "carica altro", "leggi di più", "home", "contatti", "programma"
}

def fetch_html(url: str, timeout: int = 15) -> str:
    resp = requests.get(url, timeout=timeout, headers={"User-Agent": USER_AGENT})
    resp.raise_for_status()
    return resp.text

def extract_jsonld_events(html: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    scripts = soup.find_all("script", {"type": "application/ld+json"})
    events: List[Dict[str, Any]] = []
    for s in scripts:
        text = s.string or s.get_text() or ""
        try:
            data = json.loads(text)
        except Exception:
            continue
        candidates = data if isinstance(data, list) else [data]
        for item in candidates:
            if not item:
                continue
            typ = item.get("@type") or item.get("type")
            if typ:
                if isinstance(typ, list):
                    is_event = "Event" in typ
                else:
                    is_event = typ == "Event"
            else:
                is_event = False
            if is_event or item.get("event") is not None:
                events.append(item)
            elif any(k in item for k in ("startDate", "endDate", "location", "name")):
                events.append(item)
    return events

def parse_date_to_dt(v: Any) -> Optional[datetime]:
    if not v:
        return None
    try:
        # dateparser gestisce bene le date in italiano
        if isinstance(v, datetime):
            return v
        dt = dateparser.parse(str(v), languages=['it'], settings={'PREFER_DATES_FROM': 'future'})
        return dt
    except Exception:
        return None

def find_dates_in_text(text: str) -> List[datetime]:
    # usa dateparser.search.search_dates per trovare date nel testo (lingua italiana)
    try:
        found = search_dates(text, languages=['it'], settings={'PREFER_DATES_FROM': 'future'})
        if not found:
            return []
        # search_dates returns list of (matched_text, datetime)
        dts = [t for (_, t) in found]
        return dts
    except Exception:
        # fallback: regex lookups basilari
        patterns = [
            r"\d{1,2}\s+[A-Za-zàèéìòù]{3,}\s+\d{4}",  # 12 Marzo 2026
            r"\d{4}-\d{2}-\d{2}",
            r"\d{1,2}/\d{1,2}/\d{2,4}",
        ]
        dates = []
        for pat in patterns:
            for m in re.finditer(pat, text, flags=re.IGNORECASE):
                dt = parse_date_to_dt(m.group(0))
                if dt:
                    dates.append(dt)
        return dates

def normalize_event(raw: Dict[str, Any], source_url: str) -> Dict[str, Any]:
    title = raw.get("name") or raw.get("headline") or ""
    start_dt = parse_date_to_dt(raw.get("startDate") or raw.get("start"))
    end_dt = parse_date_to_dt(raw.get("endDate") or raw.get("end"))
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
        "start_dt": start_dt,
        "end_dt": end_dt,
        "description": description,
        "location": location,
        "url": url,
        "source": source_url,
        "raw": raw
    }

def is_nav_text(text: str) -> bool:
    if not text:
        return False
    t = text.strip().lower()
    # too short or blacklisted
    if len(t) < 3:
        return True
    for bad in NAV_TEXT_BLACKLIST:
        if bad in t:
            return True
    return False

def sensible_event_href(base: str, href: str) -> bool:
    # scarta link esterni o link generici della stessa base senza slug utile
    if not href:
        return False
    full = urljoin(base, href)
    p = urlparse(full).path
    # scarta link troppo generici (es. /it/event/ senza slug)
    segs = [s for s in p.split("/") if s]
    if len(segs) <= 1:
        return False
    # preferisci percorsi che contengano 'event' o 'evento' o che abbiano sufficiente profondità
    if any(k in p.lower() for k in ("/event/", "/evento", "/eventi/", "/events/")):
        # escludi query o anchor che rimandano a filtri di navigazione
        return True
    # fallback: accetta se path ha almeno 2 segmenti (molti siti usano /anno/mese/slug)
    return len(segs) >= 2

def get_title_from_detail(soup: BeautifulSoup, fallback_text: Optional[str]) -> str:
    # priorità: meta og:title, meta name=title, <title>, h1/h2, elementi con class 'title' o 'entry-title', fallback_text
    og = soup.find("meta", property="og:title")
    if og and og.get("content"):
        t = og["content"].strip()
        if t and not is_nav_text(t):
            return t
    nm = soup.find("meta", attrs={"name": "title"})
    if nm and nm.get("content"):
        t = nm["content"].strip()
        if t and not is_nav_text(t):
            return t
    head_title = soup.find("title")
    if head_title and head_title.get_text(strip=True):
        t = head_title.get_text(strip=True)
        if t and not is_nav_text(t):
            return t
    for tag in ("h1","h2"):
        el = soup.find(tag)
        if el and el.get_text(strip=True):
            t = el.get_text(strip=True)
            if t and not is_nav_text(t):
                return t
    # cerca elementi con class che contiene 'title' o 'titolo' o 'entry-title'
    el = soup.select_one("[class*='title'], [class*='titolo'], .entry-title")
    if el and el.get_text(strip=True):
        t = el.get_text(strip=True)
        if t and not is_nav_text(t):
            return t
    # fallback al testo di ancoraggio se non è navigazione
    if fallback_text and not is_nav_text(fallback_text):
        return fallback_text.strip()
    return ""

# --- site-specific parsers ---
def parse_teatrodiroma(html: str, base_url: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    events: List[Dict[str, Any]] = []
    candidates = []
    # cerca link che sembrano eventi e bottoni/elementi con class 'evento' o 'calendar'
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if sensible_event_href(base_url, href) and not is_nav_text(a.get_text()):
            candidates.append(urljoin(base_url, href))
    # anche cerca elementi con class contenente 'evento' o 'card'
    for card in soup.select("[class*='evento'], [class*='card'], [class*='calendar']"):
        a = card.find("a", href=True)
        if a and sensible_event_href(base_url, a["href"]) and not is_nav_text(a.get_text()):
            candidates.append(urljoin(base_url, a["href"]))
    candidates = list(dict.fromkeys(candidates))
    for url in candidates[:120]:
        try:
            detail = fetch_html(url)
        except Exception as e:
            print(f"[WARN] teatro detail fetch failed {url}: {e}", file=sys.stderr)
            continue
        raw_events = extract_jsonld_events(detail)
        if raw_events:
            for re in raw_events:
                events.append(normalize_event(re, url))
            continue
        soupd = BeautifulSoup(detail, "html.parser")
        title = get_title_from_detail(soupd, None)
        text = soupd.get_text(" ", strip=True)
        dts = find_dates_in_text(text)
        raw = {"name": title or "", "description": ""}
        if dts:
            raw["startDate"] = dts[0].isoformat()
            if len(dts) > 1:
                raw["endDate"] = dts[1].isoformat()
        raw["url"] = url
        events.append(normalize_event(raw, url))
    return events

def parse_auditorium(html: str, base_url: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    events: List[Dict[str, Any]] = []
    candidates = []
    # raccogli link che contengono '/it/event/' oppure '/event/' e che abbiano slug
    for a in soup.find_all("a", href=True):
        href = a["href"]
        full = urljoin(base_url, href)
        if sensible_event_href(base_url, href):
            # scarta anchor chiaramente di navigazione
            text = (a.get_text() or "").strip()
            if is_nav_text(text):
                continue
            # scarta la pagina generica /it/event/ senza slug
            path = urlparse(full).path
            if path.rstrip("/").lower().endswith("/it/event"):
                continue
            candidates.append(full)
    candidates = list(dict.fromkeys(candidates))
    for url in candidates[:150]:
        try:
            detail = fetch_html(url)
        except Exception as e:
            print(f"[WARN] auditorium detail fetch failed {url}: {e}", file=sys.stderr)
            continue
        raw_events = extract_jsonld_events(detail)
        if raw_events:
            for re in raw_events:
                events.append(normalize_event(re, url))
            continue
        soupd = BeautifulSoup(detail, "html.parser")
        title = get_title_from_detail(soupd, "")
        text = soupd.get_text(" ", strip=True)
        dts = find_dates_in_text(text)
        raw = {"name": title or "", "description": ""}
        if dts:
            raw["startDate"] = dts[0].isoformat()
            if len(dts) > 1:
                raw["endDate"] = dts[1].isoformat()
        raw["url"] = url
        events.append(normalize_event(raw, url))
    return events

def parse_casadeljazz(html: str, base_url: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    events: List[Dict[str, Any]] = []
    candidates: List[Tuple[str,str]] = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        text = (a.get_text() or "").strip()
        if sensible_event_href(base_url, href) and not is_nav_text(text):
            candidates.append((urljoin(base_url, href), text))
    candidates = list(dict.fromkeys(candidates))
    for url, anchor_text in candidates[:120]:
        try:
            detail = fetch_html(url)
        except Exception as e:
            print(f"[WARN] casadeljazz detail fetch failed {url}: {e}", file=sys.stderr)
            continue
        soupd = BeautifulSoup(detail, "html.parser")
        raw_events = extract_jsonld_events(detail)
        if raw_events:
            for re in raw_events:
                events.append(normalize_event(re, url))
            continue
        title = get_title_from_detail(soupd, anchor_text)
        text = soupd.get_text(" ", strip=True)
        dts = find_dates_in_text(text)
        raw = {"name": title or "", "description": ""}
        if dts:
            raw["startDate"] = dts[0].isoformat()
            if len(dts) > 1:
                raw["endDate"] = dts[1].isoformat()
        raw["url"] = url
        events.append(normalize_event(raw, url))
    return events

# --- Main collector with fallback ---
def collect_from_urls(urls: List[str]) -> List[Dict[str, Any]]:
    all_events: List[Dict[str, Any]] = []
    for url in urls:
        print(f"[INFO] processing {url}", file=sys.stderr)
        try:
            html = fetch_html(url)
        except Exception as e:
            print(f"[WARN] failed to fetch {url}: {e}", file=sys.stderr)
            continue
        raw_events = extract_jsonld_events(html)
        if raw_events:
            print(f"[INFO] found {len(raw_events)} JSON-LD events on {url}", file=sys.stderr)
            for re in raw_events:
                ev = normalize_event(re, url)
                ev["source"] = url
                all_events.append(ev)
            continue
        parsed = []
        hostname = urlparse(url).netloc.lower()
        if "teatrodiroma" in hostname:
            parsed = parse_teatrodiroma(html, url)
        elif "auditorium" in hostname:
            parsed = parse_auditorium(html, url)
        elif "casadeljazz" in hostname or "casajazz" in hostname:
            parsed = parse_casadeljazz(html, url)
        else:
            # generic fallback: cerca link contenenti 'event' e prova i dettagli
            soup = BeautifulSoup(html, "html.parser")
            links = []
            for a in soup.find_all("a", href=True):
                if sensible_event_href(url, a["href"]) and not is_nav_text(a.get_text()):
                    links.append(urljoin(url, a["href"]))
            links = list(dict.fromkeys(links))
            for l in links[:80]:
                try:
                    det = fetch_html(l)
                except Exception as e:
                    print(f"[WARN] generic detail fetch failed {l}: {e}", file=sys.stderr)
                    continue
                revents = extract_jsonld_events(det)
                if revents:
                    for re in revents:
                        parsed.append(normalize_event(re, l))
                else:
                    soupd = BeautifulSoup(det, "html.parser")
                    title = get_title_from_detail(soupd, "")
                    text = soupd.get_text(" ", strip=True)
                    dts = find_dates_in_text(text)
                    raw = {"name": title or "", "description": ""}
                    if dts:
                        raw["startDate"] = dts[0].isoformat()
                        if len(dts) > 1:
                            raw["endDate"] = dts[1].isoformat()
                    raw["url"] = l
                    parsed.append(normalize_event(raw, l))
        if parsed:
            print(f"[INFO] parsed {len(parsed)} events via fallback on {url}", file=sys.stderr)
            for e in parsed:
                e["source"] = url
                all_events.append(e)
        else:
            print(f"[INFO] no JSON-LD events and no fallback events found on {url}", file=sys.stderr)
    return all_events

def save_json(events: List[Dict[str, Any]], outpath: str) -> None:
    serializable = []
    for e in events:
        obj = {k: v for k, v in e.items() if k not in ("start_dt", "end_dt")}
        serializable.append(obj)
    with open(outpath, "w", encoding="utf-8") as f:
        json.dump({"events": serializable}, f, ensure_ascii=False, indent=2)
    print(f"[OK] saved {len(events)} events to {outpath}")

def save_ics(events: List[Dict[str, Any]], outpath: str) -> None:
    cal = Calendar()
    cal.add("prodid", "-//rome-events-calendar//example//IT")
    cal.add("version", "2.0")
    now = datetime.utcnow()
    added = 0
    for e in events:
        dtstart = e.get("start_dt")
        if not dtstart:
            continue
        dtend = e.get("end_dt")
        ve = ICalEvent()
        ve.add("uid", e["id"])
        ve.add("dtstamp", now)
        ve.add("dtstart", dtstart)
        if dtend:
            ve.add("dtend", dtend)
        ve.add("summary", e.get("title") or "")
        desc_parts = []
        if e.get("description"):
            desc_parts.append(e["description"])
        desc_parts.append(f"Fonte: {e.get('source')}")
        if e.get("url"):
            desc_parts.append(f"URL: {e.get('url')}")
        ve.add("description", "\n".join(desc_parts))
        loc_name = e.get("location", {}).get("name")
        loc_addr = e.get("location", {}).get("address")
        if loc_name or loc_addr:
            ve.add("location", ", ".join(p for p in (loc_name, loc_addr) if p))
        cal.add_component(ve)
        added += 1
    with open(outpath, "wb") as f:
        f.write(cal.to_ical())
    print(f"[OK] saved {added} events to {outpath} (ICS)")

def parse_args(argv: List[str]) -> argparse.Namespace:
    p = argparse.ArgumentParser(description="Scrape events from pages exposing JSON-LD (schema.org/Event)")
    p.add_argument("urls", nargs="*", help="URL(s) da cui estrarre eventi (opzionale se usi --urls-file)")
    p.add_argument("--urls-file", help="File con una URL per riga")
    p.add_argument("--output-json", "-j", default="events.json", help="Percorso file di output JSON (default: ./events.json)")
    p.add_argument("--output-ics", "-c", default="events.ics", help="Percorso file di output ICS (default: ./events.ics)")
    return p.parse_args(argv)

def main(argv: List[str]) -> int:
    args = parse_args(argv)
    urls: List[str] = []
    if args.urls_file:
        try:
            with open(args.urls_file, "r", encoding="utf-8") as f:
                for line in f:
                    line = line.strip()
                    if line:
                        urls.append(line)
        except Exception as e:
            print(f"[ERROR] cannot read urls file {args.urls_file}: {e}", file=sys.stderr)
            return 2
    if args.urls:
        urls.extend(args.urls)
    if not urls:
        print("[ERROR] nessuna URL fornita (passa URL come argomenti o usa --urls-file)", file=sys.stderr)
        return 1
    events = collect_from_urls(urls)
    # dedup by id
    dedup: Dict[str, Dict[str, Any]] = {}
    for e in events:
        dedup[e["id"]] = e
    events_unique = list(dedup.values())
    save_json(events_unique, args.output_json)
    save_ics(events_unique, args.output_ics)
    return 0

if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
