#!/usr/bin/env python3
"""
unified_events.py

Scraper with site-specific fallbacks and improved filtering + session retries.
Generates JSON and ICS files.
"""
from __future__ import annotations
import argparse
import json
import sys
from typing import List, Dict, Any, Optional, Tuple
import requests
from requests.adapters import HTTPAdapter
from urllib.parse import urljoin, urlparse
from requests.packages.urllib3.util.retry import Retry
from bs4 import BeautifulSoup
import dateparser
from dateparser.search import search_dates
from datetime import datetime
import uuid
from icalendar import Calendar, Event as ICalEvent
import re

USER_AGENT = "rome-events-bot/1.0"

NAV_TEXT_BLACKLIST = {
    "navigazione principale", "cerca", "cerca un evento", "eventi passati",
    "vedi tutti", "carica altro", "leggi di più", "home", "contatti", "programma",
    "navigazione", "menu"
}
TITLE_BLACKLIST_KEYWORDS = [
    "archive", "archives", "stagione", "accessibil", "news", "contatt", "privacy",
    "biglietteria", "fondaz", "archiv", "home", "youtube", "spotify", "eventi |",
]
URL_PATH_BLACKLIST = ["/contatti", "/app/uploads", "/comunicazione", "/privacy", "/contatto", "/dove-siamo"]

# session with retries
SESSION = requests.Session()
retries = Retry(total=2, backoff_factor=0.5, status_forcelist=[429,500,502,503,504])
SESSION.mount("https://", HTTPAdapter(max_retries=retries))
SESSION.mount("http://", HTTPAdapter(max_retries=retries))
SESSION.headers.update({
    "User-Agent": USER_AGENT,
    "Accept-Language": "it-IT,it;q=0.9,en;q=0.8"
})

DEFAULT_TIMEOUT = 8

def fetch_html(url: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    resp = SESSION.get(url, timeout=timeout)
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
        if isinstance(v, datetime):
            return v
        dt = dateparser.parse(str(v), languages=['it'], settings={'PREFER_DATES_FROM': 'future'})
        return dt
    except Exception:
        return None

def find_dates_in_text(text: str) -> List[datetime]:
    try:
        found = search_dates(text, languages=['it'], settings={'PREFER_DATES_FROM': 'future'})
        if not found:
            return []
        dts = [t for (_, t) in found]
        return dts
    except Exception:
        patterns = [
            r"\d{1,2}\s+[A-Za-zàèéìòù]{3,}\s+\d{4}",
            r"\d{4}-\d{2}-\d{2}",
            r"\d{1,2}/\d{1,2}/\d{2,4}",
            r"\b\d{1,2}:\d{2}\b",
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
    if len(t) < 3:
        return True
    for bad in NAV_TEXT_BLACKLIST:
        if bad in t:
            return True
    return False

def sensible_event_href(base: str, href: str) -> bool:
    if not href:
        return False
    full = urljoin(base, href)
    p = urlparse(full).path
    segs = [s for s in p.split("/") if s]
    if len(segs) <= 1:
        return False
    if any(k in p.lower() for k in ("/event/", "/evento", "/eventi/", "/events/")):
        return True
    return len(segs) >= 2

def get_title_from_detail(soup: BeautifulSoup, fallback_text: Optional[str]) -> str:
    meta_props = [
        ("property", "og:title"),
        ("name", "twitter:title"),
        ("name", "headline"),
        ("name", "title"),
    ]
    for attr, val in meta_props:
        m = soup.find("meta", attrs={attr: val})
        if m and m.get("content"):
            t = m["content"].strip()
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
    selectors = [".event-title", ".evento-title", ".post-title", ".entry-title", ".single-event .title", ".page-title", ".titolo", ".title"]
    for sel in selectors:
        el = soup.select_one(sel)
        if el and el.get_text(strip=True):
            t = el.get_text(strip=True)
            if t and not is_nav_text(t):
                return t
    if fallback_text and not is_nav_text(fallback_text):
        return fallback_text.strip()
    return ""

# site parsers with reduced caps
def parse_teatrodiroma(html: str, base_url: str) -> List[Dict[str, Any]]:
    soup = BeautifulSoup(html, "html.parser")
    events: List[Dict[str, Any]] = []
    candidates = []
    for a in soup.find_all("a", href=True):
        href = a["href"]
        if sensible_event_href(base_url, href) and not is_nav_text(a.get_text()):
            candidates.append(urljoin(base_url, href))
    for card in soup.select("[class*='evento'], [class*='card'], [class*='calendar']"):
        a = card.find("a", href=True)
        if a and sensible_event_href(base_url, a["href"]) and not is_nav_text(a.get_text()):
            candidates.append(urljoin(base_url, a["href"]))
    candidates = list(dict.fromkeys(candidates))
    for url in candidates[:30]:
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
    for a in soup.find_all("a", href=True):
        href = a["href"]
        full = urljoin(base_url, href)
        if sensible_event_href(base_url, href):
            text = (a.get_text() or "").strip()
            if is_nav_text(text):
                continue
            path = urlparse(full).path
            if any(path.lower().startswith(p) for p in ["/it/event", "/en/event"]) and path.rstrip("/") in ["/it/event", "/en/event"]:
                continue
            candidates.append(full)
    candidates = list(dict.fromkeys(candidates))
    for url in candidates[:30]:
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
    for url, anchor_text in candidates[:50]:
        try:
            detail = fetch_html(url)
        except Exception as e:
            print(f"[WARN] casadeljazz detail fetch failed {url}: {e}", file=sys.stderr)
            continue
        if len(detail) < 1500:
            print(f"[WARN] casadeljazz detail seems too short (len={len(detail)}), skipping {url}", file=sys.stderr)
            continue
        soupd = BeautifulSoup(detail, "html.parser")
        raw_events = extract_jsonld_events(detail)
        if raw_events:
            for re in raw_events:
                events.append(normalize_event(re, url))
            continue
        title = get_title_from_detail(soupd, anchor_text)
        if not title:
            snippet = soupd.get_text(" ", strip=True)[:400]
            print(f"[DEBUG] casadeljazz no title for {url}. Snippet: {snippet}", file=sys.stderr)
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

# main collector and post-filtering
def post_filter_events(events: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    filtered: List[Dict[str, Any]] = []
    for e in events:
        title = (e.get('title') or '').strip()
        title_l = title.lower()
        url = e.get('url') or ''
        path = urlparse(url).path.lower()
        source = (e.get('source') or '').lower()

        # drop obvious non-html resources
        if path.endswith('.pdf') or path.endswith('.jpg') or path.endswith('.png') or path.endswith('.jpeg'):
            print(f"[DEBUG] dropping non-html resource: {url}", file=sys.stderr)
            continue

        # path blacklist (general)
        if any(p in path for p in URL_PATH_BLACKLIST):
            print(f"[DEBUG] dropping by path blacklist: {url}", file=sys.stderr)
            continue

        # drop titles containing generic keywords
        if any(k in title_l for k in TITLE_BLACKLIST_KEYWORDS):
            print(f"[DEBUG] dropping by title keyword: {title} ({url})", file=sys.stderr)
            continue

        # drop titles that look like page headers e.g. "Eventi | Auditorium..."
        if '|' in title and ('auditorium' in title_l or 'teatro' in title_l):
            print(f"[DEBUG] dropping by pipe-title pattern: {title} ({url})", file=sys.stderr)
            continue

        # If no start date, apply stricter site-specific heuristics
        if not e.get('start'):
            # Teatro di Roma: allow if path looks like spettacoli or progetto/evento pages
            if 'teatrodiroma' in source:
                if not any(p in path for p in ['/spettacoli/', '/spettacoli', '/progetti/', '/progetto/', '/eventi/', '/evento/']):
                    print(f"[DEBUG] dropping teatro link without date: {url}", file=sys.stderr)
                    continue
            # Auditorium: allow only if path looks like an event/detail page
            if 'auditorium.com' in source:
                if not any(p in path for p in ['/event/', '/it/event/', '/en/event/', '/eventi/', '/evento/']):
                    print(f"[DEBUG] dropping auditorium link without date: {url}", file=sys.stderr)
                    continue
            # Casa del Jazz: be lenient (many event pages are OK) — keep for now
        # if passes all checks, keep it
        filtered.append(e)
    return filtered

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
            soup = BeautifulSoup(html, "html.parser")
            links = []
            for a in soup.find_all("a", href=True):
                if sensible_event_href(url, a["href"]) and not is_nav_text(a.get_text()):
                    links.append(urljoin(url, a["href"]))
            links = list(dict.fromkeys(links))
            for l in links[:50]:
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
    print(f"[INFO] total raw events before post-filter: {len(all_events)}", file=sys.stderr)
    filtered = post_filter_events(all_events)
    print(f"[INFO] total events after post-filter: {len(filtered)}", file=sys.stderr)
    return filtered

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



