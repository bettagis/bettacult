from typing import Dict, Any, Optional
import uuid
from datetime import datetime, timedelta
from dateutil import parser as dateutil_parser


def parse_date_to_dt(date_str: Optional[str]) -> Optional[datetime]:
    """Parse a date string to a datetime object, or return None if invalid."""
    if not date_str or not isinstance(date_str, str):
        return None
    try:
        return dateutil_parser.parse(date_str)
    except (ValueError, TypeError):
        return None


def normalize_event(raw: Dict[str, Any], source_url: str) -> Dict[str, Any]:
    title = raw.get("name") or raw.get("headline") or ""
    now = datetime.now()
    # Fallbacks: get start and end from common keys or from raw.dict
    start_val = raw.get("startDate") or raw.get("start") or (raw.get("raw", {}).get("startDate") if isinstance(raw.get("raw"), dict) else None)
    end_val = raw.get("endDate") or raw.get("end") or (raw.get("raw", {}).get("endDate") if isinstance(raw.get("raw"), dict) else None)

    # If missing or suspiciously ambiguous
    if not start_val or not isinstance(start_val, str) or len(start_val) < 8:
        desc = raw.get("description", "")
        if not desc and isinstance(raw.get("raw"), dict):
            desc = raw["raw"].get("description", "")
        from dateparser.search import search_dates
        try:
            found = search_dates(desc, languages=['it'], settings={'PREFER_DATES_FROM': 'future'})
            # Keep only dates that are not too far from today
            dates = [t for (_, t) in found or [] if isinstance(t, datetime) and now - timedelta(days=2) < t < now + timedelta(days=366)]
            if dates:
                start_val = dates[0].isoformat()
                # Use end_val only if close to start date (range < 15 days)
                if len(dates) > 1 and (dates[1] - dates[0]).days < 15:
                    end_val = dates[1].isoformat()
                else:
                    end_val = None
        except Exception:
            pass

    start_dt = parse_date_to_dt(start_val)
    end_dt = parse_date_to_dt(end_val)
    
    # Validate dates: set to None if year > 2100 (unrealistic future dates beyond expected horizon)
    if start_dt and start_dt.year > 2100:
        start_dt = None
    if end_dt and end_dt.year > 2100:
        end_dt = None
    
    # Validate end_dt: set to None if difference is negative or exceeds 15 days (typical event duration limit)
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
        "start_dt": start_dt,
        "end_dt": end_dt,
        "description": description,
        "location": location,
        "url": url,
        "source": source_url,
        "raw": raw
    }