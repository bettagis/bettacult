# in normalize_event
if not start_val or not isinstance(start_val, str) or len(start_val) < 8:
    desc = raw.get("description", "")
    if not desc and isinstance(raw.get("raw"), dict):
        desc = raw["raw"].get("description", "")
    from utils_date_parsing import extract_dates_from_desc
    dates = extract_dates_from_desc(desc)
    if dates:
        start_val = dates[0].isoformat()
        end_val = dates[-1].isoformat() if len(dates) > 1 else None
    else:
        # Fallback legacy (se proprio non trova nulla)
        from dateparser.search import search_dates
        try:
            found = search_dates(desc, languages=['it'], settings={'PREFER_DATES_FROM': 'future'})
            dates = [t for (_, t) in found or [] if isinstance(t, datetime)]
            if dates:
                start_val = dates[0].isoformat()
                if len(dates) > 1:
                    end_val = dates[1].isoformat()
                else:
                    end_val = None
        except Exception:
            pass
