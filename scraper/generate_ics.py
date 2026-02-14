import json
from icalendar import Calendar, Event
from datetime import datetime

INPUT_JSON = "site/events.json"
OUTPUT_ICS = "site/events.ics"

def parse_datetime(value):
    try:
        return datetime.fromisoformat(value)
    except:
        try:
            return datetime.strptime(value[:10], "%Y-%m-%d")
        except:
            return None

with open(INPUT_JSON, encoding="utf-8") as f:
    events = json.load(f)

cal = Calendar()
cal.add('prodid', '-//Bettacult//Unified Events Calendar//IT')
cal.add('version', '2.0')

added = 0
for e in events:
    if not e.get('start'):
        continue
    dtstart = parse_datetime(e['start'])
    if not dtstart:
        continue
    evt = Event()
    evt.add('summary', e['title'])
    evt.add('dtstart', dtstart)
    if e.get('end'):
        dtend = parse_datetime(e['end'])
        if dtend:
            evt.add('dtend', dtend)
    evt.add('description', e.get('description', ''))
    loc = e.get('location', {})
    evt.add('location', (loc.get('name') or '') + (" - " + loc.get('address') if loc.get('address') else ''))
    evt.add('url', e.get('url', ''))
    cal.add_component(evt)
    added += 1

with open(OUTPUT_ICS, "wb") as f:
    f.write(cal.to_ical())

print(f"ICS generato: {OUTPUT_ICS} con {added} eventi.")
