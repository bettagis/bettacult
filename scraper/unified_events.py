def post_filter_events(events):
    """Filters out events that have external ticketing links and processes events from Casadeljazz."""
    filtered_events = []
    for event in events:
        # Check if the event is from Casadeljazz
        if "casadeljazz" in event.get("host", ""):
            # Further filtering logic can be applied here
            filtered_events.append(event)
        elif not any(link for link in event.get("ticket_links", []) if "external" in link):
            filtered_events.append(event)
    return filtered_events
