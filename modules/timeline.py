import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime


def _parse_date(date_str: str | None) -> datetime | None:
    """Try to parse a date string into a datetime object."""
    if not date_str:
        return None
    date_str = str(date_str)
    formats = [
        "%Y-%m-%dT%H:%M:%S.%fZ",
        "%Y-%m-%dT%H:%M:%SZ",
        "%Y-%m-%dT%H:%M:%S",
        "%Y-%m-%d",
        "%Y",
    ]
    for fmt in formats:
        try:
            return datetime.strptime(date_str, fmt)
        except (ValueError, TypeError):
            continue
    # Last-resort: try just the first 10 chars as YYYY-MM-DD
    try:
        return datetime.strptime(date_str[:10], "%Y-%m-%d")
    except (ValueError, TypeError):
        pass
    return None


def build_timeline(all_results: dict) -> list:
    """Build a chronological timeline from all OSINT findings."""
    events = []

    # Breach dates
    breach_data = all_results.get("breach", {})
    if isinstance(breach_data, dict):
        for b in breach_data.get("breach_names_with_dates", []):
            dt = _parse_date(b.get("date"))
            if dt:
                events.append({
                    "date": dt,
                    "date_str": b["date"],
                    "event": f"Data breach: {b['name']} ({b.get('domain', '')})",
                    "source": "HIBP",
                    "confidence": "CONFIRMED",
                    "type": "breach",
                })

    # GitHub join date
    for platform_entry in all_results.get("profile_enrichments", []):
        platform_name = platform_entry.get("platform", "").lower()
        enriched = platform_entry.get("enriched", {})
        join_date = enriched.get("join_date")
        dt = _parse_date(join_date)
        if dt:
            events.append({
                "date": dt,
                "date_str": str(join_date),
                "event": f"Account created on {platform_entry.get('platform', 'unknown platform')}",
                "source": platform_name,
                "confidence": "CONFIRMED",
                "type": "account_creation",
            })

    # Paste exposure dates
    paste_data = all_results.get("pastes", {})
    if isinstance(paste_data, dict):
        for paste in paste_data.get("pastes", []):
            dt = _parse_date(paste.get("Date"))
            if dt:
                events.append({
                    "date": dt,
                    "date_str": str(paste.get("Date", "")),
                    "event": f"Email in paste on {paste.get('Source', 'unknown')}",
                    "source": "HIBP Pastes",
                    "confidence": "PROBABLE",
                    "type": "paste",
                })

    # Sort chronologically
    events.sort(key=lambda x: x["date"])

    # Clean up: replace datetime objects with string representation
    for e in events:
        e["date"] = e.pop("date_str", str(e["date"].year))

    return events
