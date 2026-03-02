import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from config import HIBP_KEY, REQUEST_TIMEOUT, CACHE_TTL_HOURS, USER_AGENT
from cache_helper import cache_get, cache_set, init_db


async def check_hibp(email: str) -> dict:
    """Check HaveIBeenPwned for breach data."""
    if not HIBP_KEY:
        return {"error": "No HIBP API key configured", "tag": "UNAVAILABLE"}

    cache_key = f"breach:hibp:{email}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        url = f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}"
        headers = {
            "hibp-api-key": HIBP_KEY,
            "User-Agent": USER_AGENT,
        }
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers, params={"truncateResponse": "false"})
            if resp.status_code == 404:
                result = {"breaches": [], "count": 0, "tag": "CLEAN"}
            elif resp.status_code == 200:
                data = resp.json()
                summary = summarise_breaches(data)
                result = {"breaches": data, "tag": "CONFIRMED", **summary}
            elif resp.status_code == 401:
                result = {"error": "Invalid HIBP API key", "tag": "UNAVAILABLE"}
            elif resp.status_code == 429:
                result = {"error": "HIBP rate limit reached", "tag": "UNAVAILABLE"}
            else:
                result = {"error": f"HIBP returned {resp.status_code}", "tag": "UNAVAILABLE"}
    except httpx.TimeoutException:
        result = {"error": "Request timed out", "tag": "UNAVAILABLE"}
    except Exception as exc:
        result = {"error": str(exc), "tag": "UNAVAILABLE"}

    cache_set(cache_key, "breach", result, CACHE_TTL_HOURS)
    return result


async def check_pastes(email: str) -> dict:
    """Check HaveIBeenPwned for paste exposure."""
    if not HIBP_KEY:
        return {"error": "No HIBP API key configured", "tag": "UNAVAILABLE"}

    cache_key = f"breach:paste:{email}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        url = f"https://haveibeenpwned.com/api/v3/pasteaccount/{email}"
        headers = {
            "hibp-api-key": HIBP_KEY,
            "User-Agent": USER_AGENT,
        }
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(url, headers=headers)
            if resp.status_code == 404:
                result = {"pastes": [], "count": 0, "tag": "CLEAN"}
            elif resp.status_code == 200:
                data = resp.json()
                sources = list({p.get("Source", "Unknown") for p in data})
                result = {
                    "pastes": data,
                    "count": len(data),
                    "sources": sources,
                    "tag": "PROBABLE",
                }
            elif resp.status_code == 401:
                result = {"error": "Invalid HIBP API key", "tag": "UNAVAILABLE"}
            elif resp.status_code == 429:
                result = {"error": "HIBP rate limit reached", "tag": "UNAVAILABLE"}
            else:
                result = {"error": f"HIBP returned {resp.status_code}", "tag": "UNAVAILABLE"}
    except httpx.TimeoutException:
        result = {"error": "Request timed out", "tag": "UNAVAILABLE"}
    except Exception as exc:
        result = {"error": str(exc), "tag": "UNAVAILABLE"}

    cache_set(cache_key, "breach_paste", result, CACHE_TTL_HOURS)
    return result


def summarise_breaches(breach_data: list) -> dict:
    """Summarise breach list into key stats."""
    if not breach_data:
        return {"count": 0, "names": [], "data_types": [], "earliest": None, "most_recent": None}

    names = [b.get("Name", "Unknown") for b in breach_data]
    dates = [b.get("BreachDate", "") for b in breach_data if b.get("BreachDate")]
    dates_sorted = sorted(dates)

    data_types: list = []
    for b in breach_data:
        for dt in b.get("DataClasses", []):
            if dt not in data_types:
                data_types.append(dt)

    breach_names_with_dates = [
        {"name": b.get("Name", "Unknown"), "date": b.get("BreachDate", ""), "domain": b.get("Domain", "")}
        for b in breach_data
    ]

    return {
        "count": len(breach_data),
        "names": names,
        "breach_names_with_dates": breach_names_with_dates,
        "data_types": data_types,
        "earliest": dates_sorted[0] if dates_sorted else None,
        "most_recent": dates_sorted[-1] if dates_sorted else None,
    }
