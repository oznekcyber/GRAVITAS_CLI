import sys
import asyncio
import socket
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from config import ABUSEIPDB_KEY, SHODAN_KEY, IPINFO_KEY, REQUEST_TIMEOUT, USER_AGENT, CACHE_TTL_HOURS
from cache_helper import cache_get, cache_set


async def check_abuseipdb(ip: str) -> dict:
    """Check IP reputation on AbuseIPDB."""
    if not ABUSEIPDB_KEY:
        return {"error": "No AbuseIPDB API key configured", "tag": "UNAVAILABLE"}

    cache_key = f"abuseipdb:{ip}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        url = "https://api.abuseipdb.com/api/v2/check"
        headers = {"Key": ABUSEIPDB_KEY, "Accept": "application/json", "User-Agent": USER_AGENT}
        params = {"ipAddress": ip, "maxAgeInDays": 90, "verbose": ""}
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(url, headers=headers, params=params)
            if resp.status_code == 200:
                data = resp.json().get("data", {})
                score = data.get("abuseConfidenceScore", 0)
                if score > 50:
                    tag = "CONFIRMED"
                elif score >= 20:
                    tag = "PROBABLE"
                else:
                    tag = "INFERRED"
                result = {
                    "abuse_score": score,
                    "total_reports": data.get("totalReports", 0),
                    "last_reported": data.get("lastReportedAt"),
                    "country": data.get("countryCode"),
                    "isp": data.get("isp"),
                    "usage_type": data.get("usageType"),
                    "is_tor": data.get("isTor", False),
                    "is_whitelisted": data.get("isWhitelisted", False),
                    "tag": tag,
                }
            elif resp.status_code == 401:
                result = {"error": "Invalid AbuseIPDB API key", "tag": "UNAVAILABLE"}
            elif resp.status_code == 429:
                result = {"error": "AbuseIPDB rate limit reached", "tag": "UNAVAILABLE"}
            else:
                result = {"error": f"AbuseIPDB returned {resp.status_code}", "tag": "UNAVAILABLE"}
    except httpx.TimeoutException:
        result = {"error": "Request timed out", "tag": "UNAVAILABLE"}
    except Exception as exc:
        result = {"error": str(exc), "tag": "UNAVAILABLE"}

    cache_set(cache_key, "abuseipdb", result, CACHE_TTL_HOURS)
    return result


async def check_ipinfo(ip: str) -> dict:
    """Get IP geolocation and org info from ipinfo.io."""
    cache_key = f"ipinfo:{ip}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        token = IPINFO_KEY
        url = f"https://ipinfo.io/{ip}/json"
        params = {}
        if token:
            params["token"] = token
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(url, params=params, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                data = resp.json()
                result = {
                    "city": data.get("city"),
                    "region": data.get("region"),
                    "country": data.get("country"),
                    "org": data.get("org"),
                    "hostname": data.get("hostname"),
                    "timezone": data.get("timezone"),
                    "loc": data.get("loc"),
                    "tag": "CONFIRMED",
                }
            else:
                result = {"error": f"ipinfo returned {resp.status_code}", "tag": "UNAVAILABLE"}
    except httpx.TimeoutException:
        result = {"error": "Request timed out", "tag": "UNAVAILABLE"}
    except Exception as exc:
        result = {"error": str(exc), "tag": "UNAVAILABLE"}

    cache_set(cache_key, "ipinfo", result, CACHE_TTL_HOURS)
    return result


async def check_shodan(ip: str) -> dict:
    """Look up IP on Shodan."""
    if not SHODAN_KEY:
        return {"error": "No Shodan API key configured", "tag": "UNAVAILABLE"}

    cache_key = f"shodan:{ip}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        url = f"https://api.shodan.io/shodan/host/{ip}"
        params = {"key": SHODAN_KEY}
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(url, params=params, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                data = resp.json()
                ports = data.get("ports", [])
                vulns = list(data.get("vulns", {}).keys()) if isinstance(data.get("vulns"), dict) else []
                banners = [
                    {"port": item.get("port"), "transport": item.get("transport"), "product": item.get("product", ""), "banner": item.get("data", "")[:200]}
                    for item in data.get("data", [])[:10]
                ]
                result = {
                    "open_ports": ports,
                    "banners": banners,
                    "vulns": vulns,
                    "tags": data.get("tags", []),
                    "last_update": data.get("last_update"),
                    "os": data.get("os"),
                    "hostnames": data.get("hostnames", []),
                    "domains": data.get("domains", []),
                    "tag": "CONFIRMED",
                }
            elif resp.status_code == 404:
                result = {"error": "IP not in Shodan database", "tag": "INFERRED"}
            elif resp.status_code == 401:
                result = {"error": "Invalid Shodan API key", "tag": "UNAVAILABLE"}
            else:
                result = {"error": f"Shodan returned {resp.status_code}", "tag": "UNAVAILABLE"}
    except httpx.TimeoutException:
        result = {"error": "Request timed out", "tag": "UNAVAILABLE"}
    except Exception as exc:
        result = {"error": str(exc), "tag": "UNAVAILABLE"}

    cache_set(cache_key, "shodan", result, CACHE_TTL_HOURS)
    return result


async def reverse_dns(ip: str) -> dict:
    """Perform reverse DNS lookup."""
    try:
        loop = asyncio.get_event_loop()
        hostname, aliases, _ = await loop.run_in_executor(None, socket.gethostbyaddr, ip)
        return {"hostname": hostname, "aliases": aliases, "tag": "CONFIRMED"}
    except socket.herror:
        return {"hostname": None, "tag": "INFERRED"}
    except Exception as exc:
        return {"hostname": None, "error": str(exc), "tag": "UNAVAILABLE"}


def classify_ip(ipinfo_data: dict, abuseipdb_data: dict) -> dict:
    """Classify IP type and flag risks."""
    risk_flags = []
    classification = "unknown"

    org = (ipinfo_data.get("org") or "").lower()
    usage_type = (abuseipdb_data.get("usage_type") or "").lower()
    is_tor = abuseipdb_data.get("is_tor", False)
    abuse_score = abuseipdb_data.get("abuse_score", 0)

    if is_tor:
        classification = "tor"
        risk_flags.append("Tor exit node")
    elif any(kw in org for kw in ["vpn", "nordvpn", "expressvpn", "mullvad", "proton"]):
        classification = "vpn"
        risk_flags.append("Known VPN provider")
    elif any(kw in org for kw in ["amazon", "google", "microsoft", "digitalocean", "linode", "vultr", "hetzner", "ovh"]):
        classification = "datacenter"
        risk_flags.append("Datacenter/cloud IP")
    elif "mobile" in usage_type or "cellular" in usage_type:
        classification = "mobile"
    elif "residential" in usage_type or "fixed" in usage_type:
        classification = "residential"
    else:
        classification = "unknown"

    if abuse_score > 50:
        risk_flags.append(f"High abuse score ({abuse_score})")
    elif abuse_score >= 20:
        risk_flags.append(f"Moderate abuse score ({abuse_score})")

    return {"classification": classification, "risk_flags": risk_flags}
