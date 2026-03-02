import sys
import re
import hashlib
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
import dns.resolver
from config import REQUEST_TIMEOUT, USER_AGENT
from cache_helper import cache_get, cache_set

DISPOSABLE_DOMAINS = {
    "mailinator.com", "guerrillamail.com", "10minutemail.com", "throwam.com",
    "yopmail.com", "sharklasers.com", "guerrillamailblock.com", "grr.la",
    "spam4.me", "trashmail.com", "mailnull.com", "spamgourmet.com",
    "dispostable.com", "fakeinbox.com", "maildrop.cc", "spamfree24.org",
    "tempmail.com", "getairmail.com", "mailtemp.info", "tempr.email",
    "discard.email", "mailscrap.com", "anonbox.net", "anonaddy.com",
    "mailnesia.com", "spamgob.com", "boximail.com", "filzmail.com",
    "garliclife.com", "harakirimail.com", "inoutmail.de", "meltmail.com",
    "mindless.com", "mt2015.com", "mycleaninbox.net", "no-spam.ws",
    "nobulk.com", "noclickemail.com", "nospammail.net", "notmailinator.com",
    "obobbo.com", "pookmail.com", "proxymail.eu", "quickinbox.com",
    "rcpt.at", "send-email.org", "shitware.nl", "spam.la",
    "spaml.de", "spamoff.de", "super-auswahl.de", "tafmail.com",
    "tapmail.com", "teleworm.us", "temp-mail.org", "tempail.com",
    "tempalias.com", "temporary-mail.net", "trash-me.com", "trashdevil.com",
    "trashmail.at", "trashmail.io", "trashmail.me", "trashmail.net",
    "trashmail.org", "trashmailer.com", "trbvm.com", "turual.com",
    "twinmail.de", "tyldd.com", "uggsrock.com", "veryrealemail.com",
    "xagloo.com", "yomail.info", "zetmail.com", "zoemail.net",
    "throwaway.email", "mailexpire.com", "spamevader.com", "spamgob.net",
    "discard.ga", "cock.li", "trashmail.fr", "33mail.com",
    "spamgourmet.net", "spamgourmet.org", "tempinbox.com", "tempinbox.co.uk",
    "spamex.com", "spammotel.com", "spam.su", "spam.care",
    "mailzilla.com", "einrot.com", "spamfree.eu", "throwam.net",
}


def _email_regex(email: str) -> bool:
    pattern = r"^[a-zA-Z0-9._%+\-]+@[a-zA-Z0-9.\-]+\.[a-zA-Z]{2,}$"
    return bool(re.match(pattern, email))


async def validate_email(email: str) -> dict:
    """Validate email format and extract parts."""
    if not _email_regex(email):
        return {"valid": False, "email": email, "username": None, "domain": None}
    parts = email.split("@", 1)
    return {"valid": True, "email": email, "username": parts[0], "domain": parts[1]}


async def check_gravatar(email: str) -> dict:
    """Check if email has a Gravatar profile."""
    cache_key = f"gravatar:{email}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    try:
        email_hash = hashlib.md5(email.strip().lower().encode()).hexdigest()
        profile_url = f"https://www.gravatar.com/{email_hash}.json"
        avatar_url = f"https://www.gravatar.com/avatar/{email_hash}?d=404"

        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            avatar_resp = await client.get(avatar_url)
            if avatar_resp.status_code == 404:
                result = {"exists": False, "tag": "INFERRED"}
            else:
                result = {"exists": True, "profile_url": f"https://www.gravatar.com/{email_hash}", "tag": "CONFIRMED"}
                try:
                    profile_resp = await client.get(profile_url)
                    if profile_resp.status_code == 200:
                        pdata = profile_resp.json()
                        entry = pdata.get("entry", [{}])[0]
                        result["display_name"] = entry.get("displayName", "")
                        result["about"] = entry.get("aboutMe", "")
                        result["linked_accounts"] = entry.get("accounts", [])
                except Exception:
                    pass
    except httpx.TimeoutException:
        result = {"exists": False, "error": "timeout", "tag": "UNAVAILABLE"}
    except Exception as exc:
        result = {"exists": False, "error": str(exc), "tag": "UNAVAILABLE"}

    cache_set(cache_key, "gravatar", result)
    return result


async def check_domain_mx(domain: str) -> dict:
    """Check MX records for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = REQUEST_TIMEOUT
        answers = resolver.resolve(domain, "MX")
        records = [str(r.exchange).rstrip(".") for r in answers]
        return {"has_mx": True, "mx_records": records}
    except dns.resolver.NXDOMAIN:
        return {"has_mx": False, "mx_records": [], "error": "Domain not found"}
    except dns.resolver.NoAnswer:
        return {"has_mx": False, "mx_records": []}
    except Exception as exc:
        return {"has_mx": False, "mx_records": [], "error": str(exc)}


async def check_domain_spf(domain: str) -> dict:
    """Check SPF record for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = REQUEST_TIMEOUT
        answers = resolver.resolve(domain, "TXT")
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if txt.startswith("v=spf1"):
                return {"has_spf": True, "spf_record": txt}
        return {"has_spf": False, "spf_record": None}
    except Exception as exc:
        return {"has_spf": False, "spf_record": None, "error": str(exc)}


async def check_domain_dmarc(domain: str) -> dict:
    """Check DMARC record for a domain."""
    try:
        resolver = dns.resolver.Resolver()
        resolver.timeout = REQUEST_TIMEOUT
        answers = resolver.resolve(f"_dmarc.{domain}", "TXT")
        for rdata in answers:
            txt = "".join(s.decode() if isinstance(s, bytes) else s for s in rdata.strings)
            if "v=DMARC1" in txt:
                policy = "none"
                for part in txt.split(";"):
                    part = part.strip()
                    if part.startswith("p="):
                        policy = part[2:]
                return {"has_dmarc": True, "dmarc_record": txt, "policy": policy}
        return {"has_dmarc": False, "policy": None}
    except Exception as exc:
        return {"has_dmarc": False, "policy": None, "error": str(exc)}


async def check_disposable(domain: str) -> dict:
    """Check if domain is a known disposable email provider."""
    is_disposable = domain.lower() in DISPOSABLE_DOMAINS
    return {"is_disposable": is_disposable, "tag": "CONFIRMED" if is_disposable else "INFERRED"}


def generate_google_dorks(email: str) -> list:
    """Generate Google dork queries for email OSINT."""
    return [
        f'"{email}"',
        f'"{email}" site:linkedin.com',
        f'"{email}" site:github.com',
        f'"{email}" filetype:pdf',
        f'"{email}" filetype:xls OR filetype:xlsx',
        f'"{email}" intext:password',
        f'"{email}" site:pastebin.com',
        f'"{email}" site:reddit.com',
        f'"{email}" site:twitter.com OR site:x.com',
        f'"{email}" resume OR cv',
        f'"{email}" -site:haveibeenpwned.com',
    ]
