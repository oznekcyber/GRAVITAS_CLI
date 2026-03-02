import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
import phonenumbers
from phonenumbers import geocoder, carrier, number_type as ph_number_type, PhoneNumberType
from config import NUMVERIFY_KEY, REQUEST_TIMEOUT, USER_AGENT, CACHE_TTL_HOURS
from cache_helper import cache_get, cache_set

_TYPE_MAP = {
    PhoneNumberType.FIXED_LINE: "fixed_line",
    PhoneNumberType.MOBILE: "mobile",
    PhoneNumberType.FIXED_LINE_OR_MOBILE: "fixed_or_mobile",
    PhoneNumberType.TOLL_FREE: "toll_free",
    PhoneNumberType.PREMIUM_RATE: "premium_rate",
    PhoneNumberType.SHARED_COST: "shared_cost",
    PhoneNumberType.VOIP: "voip",
    PhoneNumberType.PERSONAL_NUMBER: "personal_number",
    PhoneNumberType.PAGER: "pager",
    PhoneNumberType.UAN: "uan",
    PhoneNumberType.VOICEMAIL: "voicemail",
    PhoneNumberType.UNKNOWN: "unknown",
}


def parse_phone(phone: str) -> dict:
    """Parse and validate phone number using phonenumbers library."""
    try:
        parsed = phonenumbers.parse(phone, None)
        is_valid = phonenumbers.is_valid_number(parsed)
        ntype = ph_number_type(parsed)
        return {
            "valid": is_valid,
            "country": geocoder.description_for_number(parsed, "en"),
            "country_code": f"+{parsed.country_code}",
            "national_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.NATIONAL),
            "e164_format": phonenumbers.format_number(parsed, phonenumbers.PhoneNumberFormat.E164),
            "number_type": _TYPE_MAP.get(ntype, "unknown"),
            "carrier": carrier.name_for_number(parsed, "en"),
        }
    except phonenumbers.NumberParseException as exc:
        return {"valid": False, "error": str(exc)}
    except Exception as exc:
        return {"valid": False, "error": str(exc)}


async def check_numverify(phone: str) -> dict:
    """Validate phone via NumVerify API, fallback to phonenumbers."""
    cache_key = f"numverify:{phone}"
    cached = cache_get(cache_key)
    if cached is not None:
        return cached

    parsed = parse_phone(phone)

    if not NUMVERIFY_KEY:
        result = {**parsed, "source": "phonenumbers_library", "tag": "INFERRED"}
        cache_set(cache_key, "numverify", result, CACHE_TTL_HOURS)
        return result

    try:
        url = "http://apilayer.net/api/validate"
        params = {"access_key": NUMVERIFY_KEY, "number": phone, "format": 1}
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT) as client:
            resp = await client.get(url, params=params, headers={"User-Agent": USER_AGENT})
            if resp.status_code == 200:
                data = resp.json()
                if data.get("valid"):
                    result = {
                        "valid": True,
                        "country": data.get("country_name"),
                        "country_code": data.get("country_code"),
                        "national_format": data.get("local_format"),
                        "e164_format": data.get("international_format"),
                        "number_type": data.get("line_type", "unknown").lower(),
                        "carrier": data.get("carrier"),
                        "location": data.get("location"),
                        "source": "numverify",
                        "tag": "CONFIRMED",
                    }
                else:
                    result = {**parsed, "source": "numverify_invalid", "tag": "INFERRED"}
            else:
                result = {**parsed, "source": "phonenumbers_library", "tag": "INFERRED", "error": f"NumVerify returned {resp.status_code}"}
    except httpx.TimeoutException:
        result = {**parsed, "source": "phonenumbers_library", "tag": "INFERRED", "error": "timeout"}
    except Exception as exc:
        result = {**parsed, "source": "phonenumbers_library", "tag": "INFERRED", "error": str(exc)}

    cache_set(cache_key, "numverify", result, CACHE_TTL_HOURS)
    return result


def assess_phone_risk(phone_data: dict) -> dict:
    """Assess risk level of phone number."""
    flags = []
    risk_level = "LOW"
    ntype = phone_data.get("number_type", "").lower()

    if "voip" in ntype:
        flags.append("VOIP number - commonly used for anonymity")
        risk_level = "MODERATE"
    if "premium" in ntype:
        flags.append("Premium rate number")
        risk_level = "MODERATE"
    if "toll_free" in ntype:
        flags.append("Toll-free number")
    if not phone_data.get("valid", False):
        flags.append("Invalid phone number")
        risk_level = "HIGH"
    if not phone_data.get("carrier"):
        flags.append("No carrier information available")

    return {"risk_level": risk_level, "flags": flags, "is_voip": "voip" in ntype}
