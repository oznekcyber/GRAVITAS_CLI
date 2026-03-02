import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from collections import defaultdict
from typing import Any


def correlate_findings(all_results: dict) -> dict:
    """Cross-reference all module results and identify connections."""
    correlations = []
    cross_links = []
    risk_boosts = []

    email = all_results.get("email")
    username = all_results.get("username")
    platforms = all_results.get("platforms", [])
    breach_data = all_results.get("breach", {})
    email_intel = all_results.get("email_intel", {})
    gravatar = email_intel.get("gravatar", {}) if email_intel else {}
    profile_enrichments = all_results.get("profile_enrichments", [])

    found_platforms = [p for p in platforms if p.get("found")]
    found_names = set()
    found_usernames = set()

    # Collect display names from enriched profiles
    for p in profile_enrichments:
        enriched = p.get("enriched", {})
        name = enriched.get("display_name")
        if name:
            found_names.add(name.lower().strip())

    # Gravatar display name
    if gravatar.get("display_name"):
        found_names.add(gravatar["display_name"].lower().strip())

    # Bio link cross-references
    bio_links = all_results.get("bio_links", [])
    for link in bio_links:
        if link.get("resolved_platform") and link.get("resolved_username"):
            cross_links.append({
                "source": "bio_link",
                "platform": link["resolved_platform"],
                "username": link["resolved_username"],
                "url": link["original_url"],
                "confidence": "PROBABLE",
            })

    # Cross-reference: if breach email domain matches platform
    breach_names = []
    if isinstance(breach_data, dict) and breach_data.get("names"):
        breach_names = breach_data["names"]

    # Check name consistency across platforms
    if len(found_names) > 1:
        correlations.append({
            "type": "name_variation",
            "description": f"Multiple display names found: {', '.join(list(found_names)[:5])}",
            "confidence": "PROBABLE",
        })
    elif len(found_names) == 1:
        correlations.append({
            "type": "name_consistent",
            "description": f"Consistent display name across platforms: {list(found_names)[0]}",
            "confidence": "CONFIRMED",
        })

    # Platform spread
    categories = defaultdict(list)
    for p in found_platforms:
        categories[p.get("category", "misc")].append(p["platform"])

    if len(found_platforms) > 10:
        correlations.append({
            "type": "high_platform_spread",
            "description": f"High platform spread: {len(found_platforms)} confirmed accounts",
            "confidence": "CONFIRMED",
        })
        risk_boosts.append({"reason": "high_platform_spread", "boost": 5})

    # Breach + platform overlap risk
    if breach_data.get("count", 0) > 0 and len(found_platforms) > 5:
        correlations.append({
            "type": "breach_platform_overlap",
            "description": f"Subject has {breach_data['count']} breach(es) AND {len(found_platforms)} active platforms",
            "confidence": "CONFIRMED",
        })
        risk_boosts.append({"reason": "breach_platform_overlap", "boost": 10})

    # Disposable email flag
    disposable_check = email_intel.get("disposable", {}) if email_intel else {}
    if disposable_check.get("is_disposable"):
        risk_boosts.append({"reason": "disposable_email", "boost": 5})
        correlations.append({
            "type": "disposable_email",
            "description": "Email uses a disposable/temporary domain",
            "confidence": "CONFIRMED",
        })

    # Phone VOIP risk
    phone_risk = all_results.get("phone_risk", {})
    if phone_risk.get("is_voip"):
        risk_boosts.append({"reason": "voip_phone", "boost": 5})

    return {
        "correlations": correlations,
        "cross_links": cross_links,
        "risk_boosts": risk_boosts,
        "found_names": list(found_names),
        "category_spread": {k: v for k, v in categories.items()},
    }


def cluster_personas(all_results: dict, correlations: dict) -> list:
    """Group findings into persona clusters."""
    platforms = all_results.get("platforms", [])
    found_platforms = [p for p in platforms if p.get("found")]
    cross_links = correlations.get("cross_links", [])

    # Group by category
    category_groups = defaultdict(list)
    for p in found_platforms:
        category_groups[p.get("category", "misc")].append(p["platform"])

    personas = []
    main_persona = {
        "persona_label": "Primary Identity",
        "platforms": [p["platform"] for p in found_platforms[:20]],
        "confidence": "CONFIRMED" if found_platforms else "INFERRED",
        "linked_to": [l["url"] for l in cross_links[:5]],
        "categories": dict(category_groups),
    }
    personas.append(main_persona)

    # If bio links reveal additional accounts on different platforms
    if cross_links:
        bio_persona = {
            "persona_label": "Bio-Linked Accounts",
            "platforms": [l["platform"] for l in cross_links if l.get("platform")],
            "confidence": "PROBABLE",
            "linked_to": [],
            "categories": {"bio_linked": [l["platform"] for l in cross_links if l.get("platform")]},
        }
        personas.append(bio_persona)

    return personas
