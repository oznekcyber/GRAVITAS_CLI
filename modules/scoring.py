import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))


def calculate_gravity_score(all_results: dict, correlations: dict) -> dict:
    """Calculate GRAVITAS composite risk score."""
    score = 0
    breakdown = {}
    top_risk_factors = []

    # --- Breach exposure: 5pts per breach, cap 25 ---
    breach_data = all_results.get("breach", {})
    breach_count = breach_data.get("count", 0) if isinstance(breach_data, dict) else 0
    breach_score = min(breach_count * 5, 25)
    breakdown["breach_exposure"] = breach_score
    score += breach_score
    if breach_count > 0:
        top_risk_factors.append(f"Found in {breach_count} data breach(es) (+{breach_score}pts)")

    # --- Platform spread: 1pt per confirmed platform, cap 20 ---
    platforms = all_results.get("platforms", [])
    found_platforms = [p for p in platforms if p.get("found")]
    platform_score = min(len(found_platforms), 20)
    breakdown["platform_spread"] = platform_score
    score += platform_score
    if found_platforms:
        top_risk_factors.append(f"Active on {len(found_platforms)} platforms (+{platform_score}pts)")

    # --- Cross-source correlations: 5pts per cross-link, cap 20 ---
    cross_links = correlations.get("cross_links", [])
    confirmed_links = [l for l in cross_links if l.get("confidence") == "CONFIRMED"]
    correlation_score = min(len(confirmed_links) * 5, 20)
    breakdown["cross_source_correlations"] = correlation_score
    score += correlation_score

    # --- Persona count: more distinct = higher, cap 10 ---
    corr_list = correlations.get("correlations", [])
    persona_score = min(len(corr_list) * 2, 10)
    breakdown["persona_count"] = persona_score
    score += persona_score

    # --- IP threat score: from AbuseIPDB, cap 10 ---
    ip_data = all_results.get("ip", {})
    abuse_score_raw = 0
    if isinstance(ip_data, dict):
        abuseipdb = ip_data.get("abuseipdb", {})
        if isinstance(abuseipdb, dict):
            abuse_score_raw = abuseipdb.get("abuse_score", 0) or 0
    ip_score = min(int(abuse_score_raw / 10), 10)
    breakdown["ip_threat"] = ip_score
    score += ip_score
    if ip_score > 0:
        top_risk_factors.append(f"IP abuse confidence score: {abuse_score_raw} (+{ip_score}pts)")

    # --- Disposable email: +5 ---
    email_intel = all_results.get("email_intel", {})
    disposable_check = email_intel.get("disposable", {}) if isinstance(email_intel, dict) else {}
    disposable_score = 5 if isinstance(disposable_check, dict) and disposable_check.get("is_disposable") else 0
    breakdown["disposable_email"] = disposable_score
    score += disposable_score
    if disposable_score:
        top_risk_factors.append("Uses a disposable email domain (+5pts)")

    # --- VOIP phone: +5 ---
    phone_risk = all_results.get("phone_risk", {})
    voip_score = 5 if isinstance(phone_risk, dict) and phone_risk.get("is_voip") else 0
    breakdown["voip_phone"] = voip_score
    score += voip_score
    if voip_score:
        top_risk_factors.append("VOIP phone number detected (+5pts)")

    # --- Bio link depth: 1pt per level, cap 5 ---
    bio_links = all_results.get("bio_links", [])
    bio_link_score = min(len(bio_links), 5)
    breakdown["bio_link_depth"] = bio_link_score
    score += bio_link_score

    # Clamp score
    score = max(0, min(score, 100))

    # Determine risk band
    if score <= 20:
        band = "LOW"
        band_color = "green"
    elif score <= 40:
        band = "MODERATE"
        band_color = "yellow"
    elif score <= 60:
        band = "ELEVATED"
        band_color = "dark_orange"
    elif score <= 80:
        band = "HIGH"
        band_color = "red"
    else:
        band = "CRITICAL"
        band_color = "bold red"

    return {
        "score": score,
        "band": band,
        "band_color": band_color,
        "breakdown": breakdown,
        "top_risk_factors": top_risk_factors[:5],
    }
