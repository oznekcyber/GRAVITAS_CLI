def generate_variations(username: str) -> list:
    """Generate common username mutations."""
    from datetime import datetime as _dt
    variations = set()
    variations.add(username)

    # Split on common separators
    parts = username.replace('-', ' ').replace('_', ' ').replace('.', ' ').split()

    if len(parts) >= 2:
        first, *rest = parts
        last = rest[-1] if rest else ''
        variations.add(f"{first}_{last}")
        variations.add(f"{first}.{last}")
        variations.add(f"{first}{last}")

    # Leet substitutions
    leet_map = {'a': '4', 'e': '3', 'i': '1', 'o': '0', 's': '5', 't': '7'}
    leet_version = ''.join(leet_map.get(c, c) for c in username.lower())
    if leet_version != username:
        variations.add(leet_version)

    # Prefixes
    for prefix in ['real', 'the', 'its', 'im', 'official', 'i_am_']:
        variations.add(f"{prefix}{username}")

    # Suffixes
    for suffix in ['_official', 'tv', 'yt', '_', '1', '123', '_real', 'official', '_hd']:
        variations.add(f"{username}{suffix}")

    # Year suffixes (plausible birth years: 18+ years ago up to 2006)
    current_year = _dt.now().year
    for year in range(1990, min(current_year - 17, 2009)):
        variations.add(f"{username}{year}")

    # Numbers
    variations.add(f"{username}1")
    variations.add(f"{username}2")
    variations.add(f"{username}01")

    return sorted(list(variations))
