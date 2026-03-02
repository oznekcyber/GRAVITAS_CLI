import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import re
import httpx
from bs4 import BeautifulSoup
from config import REQUEST_TIMEOUT, USER_AGENT


_PLATFORM_PATTERNS = {
    "github.com": "github",
    "twitter.com": "twitter",
    "x.com": "twitter",
    "instagram.com": "instagram",
    "linkedin.com": "linkedin",
    "facebook.com": "facebook",
    "youtube.com": "youtube",
    "reddit.com": "reddit",
    "tiktok.com": "tiktok",
    "medium.com": "medium",
    "twitch.tv": "twitch",
    "pinterest.com": "pinterest",
    "tumblr.com": "tumblr",
    "soundcloud.com": "soundcloud",
    "spotify.com": "spotify",
    "telegram.me": "telegram",
    "t.me": "telegram",
    "discord.com": "discord",
    "patreon.com": "patreon",
    "ko-fi.com": "ko-fi",
    "keybase.io": "keybase",
    "about.me": "about.me",
}


async def extract_bio_links(profile_url: str) -> list:
    """Fetch profile page HTML and extract external links from bio section."""
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(profile_url, headers={"User-Agent": USER_AGENT})
            if resp.status_code != 200:
                return []
            soup = BeautifulSoup(resp.text, "html.parser")
            links = []
            for a in soup.find_all("a", href=True):
                href = a["href"].strip()
                text = a.get_text(strip=True)
                if href.startswith("http") and text:
                    # Skip common navigation/structural links
                    if any(kw in href.lower() for kw in ["privacy", "terms", "help", "login", "signup", "javascript:"]):
                        continue
                    links.append({"url": href, "text": text})
            return links[:30]  # cap at 30 bio links
    except Exception:
        return []


async def follow_bio_links(bio_links: list) -> list:
    """Identify social platforms from bio links and extract usernames."""
    results = []
    for link in bio_links:
        url = link.get("url", "")
        resolved_platform = None
        resolved_username = None
        try:
            for domain, platform in _PLATFORM_PATTERNS.items():
                if domain in url:
                    resolved_platform = platform
                    # Extract username from URL
                    parts = url.rstrip("/").split("/")
                    if parts:
                        candidate = parts[-1].lstrip("@").lstrip("~")
                        if candidate and not candidate.startswith("?"):
                            resolved_username = candidate
                    break
        except Exception:
            pass
        results.append({
            "original_url": url,
            "text": link.get("text", ""),
            "resolved_platform": resolved_platform,
            "resolved_username": resolved_username,
        })
    return results


async def scrape_public_metadata(platform: str, username: str, profile_url: str) -> dict:
    """Lightly scrape public profile metadata from HTML."""
    metadata = {
        "platform": platform,
        "username": username,
        "profile_url": profile_url,
        "display_name": None,
        "bio": None,
        "location": None,
        "join_date": None,
        "follower_count": None,
    }
    try:
        async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, follow_redirects=True) as client:
            resp = await client.get(profile_url, headers={"User-Agent": USER_AGENT})
            if resp.status_code != 200:
                return metadata
            soup = BeautifulSoup(resp.text, "html.parser")

            # Try og:title for display name
            og_title = soup.find("meta", property="og:title")
            if og_title:
                metadata["display_name"] = og_title.get("content", "").strip()

            # Try og:description for bio
            og_desc = soup.find("meta", property="og:description")
            if og_desc:
                metadata["bio"] = og_desc.get("content", "").strip()[:300]

            # Generic fallback: title tag
            if not metadata["display_name"] and soup.title:
                metadata["display_name"] = soup.title.string.strip() if soup.title.string else None

    except Exception:
        pass
    return metadata
