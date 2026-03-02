import sys
import asyncio
import json
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

import httpx
from config import REQUEST_TIMEOUT, USER_AGENT
from cache_helper import cache_get, cache_set

_PLATFORMS_PATH = Path(__file__).parent.parent / "data" / "platforms.json"


def _load_platforms() -> list:
    try:
        with open(_PLATFORMS_PATH) as f:
            return json.load(f)
    except Exception:
        return []


async def _check_platform(client: httpx.AsyncClient, platform: dict, username: str, semaphore: asyncio.Semaphore) -> dict:
    url = platform["url"].replace("{username}", username)
    start = time.monotonic()
    async with semaphore:
        try:
            resp = await client.get(url, follow_redirects=True)
            elapsed_ms = int((time.monotonic() - start) * 1000)
            error_type = platform.get("error_type", "status_code")
            found = False
            if error_type == "status_code":
                error_code = platform.get("error_code", 404)
                found = resp.status_code != error_code and resp.status_code < 400
            elif error_type == "body_string":
                error_string = platform.get("error_string", "")
                found = resp.status_code == 200 and error_string not in resp.text

            return {
                "platform": platform["name"],
                "url": url,
                "found": found,
                "category": platform.get("category", "misc"),
                "response_time_ms": elapsed_ms,
                "status_code": resp.status_code,
                "tag": "CONFIRMED" if found else "NOT_FOUND",
            }
        except httpx.TimeoutException:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return {
                "platform": platform["name"],
                "url": url,
                "found": False,
                "category": platform.get("category", "misc"),
                "response_time_ms": elapsed_ms,
                "status_code": None,
                "tag": "TIMEOUT",
                "error": "timeout",
            }
        except Exception as exc:
            elapsed_ms = int((time.monotonic() - start) * 1000)
            return {
                "platform": platform["name"],
                "url": url,
                "found": False,
                "category": platform.get("category", "misc"),
                "response_time_ms": elapsed_ms,
                "status_code": None,
                "tag": "ERROR",
                "error": str(exc),
            }


async def sweep_username(username: str, timeout: int = 10) -> list:
    """Check username across all platforms concurrently."""
    platforms = _load_platforms()
    semaphore = asyncio.Semaphore(20)
    headers = {"User-Agent": USER_AGENT}
    limits = httpx.Limits(max_keepalive_connections=20, max_connections=40)
    async with httpx.AsyncClient(timeout=timeout, headers=headers, limits=limits) as client:
        tasks = [_check_platform(client, p, username, semaphore) for p in platforms]
        results = await asyncio.gather(*tasks, return_exceptions=False)
    return list(results)


async def enrich_found_profiles(found_platforms: list) -> list:
    """Enrich found platform profiles with metadata from public APIs."""
    enriched = []
    async with httpx.AsyncClient(timeout=REQUEST_TIMEOUT, headers={"User-Agent": USER_AGENT}) as client:
        for entry in found_platforms:
            platform_name = entry["platform"].lower()
            username = entry["url"].rstrip("/").split("/")[-1].lstrip("@")
            meta = {}
            try:
                if "github" in platform_name:
                    resp = await client.get(f"https://api.github.com/users/{username}")
                    if resp.status_code == 200:
                        d = resp.json()
                        meta = {
                            "display_name": d.get("name"),
                            "bio": d.get("bio"),
                            "location": d.get("location"),
                            "public_repos": d.get("public_repos"),
                            "followers": d.get("followers"),
                            "following": d.get("following"),
                            "join_date": d.get("created_at"),
                            "blog": d.get("blog"),
                            "company": d.get("company"),
                            "avatar_url": d.get("avatar_url"),
                        }
                elif "reddit" in platform_name:
                    resp = await client.get(f"https://www.reddit.com/user/{username}/about.json",
                                            headers={"User-Agent": USER_AGENT})
                    if resp.status_code == 200:
                        d = resp.json().get("data", {})
                        meta = {
                            "display_name": d.get("name"),
                            "link_karma": d.get("link_karma"),
                            "comment_karma": d.get("comment_karma"),
                            "join_date": d.get("created_utc"),
                            "is_gold": d.get("is_gold"),
                            "icon_img": d.get("icon_img"),
                        }
                elif "hackernews" in platform_name or "hacker news" in platform_name:
                    resp = await client.get(f"https://hacker-news.firebaseio.com/v0/user/{username}.json")
                    if resp.status_code == 200 and resp.json():
                        d = resp.json()
                        meta = {
                            "karma": d.get("karma"),
                            "about": d.get("about"),
                            "join_date": d.get("created"),
                            "submitted_count": len(d.get("submitted", [])),
                        }
            except Exception:
                pass
            enriched.append({**entry, "enriched": meta})
    return enriched
