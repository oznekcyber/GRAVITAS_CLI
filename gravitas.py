#!/usr/bin/env python3
"""
GRAVITAS CLI — Open Source Intelligence Framework
"""
import argparse
import asyncio
import hashlib
import json
import sys
from pathlib import Path

# Ensure project root is on path
_ROOT = Path(__file__).parent
sys.path.insert(0, str(_ROOT))


def _check_deps():
    missing = []
    for pkg in ["httpx", "rich", "dns", "phonenumbers", "bs4"]:
        try:
            __import__(pkg)
        except ImportError:
            missing.append(pkg)
    if missing:
        print(f"[ERROR] Missing dependencies: {', '.join(missing)}")
        print("Run: pip install -r requirements.txt")
        sys.exit(1)


_check_deps()

from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.live import Live
from rich.panel import Panel

console = Console()

from cache_helper import init_db, save_session
from output.display import (
    print_banner,
    print_scan_header,
    render_all,
    console as display_console,
)
from modules.breach import check_hibp, check_pastes
from modules.email_intel import (
    validate_email,
    check_gravatar,
    check_domain_mx,
    check_domain_spf,
    check_domain_dmarc,
    check_disposable,
    generate_google_dorks,
)
from modules.ip_intel import check_abuseipdb, check_ipinfo, check_shodan, reverse_dns, classify_ip
from modules.phone_intel import parse_phone, check_numverify, assess_phone_risk
from modules.platform_sweep import sweep_username, enrich_found_profiles
from modules.profile_enrichment import extract_bio_links, follow_bio_links
from modules.correlation import correlate_findings, cluster_personas
from modules.timeline import build_timeline
from modules.scoring import calculate_gravity_score


def build_arg_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="gravitas",
        description="GRAVITAS — Open Source Intelligence Framework",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python gravitas.py --email target@example.com
  python gravitas.py --username johndoe --full
  python gravitas.py --ip 1.2.3.4
  python gravitas.py --phone +12125551234
  python gravitas.py --email target@example.com --username johndoe --full
  python gravitas.py --email target@example.com --output results.json
        """,
    )
    parser.add_argument("-u", "--username", help="Target username")
    parser.add_argument("-e", "--email", help="Target email address")
    parser.add_argument("-n", "--name", help="Target full name")
    parser.add_argument("-i", "--ip", help="Target IP address")
    parser.add_argument("-p", "--phone", help="Target phone number (E.164 format, e.g. +12125551234)")
    parser.add_argument("-f", "--full", action="store_true", help="Run full scan (all modules)")
    parser.add_argument("--no-cache", action="store_true", help="Bypass cache for fresh results")
    parser.add_argument("-t", "--timeout", type=int, default=10, help="HTTP request timeout in seconds (default: 10)")
    parser.add_argument("-o", "--output", help="Export results to JSON file")
    return parser


async def run_email_scan(email: str, timeout: int) -> dict:
    """Run all email-related intelligence modules."""
    results = {}
    validation = await validate_email(email)
    results["validation"] = validation
    domain = validation.get("domain", "")

    tasks = {
        "gravatar": check_gravatar(email),
        "disposable": check_disposable(domain) if domain else asyncio.sleep(0),
    }
    if domain:
        tasks["mx"] = check_domain_mx(domain)
        tasks["spf"] = check_domain_spf(domain)
        tasks["dmarc"] = check_domain_dmarc(domain)

    gathered = await asyncio.gather(*tasks.values(), return_exceptions=True)
    for key, val in zip(tasks.keys(), gathered):
        results[key] = val if not isinstance(val, Exception) else {"error": str(val)}

    return results


async def run_ip_scan(ip: str) -> dict:
    """Run all IP intelligence modules."""
    results = {}
    ipinfo_data, abuseipdb_data, shodan_data, rdns_data = await asyncio.gather(
        check_ipinfo(ip),
        check_abuseipdb(ip),
        check_shodan(ip),
        reverse_dns(ip),
        return_exceptions=True,
    )
    results["ipinfo"] = ipinfo_data if not isinstance(ipinfo_data, Exception) else {"error": str(ipinfo_data)}
    results["abuseipdb"] = abuseipdb_data if not isinstance(abuseipdb_data, Exception) else {"error": str(abuseipdb_data)}
    results["shodan"] = shodan_data if not isinstance(shodan_data, Exception) else {"error": str(shodan_data)}
    results["reverse_dns"] = rdns_data if not isinstance(rdns_data, Exception) else {"error": str(rdns_data)}
    results["classification"] = classify_ip(
        results.get("ipinfo", {}),
        results.get("abuseipdb", {}),
    )
    return results


async def main() -> None:
    parser = build_arg_parser()
    args = parser.parse_args()

    # Validate at least one target is provided
    if not any([args.email, args.username, args.ip, args.phone, args.name]):
        parser.print_help()
        sys.exit(0)

    # Init cache DB
    init_db()

    # Print banner
    print_banner()

    # Show scan targets
    targets = {
        "email": args.email,
        "username": args.username,
        "name": args.name,
        "ip": args.ip,
        "phone": args.phone,
    }
    mode = "FULL" if args.full else "TARGETED"
    print_scan_header({k: v for k, v in targets.items() if v}, mode)

    all_results: dict = {}
    all_results["email"] = args.email
    all_results["username"] = args.username
    all_results["name"] = args.name

    # ─── EMAIL MODULES ───────────────────────────────────────────────
    if args.email:
        with console.status("[bold cyan]Running email intelligence...[/bold cyan]", spinner="dots"):
            email_intel = await run_email_scan(args.email, args.timeout)
            all_results["email_intel"] = email_intel

        # Breaches (separate for clear output ordering)
        with console.status("[bold cyan]Checking breach databases...[/bold cyan]", spinner="dots"):
            breach_data, paste_data = await asyncio.gather(
                check_hibp(args.email),
                check_pastes(args.email),
                return_exceptions=True,
            )
            all_results["breach"] = breach_data if not isinstance(breach_data, Exception) else {"error": str(breach_data)}
            all_results["pastes"] = paste_data if not isinstance(paste_data, Exception) else {"error": str(paste_data)}

        # Dorks
        all_results["dorks"] = generate_google_dorks(args.email)

        # If no username but email has one, use it for platform sweep
        if not args.username and email_intel.get("validation", {}).get("username"):
            derived_username = email_intel["validation"]["username"]
            console.print(f"  [dim]Using derived username from email: [cyan]{derived_username}[/cyan][/dim]")
            args.username = derived_username

    # ─── IP MODULES ──────────────────────────────────────────────────
    if args.ip:
        with console.status("[bold cyan]Running IP intelligence...[/bold cyan]", spinner="dots"):
            ip_data = await run_ip_scan(args.ip)
            all_results["ip"] = ip_data

    # ─── PHONE MODULES ───────────────────────────────────────────────
    if args.phone:
        with console.status("[bold cyan]Analysing phone number...[/bold cyan]", spinner="dots"):
            parsed = parse_phone(args.phone)
            numverify = await check_numverify(args.phone)
            phone_risk = assess_phone_risk(numverify if numverify.get("valid") else parsed)
            all_results["phone"] = {
                "parsed": parsed,
                "numverify": numverify,
                "risk": phone_risk,
            }
            all_results["phone_risk"] = phone_risk

    # ─── PLATFORM SWEEP ──────────────────────────────────────────────
    if args.username or (args.full and args.email):
        uname = args.username
        if uname:
            console.print(f"\n[bold cyan]⠿ Platform sweep for username:[/bold cyan] [bold white]{uname}[/bold white]")
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(),
                transient=True,
                console=console,
            ) as progress:
                task = progress.add_task("Sweeping platforms...", total=None)
                platform_results = await sweep_username(uname, timeout=args.timeout)
                progress.update(task, completed=True)

            found_count = sum(1 for p in platform_results if p.get("found"))
            console.print(f"  [bold green]✓[/bold green] Platform sweep complete: [bold white]{found_count}[/bold white] accounts found across {len(platform_results)} platforms")

            # Enrich found profiles
            found_platforms = [p for p in platform_results if p.get("found")]
            if found_platforms:
                with console.status("[bold cyan]Enriching found profiles...[/bold cyan]", spinner="dots"):
                    enriched = await enrich_found_profiles(found_platforms)
                all_results["platform_enriched"] = enriched
            else:
                all_results["platform_enriched"] = []

            all_results["platforms"] = platform_results

            # Extract bio links from first found profile
            if found_platforms and args.full:
                first_url = found_platforms[0].get("url", "")
                with console.status("[bold cyan]Extracting bio links...[/bold cyan]", spinner="dots"):
                    bio_links_raw = await extract_bio_links(first_url)
                    bio_links = await follow_bio_links(bio_links_raw)
                all_results["bio_links"] = bio_links

    # ─── POST-PROCESSING ─────────────────────────────────────────────
    correlations = correlate_findings(all_results)
    personas = cluster_personas(all_results, correlations)
    timeline = build_timeline(all_results)
    score = calculate_gravity_score(all_results, correlations)

    # ─── RENDER OUTPUT ───────────────────────────────────────────────
    render_all(all_results, correlations, personas, timeline, score)

    # ─── SAVE SESSION ────────────────────────────────────────────────
    target_hash = hashlib.sha256(
        json.dumps({k: v for k, v in targets.items() if v}, sort_keys=True).encode()
    ).hexdigest()[:16]

    save_session(target_hash, targets, all_results, score.get("score", 0))

    # ─── EXPORT JSON ─────────────────────────────────────────────────
    if args.output:
        output_path = Path(args.output)
        export_data = {
            "targets": targets,
            "results": all_results,
            "correlations": correlations,
            "personas": personas,
            "timeline": timeline,
            "score": score,
        }
        try:
            output_path.write_text(json.dumps(export_data, indent=2, default=str))
            console.print(f"[bold green]✓[/bold green] Results exported to [cyan]{output_path}[/cyan]")
        except Exception as exc:
            console.print(f"[bold red]✗[/bold red] Failed to export: {exc}")


if __name__ == "__main__":
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        console.print("\n[bold yellow]⚠  Scan interrupted by user[/bold yellow]")
        sys.exit(0)
    except Exception as exc:
        console.print(f"[bold red]✗  Fatal error: {exc}[/bold red]")
        raise
