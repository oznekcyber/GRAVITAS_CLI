import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent))

from datetime import datetime, timezone
from collections import defaultdict

from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.rule import Rule
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn
from rich.columns import Columns
from rich import box

console = Console()

BANNER = r"""
 ██████╗ ██████╗  █████╗ ██╗   ██╗██╗████████╗ █████╗ ███████╗
██╔════╝ ██╔══██╗██╔══██╗██║   ██║██║╚══██╔══╝██╔══██╗██╔════╝
██║  ███╗██████╔╝███████║██║   ██║██║   ██║   ███████║███████╗
██║   ██║██╔══██╗██╔══██║╚██╗ ██╔╝██║   ██║   ██╔══██║╚════██║
╚██████╔╝██║  ██║██║  ██║ ╚████╔╝ ██║   ██║   ██║  ██║███████║
 ╚═════╝ ╚═╝  ╚═╝╚═╝  ╚═╝  ╚═══╝  ╚═╝   ╚═╝   ╚═╝  ╚═╝╚══════╝"""

_TAG_COLORS = {
    "CONFIRMED": "bold green",
    "PROBABLE": "bold yellow",
    "INFERRED": "bold cyan",
    "CLEAN": "dim green",
    "NOT_FOUND": "dim red",
    "UNAVAILABLE": "dim white",
    "TIMEOUT": "dim yellow",
    "ERROR": "dim red",
}

_BAND_COLORS = {
    "LOW": "green",
    "MODERATE": "yellow",
    "ELEVATED": "dark_orange",
    "HIGH": "red",
    "CRITICAL": "bold red",
}


def _tag(label: str) -> Text:
    color = _TAG_COLORS.get(label, "white")
    return Text(f"[{label}]", style=color)


def print_banner() -> None:
    console.print(Text(BANNER, style="bold red"))
    console.print(Text("  Open Source Intelligence Framework  |  v1.0  |  github.com/GRAVITAS-CLI", style="dim white"))
    console.print()


def print_scan_header(targets: dict, mode: str) -> None:
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M:%S UTC")
    table = Table(box=box.SIMPLE, show_header=False, padding=(0, 2))
    table.add_column("Key", style="dim white")
    table.add_column("Value", style="bold white")
    if targets.get("email"):
        table.add_row("EMAIL", targets["email"])
    if targets.get("username"):
        table.add_row("USERNAME", targets["username"])
    if targets.get("name"):
        table.add_row("NAME", targets["name"])
    if targets.get("ip"):
        table.add_row("IP", targets["ip"])
    if targets.get("phone"):
        table.add_row("PHONE", targets["phone"])
    table.add_row("MODE", mode)
    table.add_row("TIMESTAMP", now)
    console.print(Panel(table, title="[bold white]GRAVITAS SCAN TARGET[/bold white]", border_style="dim white"))


def print_breach_section(breach_data: dict) -> None:
    console.print(Rule("[bold white]BREACH INTELLIGENCE[/bold white]", style="dim white"))
    if not isinstance(breach_data, dict):
        console.print("  [dim red]No breach data available[/dim red]")
        return

    if breach_data.get("error"):
        console.print(f"  [dim red]⚠  {breach_data['error']}[/dim red]")
        return

    count = breach_data.get("count", 0)
    if count == 0:
        console.print("  [dim green]✓  No breaches found[/dim green]")
        return

    tag = _tag(breach_data.get("tag", "CONFIRMED"))
    console.print(f"  ", tag, f"[bold white] {count} breach(es) found[/bold white]")

    # Breach details table
    bwdate = breach_data.get("breach_names_with_dates", [])
    if bwdate:
        t = Table(box=box.SIMPLE, padding=(0, 1), show_header=True)
        t.add_column("Breach Name", style="bold white", no_wrap=True)
        t.add_column("Date", style="dim white")
        t.add_column("Domain", style="dim cyan")
        for b in bwdate[:20]:
            t.add_row(b.get("name", ""), b.get("date", ""), b.get("domain", ""))
        console.print(t)

    # Data types
    data_types = breach_data.get("data_types", [])
    if data_types:
        console.print(f"  [dim white]Exposed data types:[/dim white] [yellow]{', '.join(data_types[:15])}[/yellow]")

    earliest = breach_data.get("earliest")
    recent = breach_data.get("most_recent")
    if earliest:
        console.print(f"  [dim white]Range:[/dim white] [cyan]{earliest}[/cyan] [dim white]→[/dim white] [cyan]{recent}[/cyan]")
    console.print()


def print_paste_section(paste_data: dict) -> None:
    if not isinstance(paste_data, dict):
        return
    if paste_data.get("error"):
        console.print(f"  [dim red]⚠  Pastes: {paste_data['error']}[/dim red]")
        return
    count = paste_data.get("count", 0)
    if count == 0:
        console.print("  [dim green]✓  No paste exposure found[/dim green]")
    else:
        tag = _tag(paste_data.get("tag", "PROBABLE"))
        sources = paste_data.get("sources", [])
        console.print(f"  ", tag, f" [bold white]{count} paste(s)[/bold white] — Sources: [yellow]{', '.join(sources)}[/yellow]")
    console.print()


def print_email_section(email_data: dict) -> None:
    console.print(Rule("[bold white]EMAIL INTELLIGENCE[/bold white]", style="dim white"))
    if not isinstance(email_data, dict):
        console.print("  [dim red]No email data available[/dim red]")
        return

    # Validation
    validation = email_data.get("validation", {})
    if validation:
        valid = validation.get("valid", False)
        icon = "[bold green]✓[/bold green]" if valid else "[bold red]✗[/bold red]"
        console.print(f"  {icon} Email format: [bold white]{validation.get('email', '')}[/bold white]")
        if valid:
            console.print(f"     Username: [cyan]{validation.get('username')}[/cyan]  Domain: [cyan]{validation.get('domain')}[/cyan]")

    # Disposable check
    disposable = email_data.get("disposable", {})
    if disposable.get("is_disposable"):
        console.print(f"  {_tag('CONFIRMED')} [bold red]DISPOSABLE email domain detected[/bold red]")
    else:
        console.print("  [dim green]✓  Domain is not in disposable list[/dim green]")

    # Gravatar
    gravatar = email_data.get("gravatar", {})
    if gravatar.get("exists"):
        console.print(f"  {_tag('CONFIRMED')} Gravatar profile found: [cyan]{gravatar.get('profile_url', '')}[/cyan]")
        if gravatar.get("display_name"):
            console.print(f"     Display name: [bold white]{gravatar['display_name']}[/bold white]")
        if gravatar.get("about"):
            console.print(f"     About: [dim white]{gravatar['about'][:120]}[/dim white]")
    else:
        console.print("  [dim]No Gravatar profile found[/dim]")

    # DNS checks
    mx = email_data.get("mx", {})
    spf = email_data.get("spf", {})
    dmarc = email_data.get("dmarc", {})

    if mx or spf or dmarc:
        console.print()
        console.print("  [bold white]Domain DNS:[/bold white]")
        if mx:
            mx_icon = "[bold green]✓[/bold green]" if mx.get("has_mx") else "[bold red]✗[/bold red]"
            mx_records = ", ".join(mx.get("mx_records", [])[:3])
            console.print(f"    {mx_icon} MX records: [cyan]{mx_records or 'none'}[/cyan]")
        if spf:
            spf_icon = "[bold green]✓[/bold green]" if spf.get("has_spf") else "[bold red]✗[/bold red]"
            console.print(f"    {spf_icon} SPF: [dim white]{spf.get('spf_record', 'none')[:80]}[/dim white]")
        if dmarc:
            dmarc_icon = "[bold green]✓[/bold green]" if dmarc.get("has_dmarc") else "[bold red]✗[/bold red]"
            policy = dmarc.get("policy", "none")
            console.print(f"    {dmarc_icon} DMARC policy: [cyan]{policy}[/cyan]")

    console.print()


def print_ip_section(ip_data: dict) -> None:
    console.print(Rule("[bold white]IP INTELLIGENCE[/bold white]", style="dim white"))
    if not isinstance(ip_data, dict):
        console.print("  [dim red]No IP data available[/dim red]")
        return

    # ipinfo
    ipinfo = ip_data.get("ipinfo", {})
    if ipinfo and not ipinfo.get("error"):
        console.print(f"  [bold white]Location:[/bold white] {ipinfo.get('city', '?')}, {ipinfo.get('region', '?')}, {ipinfo.get('country', '?')}")
        console.print(f"  [bold white]Org:[/bold white] [cyan]{ipinfo.get('org', 'unknown')}[/cyan]")
        if ipinfo.get("hostname"):
            console.print(f"  [bold white]Hostname:[/bold white] [cyan]{ipinfo.get('hostname')}[/cyan]")
        if ipinfo.get("timezone"):
            console.print(f"  [bold white]Timezone:[/bold white] {ipinfo.get('timezone')}")

    # Reverse DNS
    rdns = ip_data.get("reverse_dns", {})
    if rdns and rdns.get("hostname"):
        console.print(f"  [bold white]Reverse DNS:[/bold white] [cyan]{rdns['hostname']}[/cyan]")

    # AbuseIPDB
    abuse = ip_data.get("abuseipdb", {})
    if abuse and not abuse.get("error"):
        score = abuse.get("abuse_score", 0)
        score_color = "green" if score < 20 else ("yellow" if score < 50 else "red")
        console.print(f"  {_tag(abuse.get('tag', 'INFERRED'))} AbuseIPDB score: [{score_color}]{score}/100[/{score_color}]  Reports: {abuse.get('total_reports', 0)}")
        if abuse.get("is_tor"):
            console.print("  [bold red]  ⚠  TOR EXIT NODE DETECTED[/bold red]")
        if abuse.get("isp"):
            console.print(f"  [bold white]ISP:[/bold white] {abuse.get('isp')}  Type: [cyan]{abuse.get('usage_type', 'unknown')}[/cyan]")
    elif abuse.get("error"):
        console.print(f"  [dim]AbuseIPDB: {abuse['error']}[/dim]")

    # Classification
    classification = ip_data.get("classification", {})
    if classification:
        cls = classification.get("classification", "unknown")
        flags = classification.get("risk_flags", [])
        console.print(f"  [bold white]Classification:[/bold white] [cyan]{cls}[/cyan]")
        for flag in flags:
            console.print(f"    [yellow]⚠  {flag}[/yellow]")

    # Shodan
    shodan = ip_data.get("shodan", {})
    if shodan and not shodan.get("error"):
        ports = shodan.get("open_ports", [])
        vulns = shodan.get("vulns", [])
        console.print(f"  [bold white]Shodan open ports:[/bold white] [cyan]{', '.join(str(p) for p in ports[:20]) or 'none'}[/cyan]")
        if vulns:
            console.print(f"  [bold red]⚠  CVEs:[/bold red] [red]{', '.join(vulns[:10])}[/red]")
    elif shodan and shodan.get("error"):
        console.print(f"  [dim]Shodan: {shodan['error']}[/dim]")

    console.print()


def print_phone_section(phone_data: dict) -> None:
    console.print(Rule("[bold white]PHONE INTELLIGENCE[/bold white]", style="dim white"))
    if not isinstance(phone_data, dict):
        console.print("  [dim red]No phone data available[/dim red]")
        return

    parsed = phone_data.get("parsed", {})
    if parsed.get("error"):
        console.print(f"  [dim red]⚠  {parsed['error']}[/dim red]")
        return

    valid = parsed.get("valid", False)
    icon = "[bold green]✓[/bold green]" if valid else "[bold red]✗[/bold red]"
    console.print(f"  {icon} Number: [bold white]{parsed.get('e164_format', 'unknown')}[/bold white]  ({parsed.get('national_format', '')})")
    console.print(f"  [bold white]Country:[/bold white] {parsed.get('country', 'unknown')} ({parsed.get('country_code', '')})")
    console.print(f"  [bold white]Type:[/bold white] [cyan]{parsed.get('number_type', 'unknown')}[/cyan]")
    if parsed.get("carrier"):
        console.print(f"  [bold white]Carrier:[/bold white] {parsed.get('carrier')}")

    # Risk
    risk = phone_data.get("risk", {})
    if risk:
        rlevel = risk.get("risk_level", "LOW")
        rlcolor = {"LOW": "green", "MODERATE": "yellow", "HIGH": "red"}.get(rlevel, "white")
        console.print(f"  [bold white]Risk:[/bold white] [{rlcolor}]{rlevel}[/{rlcolor}]")
        for flag in risk.get("flags", []):
            console.print(f"    [yellow]⚠  {flag}[/yellow]")

    console.print()


def print_platform_section(platform_data: dict) -> None:
    console.print(Rule("[bold white]PLATFORM SWEEP[/bold white]", style="dim white"))
    if not isinstance(platform_data, dict):
        console.print("  [dim red]No platform data available[/dim red]")
        return

    results = platform_data.get("results", [])
    found = [r for r in results if r.get("found")]
    not_found = [r for r in results if not r.get("found")]

    total = len(results)
    found_count = len(found)
    console.print(f"  [bold white]Scanned:[/bold white] {total} platforms  "
                  f"[bold green]Found:[/bold green] {found_count}  "
                  f"[dim red]Not found:[/dim red] {total - found_count}")
    console.print()

    if not found:
        console.print("  [dim]No accounts found on any platform[/dim]")
        console.print()
        return

    # Group by category
    categories = defaultdict(list)
    for r in found:
        categories[r.get("category", "misc")].append(r)

    for cat, entries in sorted(categories.items()):
        console.print(f"  [bold white]{cat.upper()}[/bold white]")
        for e in entries:
            enriched = e.get("enriched", {})
            ms = e.get("response_time_ms", 0)
            meta_parts = []
            if enriched.get("display_name"):
                meta_parts.append(f"[bold white]{enriched['display_name']}[/bold white]")
            if enriched.get("bio"):
                meta_parts.append(f"[dim]{enriched['bio'][:60]}[/dim]")
            if enriched.get("followers") is not None:
                meta_parts.append(f"[cyan]{enriched['followers']} followers[/cyan]")
            if enriched.get("location"):
                meta_parts.append(f"[dim white]📍{enriched['location']}[/dim white]")
            meta_str = "  ".join(meta_parts)
            console.print(f"    [bold green]✓[/bold green] [cyan]{e['platform']:25s}[/cyan] [dim]{e['url'][:60]}[/dim]  [dim]({ms}ms)[/dim]")
            if meta_str:
                console.print(f"      {meta_str}")
    console.print()

    # Summary stats
    avg_ms = sum(r.get("response_time_ms", 0) for r in found) / len(found) if found else 0
    console.print(f"  [dim white]Avg response time (found accounts): {avg_ms:.0f}ms[/dim white]")
    console.print()


def print_correlation_section(correlation_data: dict) -> None:
    console.print(Rule("[bold white]CORRELATIONS[/bold white]", style="dim white"))
    if not isinstance(correlation_data, dict):
        console.print("  [dim]No correlation data[/dim]")
        return

    correlations = correlation_data.get("correlations", [])
    cross_links = correlation_data.get("cross_links", [])
    risk_boosts = correlation_data.get("risk_boosts", [])

    if correlations:
        for c in correlations:
            conf_color = _TAG_COLORS.get(c.get("confidence", "INFERRED"), "white")
            console.print(f"  [{conf_color}]●[/{conf_color}] [white]{c.get('description', '')}[/white]  [dim]{c.get('type', '')}[/dim]")

    if cross_links:
        console.print()
        console.print("  [bold white]Bio-Linked Accounts:[/bold white]")
        for l in cross_links[:10]:
            console.print(f"    [cyan]{l.get('platform', '?'):15s}[/cyan] @{l.get('username', '?')}  [dim]{l.get('url', '')}[/dim]")

    if risk_boosts:
        console.print()
        console.print("  [bold white]Risk Boosts:[/bold white]")
        for b in risk_boosts:
            console.print(f"    [yellow]+{b.get('boost')} pts[/yellow]  {b.get('reason', '')}")

    if not correlations and not cross_links:
        console.print("  [dim]No significant correlations found[/dim]")

    console.print()


def print_persona_section(personas: list) -> None:
    console.print(Rule("[bold white]PERSONA CLUSTERS[/bold white]", style="dim white"))
    if not personas:
        console.print("  [dim]No persona data[/dim]")
        return

    for i, persona in enumerate(personas, 1):
        confidence = persona.get("confidence", "INFERRED")
        tag = _tag(confidence)
        console.print(f"  {tag} [bold white]Persona {i}: {persona.get('persona_label', 'Unknown')}[/bold white]")
        platforms = persona.get("platforms", [])
        if platforms:
            console.print(f"    Platforms: [cyan]{', '.join(platforms[:15])}[/cyan]")
        categories = persona.get("categories", {})
        if categories:
            for cat, plats in categories.items():
                console.print(f"    [dim white]{cat}:[/dim white] {', '.join(plats[:8])}")
        linked = persona.get("linked_to", [])
        if linked:
            console.print(f"    Linked to: [dim cyan]{', '.join(linked[:3])}[/dim cyan]")
        console.print()


def print_timeline_section(timeline: list) -> None:
    console.print(Rule("[bold white]ACTIVITY TIMELINE[/bold white]", style="dim white"))
    if not timeline:
        console.print("  [dim]No timeline events found[/dim]")
        console.print()
        return

    last_year = None
    for event in timeline:
        date_str = event.get("date", "")
        year = date_str[:4] if date_str else "????"
        if year != last_year:
            console.print(f"\n  [bold white]── {year} ──[/bold white]")
            last_year = year

        conf = event.get("confidence", "INFERRED")
        conf_color = _TAG_COLORS.get(conf, "white")
        etype = event.get("type", "event")
        icon = {"breach": "💥", "account_creation": "🆕", "paste": "📋"}.get(etype, "•")
        console.print(f"    [{conf_color}]{icon}[/{conf_color}]  [white]{event.get('event', '')}[/white]  [dim]({event.get('source', '')})[/dim]  [dim white]{date_str}[/dim white]")

    console.print()


def print_google_dorks(dorks: list) -> None:
    console.print(Rule("[bold white]GOOGLE DORKS[/bold white]", style="dim white"))
    if not dorks:
        console.print("  [dim]No dorks generated[/dim]")
        return
    dork_text = "\n".join(dorks)
    console.print(Panel(dork_text, title="[bold white]Search Dorks (copy & paste)[/bold white]", border_style="dim cyan", padding=(1, 2)))
    console.print()


def print_gravity_score(score_data: dict) -> None:
    console.print()
    console.print(Rule("[bold white]GRAVITY SCORE[/bold white]", style="white"))
    if not isinstance(score_data, dict):
        console.print("  [dim]Score unavailable[/dim]")
        return

    score = score_data.get("score", 0)
    band = score_data.get("band", "LOW")
    band_color = _BAND_COLORS.get(band, "white")
    breakdown = score_data.get("breakdown", {})
    top_factors = score_data.get("top_risk_factors", [])

    # Big score display
    score_text = Text()
    score_text.append(f"\n  GRAVITY SCORE: ", style="bold white")
    score_text.append(f"{score}/100", style=f"bold {band_color}")
    score_text.append(f"  ── RISK BAND: ", style="bold white")
    if band == "CRITICAL":
        score_text.append(band, style="bold red blink")
    else:
        score_text.append(band, style=f"bold {band_color}")
    console.print(score_text)

    # Progress bar (manual)
    filled = int(score / 5)  # 20 blocks = 100%
    bar = "█" * filled + "░" * (20 - filled)
    console.print(f"\n  [{band_color}]{bar}[/{band_color}]  [dim]{score}%[/dim]\n")

    # Breakdown table
    if breakdown:
        t = Table(box=box.SIMPLE, show_header=True, padding=(0, 2))
        t.add_column("Component", style="dim white")
        t.add_column("Score", style="bold white", justify="right")
        for component, pts in breakdown.items():
            label = component.replace("_", " ").title()
            color = "green" if pts == 0 else ("yellow" if pts < 10 else "red")
            t.add_row(label, f"[{color}]+{pts}[/{color}]")
        console.print(t)

    # Top risk factors
    if top_factors:
        console.print("  [bold white]Top Risk Factors:[/bold white]")
        for factor in top_factors:
            console.print(f"    [yellow]►[/yellow] {factor}")

    console.print()


def render_all(all_results: dict, correlations: dict, personas: list, timeline: list, score: dict) -> None:
    """Render all output sections."""
    # Breach
    if all_results.get("breach") or all_results.get("pastes"):
        print_breach_section(all_results.get("breach", {}))
        if all_results.get("pastes"):
            print_paste_section(all_results.get("pastes", {}))

    # Email
    if all_results.get("email_intel"):
        print_email_section(all_results["email_intel"])

    # Dorks
    if all_results.get("dorks"):
        print_google_dorks(all_results["dorks"])

    # IP
    if all_results.get("ip"):
        print_ip_section(all_results["ip"])

    # Phone
    if all_results.get("phone"):
        print_phone_section(all_results["phone"])

    # Platform sweep
    if all_results.get("platforms") is not None:
        print_platform_section({"results": all_results.get("platform_enriched", all_results.get("platforms", []))})

    # Correlation
    if correlations:
        print_correlation_section(correlations)

    # Personas
    if personas:
        print_persona_section(personas)

    # Timeline
    print_timeline_section(timeline)

    # Score (always last)
    print_gravity_score(score)
