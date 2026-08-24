#!/usr/bin/env python3
"""ATLAS OSINT: small, public-source terminal research toolkit."""

from __future__ import annotations

import ipaddress
import json
import re
import socket
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import dns.resolver
import requests
from pyfiglet import Figlet
from rich.console import Console
from rich.panel import Panel
from rich.prompt import Confirm, Prompt
from rich.table import Table

APP_NAME = "atlas-osint"
CONFIG_PATH = Path.home() / ".config" / APP_NAME / "config.json"
OUTPUT_DIR = Path("atlas-results")
TIMEOUT = 10
USER_AGENT = "ATLAS-OSINT/1.0 (+https://github.com/seqyra/atlas-osint)"
console = Console()

USERNAME_SITES = {
    "GitHub": "https://github.com/{username}",
    "GitLab": "https://gitlab.com/{username}",
    "Reddit": "https://www.reddit.com/user/{username}/",
    "TikTok": "https://www.tiktok.com/@{username}",
    "Instagram": "https://www.instagram.com/{username}/",
    "X": "https://x.com/{username}",
    "Twitch": "https://www.twitch.tv/{username}",
    "Pinterest": "https://www.pinterest.com/{username}/",
    "Telegram": "https://t.me/{username}",
    "VK": "https://vk.com/{username}",
    "OK": "https://ok.ru/{username}",
    "Steam": "https://steamcommunity.com/id/{username}",
    "Medium": "https://medium.com/@{username}",
    "Keybase": "https://keybase.io/{username}",
}


def load_nickname() -> str:
    try:
        data = json.loads(CONFIG_PATH.read_text(encoding="utf-8"))
        nickname = str(data.get("nickname", "")).strip()
        if nickname:
            return nickname
    except (OSError, ValueError, TypeError):
        pass

    nickname = Prompt.ask("Enter your nickname").strip() or "researcher"
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    CONFIG_PATH.write_text(
        json.dumps({"nickname": nickname}, ensure_ascii=False, indent=2),
        encoding="utf-8",
    )
    return nickname


def banner(nickname: str) -> None:
    figlet = Figlet(font="slant", width=110)
    console.print(f"[bold cyan]{figlet.renderText('ATLAS')}[/bold cyan]")
    console.print(Panel.fit(f"[bold green]WELCOME {nickname}[/bold green]", border_style="cyan"))


def request_json(url: str) -> Any:
    response = requests.get(url, headers={"User-Agent": USER_AGENT}, timeout=TIMEOUT)
    response.raise_for_status()
    return response.json()


def dns_values(name: str, record_type: str) -> list[str]:
    try:
        return sorted({str(record).rstrip(".") for record in dns.resolver.resolve(name, record_type)})
    except (dns.resolver.DNSException, ValueError):
        return []


def username_lookup(username: str) -> dict[str, Any]:
    username = username.strip().lstrip("@").replace("/", "")
    if not username:
        raise ValueError("Username is empty")

    rows = []
    for site, template in USERNAME_SITES.items():
        url = template.format(username=username)
        status: str
        try:
            response = requests.get(
                url,
                headers={"User-Agent": USER_AGENT},
                timeout=TIMEOUT,
                allow_redirects=True,
                stream=True,
            )
            if response.status_code == 200:
                status = "possible match"
            elif response.status_code == 404:
                status = "not found"
            elif response.status_code in {401, 403, 429}:
                status = f"inconclusive ({response.status_code})"
            else:
                status = f"inconclusive ({response.status_code})"
            response.close()
        except requests.RequestException as exc:
            status = f"error: {exc.__class__.__name__}"
        rows.append({"site": site, "status": status, "url": url})
    return {"type": "username", "target": username, "results": rows}


def domain_lookup(domain: str) -> dict[str, Any]:
    domain = domain.strip().lower().rstrip(".")
    if not re.fullmatch(r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z]{2,63}", domain):
        raise ValueError("Invalid domain name")

    records = {kind: dns_values(domain, kind) for kind in ("A", "AAAA", "MX", "NS", "TXT")}
    try:
        rdap = request_json(f"https://rdap.org/domain/{domain}")
    except requests.RequestException as exc:
        rdap = {"error": str(exc)}

    try:
        ct_data = request_json(f"https://crt.sh/?q=%25.{domain}&output=json")
        subdomains = sorted(
            {
                name.lower().lstrip("*.")
                for row in ct_data
                for name in str(row.get("name_value", "")).splitlines()
                if name.lower().lstrip("*.").endswith(domain)
            }
        )
    except (requests.RequestException, ValueError, TypeError) as exc:
        subdomains = [f"Lookup failed: {exc}"]

    return {
        "type": "domain",
        "target": domain,
        "dns": records,
        "rdap": rdap,
        "certificate_transparency_names": subdomains,
    }


def ip_lookup(value: str) -> dict[str, Any]:
    address = ipaddress.ip_address(value.strip())
    if not address.is_global:
        raise ValueError("Only public IP addresses can be queried")
    try:
        rdap = request_json(f"https://rdap.org/ip/{address.compressed}")
    except requests.RequestException as exc:
        rdap = {"error": str(exc)}
    try:
        reverse_dns = socket.gethostbyaddr(address.compressed)[0]
    except (socket.herror, socket.gaierror):
        reverse_dns = None
    return {"type": "ip", "target": address.compressed, "reverse_dns": reverse_dns, "rdap": rdap}


def email_lookup(email: str) -> dict[str, Any]:
    email = email.strip()
    match = re.fullmatch(r"[^@\s]+@([^@\s]+)", email)
    if not match:
        raise ValueError("Invalid email address")
    domain = match.group(1).lower().rstrip(".")
    txt = dns_values(domain, "TXT")
    return {
        "type": "email-domain",
        "target": email,
        "domain": domain,
        "mx": dns_values(domain, "MX"),
        "spf": [value for value in txt if "v=spf1" in value.lower()],
        "dmarc": dns_values(f"_dmarc.{domain}", "TXT"),
        "note": "ATLAS did not contact the mailbox or test whether it exists.",
    }


def print_result(result: dict[str, Any]) -> None:
    if result["type"] == "username":
        table = Table(title=f"Username: {result['target']}")
        table.add_column("Site", style="cyan")
        table.add_column("Status")
        table.add_column("URL", overflow="fold")
        for row in result["results"]:
            color = "green" if row["status"] == "possible match" else "yellow"
            table.add_row(row["site"], f"[{color}]{row['status']}[/{color}]", row["url"])
        console.print(table)
    else:
        console.print_json(data=result)


def export_result(result: dict[str, Any]) -> Path:
    OUTPUT_DIR.mkdir(exist_ok=True)
    safe_target = re.sub(r"[^a-zA-Z0-9._-]+", "_", str(result["target"]))[:80]
    timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    path = OUTPUT_DIR / f"{result['type']}-{safe_target}-{timestamp}.json"
    payload = {"generated_at": datetime.now(timezone.utc).isoformat(), **result}
    path.write_text(json.dumps(payload, ensure_ascii=False, indent=2), encoding="utf-8")
    return path


def main() -> None:
    nickname = load_nickname()
    banner(nickname)
    actions = {"1": username_lookup, "2": domain_lookup, "3": ip_lookup, "4": email_lookup}

    while True:
        console.print("\n[cyan]1[/cyan] Username  [cyan]2[/cyan] Domain  [cyan]3[/cyan] IP  [cyan]4[/cyan] Email infrastructure  [cyan]0[/cyan] Exit")
        choice = Prompt.ask("Select", choices=["0", "1", "2", "3", "4"], default="1")
        if choice == "0":
            console.print("[cyan]Stay curious. Verify your findings.[/cyan]")
            return
        target = Prompt.ask("Target")
        try:
            result = actions[choice](target)
            print_result(result)
            if Confirm.ask("Export this result as JSON?", default=False):
                console.print(f"Saved to [green]{export_result(result)}[/green]")
        except (ValueError, OSError, requests.RequestException) as exc:
            console.print(f"[bold red]Lookup failed:[/bold red] {exc}")


if __name__ == "__main__":
    try:
        main()
    except KeyboardInterrupt:
        console.print("\n[yellow]Cancelled.[/yellow]")

