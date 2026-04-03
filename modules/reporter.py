from rich.console import Console
from rich.table import Table
from rich import print as rprint
from datetime import datetime
import json
import os

console = Console()

def print_whois(data):
    console.rule("[bold cyan]WHOIS[/bold cyan]")
    table = Table(show_header=False, border_style="cyan")
    table.add_column("Champ", style="bold")
    table.add_column("Valeur")
    for key, value in data.items():
        table.add_row(key, str(value))
    console.print(table)

def print_dns(data):
    console.rule("[bold green]DNS[/bold green]")
    table = Table(show_header=False, border_style="green")
    table.add_column("Type", style="bold")
    table.add_column("Valeur")
    for record_type, values in data.items():
        table.add_row(record_type, "\n".join(values) if values else "—")
    console.print(table)

def print_subdomains(data):
    console.rule("[bold yellow]SOUS-DOMAINES[/bold yellow]")
    if not data:
        console.print("[dim]Aucun sous-domaine trouvé[/dim]")
        return
    for sub in data:
        console.print(f"  [green]✔[/green] {sub}")
    console.print(f"\n[bold]{len(data)} sous-domaine(s) trouvé(s)[/bold]")

def print_virustotal(data):
    console.rule("[bold red]VIRUSTOTAL[/bold red]")
    table = Table(show_header=False, border_style="red")
    table.add_column("Champ", style="bold")
    table.add_column("Valeur")
    color = "red" if data.get("malicious", 0) > 0 else "green"
    table.add_row("Réputation", str(data.get("reputation", "N/A")))
    table.add_row("Malicious", f"[{color}]{data.get('malicious', 0)}[/{color}]")
    table.add_row("Suspicious", str(data.get("suspicious", 0)))
    table.add_row("Harmless", str(data.get("harmless", 0)))
    console.print(table)

def print_shodan(data):
    console.rule("[bold magenta]SHODAN[/bold magenta]")
    if "error" in data:
        console.print(f"[red]Erreur : {data['error']}[/red]")
        return
    table = Table(show_header=False, border_style="magenta")
    table.add_column("Champ", style="bold")
    table.add_column("Valeur")
    table.add_row("IP", data.get("ip", "N/A"))
    table.add_row("Organisation", data.get("organisation", "N/A"))
    table.add_row("Pays", data.get("pays", "N/A"))
    table.add_row("Ports ouverts", str(data.get("ports_ouverts", [])))
    console.print(table)

def export_json(domain, whois, dns, subdomains, virustotal, shodan):
    os.makedirs("output", exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"output/{domain}_{timestamp}.json"
    report = {
        "domain": domain,
        "date": timestamp,
        "whois": whois,
        "dns": dns,
        "subdomains": subdomains,
        "virustotal": virustotal,
        "shodan": shodan,
    }
    with open(filename, "w") as f:
        json.dump(report, f, indent=4, default=str)
    console.print(f"\n[bold green]✔ Rapport exporté : {filename}[/bold green]")