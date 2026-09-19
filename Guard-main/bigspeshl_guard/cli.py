from __future__ import annotations

import argparse
import os
import time
from typing import Optional

from rich import box
from rich.align import Align
from rich.console import Console
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from .engine import GuardEngine, ThreatEvent, simulate_mode
from .simulator import TrafficSimulator

console = Console()


def print_banner() -> None:
    console.print()
    console.print(Align.center("[bold white on red]BigSpeshl-GUARD[/bold white on red]"), style="bold")
    console.print(Align.center("[cyan]Autonomous DDoS Defense / Threat Mitigation[/cyan]"))
    console.print()


def _safe_ip() -> str:
    return "203.0.113.7"


def show_status(engine: Optional[GuardEngine] = None) -> None:
    engine = engine or GuardEngine()
    summary = engine.summary()
    table = Table(title="Guard status")
    table.add_column("Metric", style="cyan")
    table.add_column("Value", style="magenta")
    table.add_row("Active sources", str(summary["active_sources"]))
    table.add_row("Blocked sources", str(summary["blocked_sources"]))
    table.add_row("Alert count", str(summary["threat_count"]))
    table.add_row("Avg target load", f"{summary['avg_target_load']}")
    table.add_row("Load factor", f"{summary['load_factor']}%")
    table.add_row("Window", f"{summary['window_seconds']}s")
    console.print(table)


def show_blocklist(engine: GuardEngine) -> None:
    if not engine.blocklist:
        console.print("[green]No active blocked IPs.[/green]")
        return
    table = Table(title="Blocked IPs", box=box.SIMPLE)
    table.add_column("IP", style="red")
    table.add_column("Expiry", style="yellow")
    for ip, expires in engine.blocklist.items():
        table.add_row(ip, expires.strftime("%H:%M:%S"))
    console.print(table)


def show_alerts(engine: GuardEngine, count: int = 10) -> None:
    alerts = engine.recent_alerts(limit=count)
    if not alerts:
        console.print("[green]No active alerts. Network normal.[/green]")
        return
    table = Table(title="Recent incidents", box=box.MINIMAL_DOUBLE_HEAD)
    table.add_column("Time", style="cyan")
    table.add_column("IP", style="yellow")
    table.add_column("Attack", style="bold red")
    table.add_column("Action", style="green")
    for alert in alerts:
        table.add_row(alert["timestamp"], alert["source_ip"], alert["attack"], alert["action"])
    console.print(table)


def run_watch(duration: float = 12.0, mode: str = "mixed") -> None:
    engine = GuardEngine()
    simulator = TrafficSimulator(engine, mode=mode, interval=0.4)
    print_banner()
    console.print(Panel.fit(f"Monitoring mode: [bold]{mode}[/bold] | Duration: {duration}s", border_style="cyan"))

    with Live(console=console, refresh_per_second=6, transient=False) as live:
        start = time.monotonic()
        while time.monotonic() - start < duration:
            alerts = simulator.run_once()
            if alerts:
                summary = engine.summary()
                live.update(
                    Panel.fit(
                        f"[bold red]BigSpeshl-GUARD[/bold red]\n\n"
                        f"Threats: {summary['threat_count']} | Blocked: {summary['blocked_sources']} | Active: {summary['active_sources']}\n"
                        f"Last alert: {alerts[-1]['source_ip']} -> {alerts[-1]['action']}"
                    )
                )
            else:
                summary = engine.summary()
                live.update(
                    Panel.fit(
                        f"[bold red]BigSpeshl-GUARD[/bold red]\n\n"
                        f"Threats: {summary['threat_count']} | Blocked: {summary['blocked_sources']} | Active: {summary['active_sources']}\n"
                        f"Status: [green]Monitoring normal flow[/green]"
                    )
                )
            time.sleep(0.5)

    console.print("[green]Monitoring session complete.[/green]")
    show_status(engine)
    show_alerts(engine)
    show_blocklist(engine)


def interactive_menu() -> None:
    engine = GuardEngine()
    while True:
        print_banner()
        table = Table(title="Command menu", box=box.SIMPLE_HEAVY)
        table.add_column("Option", style="cyan")
        table.add_column("Action", style="magenta")
        table.add_row("1", "Live monitor")
        table.add_row("2", "Simulate SYN flood")
        table.add_row("3", "Simulate UDP reflection")
        table.add_row("4", "Simulate HTTP flood")
        table.add_row("5", "Show status")
        table.add_row("6", "Show blocklist")
        table.add_row("7", "Show alerts")
        table.add_row("8", "Exit")
        console.print(table)
        choice = console.input("[bold yellow]Select action:[/bold yellow] ")

        if choice == "1":
            run_watch(duration=12.0, mode="mixed")
        elif choice == "2":
            run_watch(duration=10.0, mode="syn_flood")
        elif choice == "3":
            run_watch(duration=10.0, mode="udp_reflection")
        elif choice == "4":
            run_watch(duration=10.0, mode="http_flood")
        elif choice == "5":
            show_status(engine)
        elif choice == "6":
            show_blocklist(engine)
        elif choice == "7":
            show_alerts(engine)
        elif choice == "8":
            console.print("[green]BigSpeshl-GUARD shutdown complete.[/green]")
            break
        else:
            console.print("[red]Invalid option. Try again.[/red]")

        console.input("[bold white]Press Enter to continue...[/bold white]")
        os.system('cls' if os.name == 'nt' else 'clear')


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BigSpeshl-GUARD autonomous DDoS protection CLI")
    parser.add_argument("--mode", choices=["mixed", "syn_flood", "udp_reflection", "http_flood"], default="mixed")
    parser.add_argument("--duration", type=float, default=10.0)
    parser.add_argument("--status", action="store_true")
    parser.add_argument("--interactive", action="store_true")
    return parser


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()

    if args.status:
        print_banner()
        show_status(GuardEngine())
        return

    if args.interactive or not any([args.status, args.mode]):
        interactive_menu()
        return

    print_banner()
    engine = GuardEngine()
    simulator = TrafficSimulator(engine, mode=args.mode, interval=0.3)
    alerts = simulator.run(duration=args.duration)
    console.print(Panel.fit(f"Simulation: {args.mode} | Duration: {args.duration}s", border_style="magenta"))
    show_status(engine)
    show_alerts(engine)
    show_blocklist(engine)


if __name__ == "__main__":
    main()
