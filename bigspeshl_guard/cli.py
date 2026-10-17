from __future__ import annotations

import argparse
import getpass
import os
import time
from pathlib import Path
from typing import Dict, Optional

from rich import box
from rich.align import Align
from rich.console import Console, Group
from rich.live import Live
from rich.panel import Panel
from rich.table import Table

from .config import default_config_path, load_config, save_config
from .capture import run_live_capture
from .discord_notify import DiscordNotifier
from .engine import ATTACK_NAMES, GuardEngine
from .firewall import NftablesFirewall
from .simulator import TrafficSimulator

console = Console()
MODE_NAMES = {
    "mixed": "Обычный смешанный трафик",
    "syn_flood": "Симуляция SYN flood",
    "udp_reflection": "Симуляция UDP reflection",
    "http_flood": "Симуляция HTTP flood",
    "live": "Захват реальных пакетов",
}


def print_banner() -> None:
    console.print()
    console.print(Align.center("[bold white on red] BigSpeshl-GUARD [/bold white on red]"))
    console.print(Align.center("[cyan]Обнаружение сетевых угроз и автоматическая защита[/cyan]"))
    console.print()


def create_engine(config: Dict[str, object]) -> GuardEngine:
    attacks = config["attacks"]
    if not isinstance(attacks, dict):
        raise ValueError("В конфигурации отсутствуют корректные политики атак.")
    policies = {
        attack: {
            "threshold_requests": policy["threshold_requests"],
            "block_seconds": policy["block_seconds"],
        }
        for attack, policy in attacks.items()
    }
    return GuardEngine(window_seconds=config["window_seconds"], attack_policies=policies)


def show_status(engine: GuardEngine) -> None:
    summary = engine.summary()
    table = Table(title="Состояние защиты", box=box.ROUNDED, border_style="cyan")
    table.add_column("Показатель", style="cyan")
    table.add_column("Значение", style="bold white")
    table.add_row("Активных IP в окне", str(summary["active_sources"]))
    table.add_row("Заблокировано IP", str(summary["blocked_sources"]))
    table.add_row("Обнаружено атак", str(summary["threat_count"]))
    table.add_row(f"Запросов за последние {summary['window_seconds']} с", str(summary["total_requests"]))
    console.print(table)


def show_blocklist(engine: GuardEngine) -> None:
    engine.summary()
    if not engine.blocklist:
        console.print("[green]Активных блокировок нет.[/green]")
        return
    table = Table(title="Заблокированные IP-адреса", box=box.ROUNDED, border_style="red")
    table.add_column("IP-адрес", style="red")
    table.add_column("Разблокировка", style="yellow")
    table.add_column("Осталось", style="cyan")
    now = time.time()
    for ip, expires in engine.blocklist.items():
        remaining = max(0, int(expires.timestamp() - now))
        table.add_row(ip, expires.astimezone().strftime("%H:%M:%S"), f"{remaining} с")
    console.print(table)


def show_alerts(engine: GuardEngine, count: int = 10) -> None:
    alerts = engine.recent_alerts(limit=count)
    if not alerts:
        console.print("[green]Угроз не обнаружено.[/green]")
        return
    table = Table(title="Последние инциденты", box=box.ROUNDED, border_style="yellow")
    table.add_column("Время", style="cyan")
    table.add_column("Источник", style="yellow")
    table.add_column("Атака", style="bold red")
    table.add_column("Запросы / окно", justify="right")
    table.add_column("Действие", style="green")
    for alert in alerts:
        table.add_row(
            alert["timestamp"],
            alert["source_ip"],
            alert["attack"],
            str(alert["requests_in_window"]),
            f"внутренняя блокировка на {alert['block_seconds']} с",
        )
    console.print(table)


def traffic_table(engine: GuardEngine) -> Table:
    table = Table(
        title=f"IP-источники за окно {engine.window_seconds} с",
        box=box.ROUNDED,
        border_style="cyan",
        expand=True,
    )
    table.add_column("IP-адрес", style="yellow", no_wrap=True)
    table.add_column(f"Пакетов/запросов за {engine.window_seconds} с", justify="right", style="white")
    table.add_column("Пакетов/запросов в секунду", justify="right", style="magenta")
    table.add_column("Протоколы (количество)", style="cyan")
    table.add_column("Порты", style="blue")
    table.add_column("Состояние", style="green")

    rows = engine.traffic_stats()
    for row in rows:
        protocol_summary = ", ".join(
            f"{protocol}: {count}" for protocol, count in sorted(row["protocols"].items())
        )
        ports = ", ".join(str(port) for port in row["ports"]) or "—"
        table.add_row(
            row["source_ip"],
            str(row["requests"]),
            f"{row['requests_per_second']:.1f}",
            protocol_summary,
            ports,
            "[red]БЛОК В GUARD[/red]" if row["blocked"] else "[green]Активен[/green]",
        )
    if not rows:
        table.add_row("—", "0", "0.0", "—", "—", "Ожидание трафика")
    return table


def dashboard(engine: GuardEngine, mode: str, duration: float) -> Group:
    summary = engine.summary()
    latest_alerts = engine.recent_alerts(limit=3)
    last_attack = (
        f"Последняя угроза: {latest_alerts[0]['source_ip']} — {latest_alerts[0]['attack']}"
        if latest_alerts
        else "Угроз не обнаружено"
    )
    status = (
        f"[bold]BigSpeshl-GUARD[/bold]\n"
        f"Режим: [cyan]{MODE_NAMES[mode]}[/cyan]  |  "
        f"Время: {'реальное время' if mode == 'live' else f'{duration:.0f} с'}  |  "
        f"IP: {summary['active_sources']}  |  Запросов: {summary['total_requests']}  |  "
        f"Блокировок: {summary['blocked_sources']}\n{last_attack}"
    )
    return Group(
        Panel(status, border_style="red", title="Мониторинг событий"),
        traffic_table(engine),
    )


def run_watch(
    engine: GuardEngine,
    config: Dict[str, object],
    duration: float = 12.0,
    mode: str = "mixed",
) -> None:
    simulator = TrafficSimulator(engine, mode=mode, interval=0.4)
    discord_settings = config["discord"]
    if not isinstance(discord_settings, dict):
        raise ValueError("В конфигурации Discord некорректные настройки.")
    notifier = DiscordNotifier(discord_settings)
    print_banner()
    console.print(
        Panel(
            f"[bold]{MODE_NAMES[mode]}[/bold] • Продолжительность: {duration:.0f} с\n"
            "[yellow]Тестовый режим использует только синтетические события; сетевые пакеты не захватываются.[/yellow]",
            border_style="cyan",
        )
    )

    with Live(dashboard(engine, mode, duration), console=console, refresh_per_second=4) as live:
        start = time.monotonic()
        while time.monotonic() - start < duration:
            for alert in simulator.run_once():
                if discord_settings.get("enabled"):
                    try:
                        notifier.send_alert(alert)
                    except RuntimeError as error:
                        live.console.print(f"[bold red]Ошибка Discord-уведомления:[/bold red] {error}")
            live.update(dashboard(engine, mode, duration))
            time.sleep(0.5)

    console.print("[green]Сеанс мониторинга завершён.[/green]")
    show_alerts(engine)
    show_blocklist(engine)


def run_live_watch(
    engine: GuardEngine,
    config: Dict[str, object],
    interface: str,
    duration: Optional[float] = None,
) -> bool:
    firewall_config = config["firewall"]
    discord_settings = config["discord"]
    if not isinstance(firewall_config, dict) or not isinstance(discord_settings, dict):
        raise ValueError("Некорректные настройки firewall или Discord.")
    firewall = None
    notifier = DiscordNotifier(discord_settings)

    try:
        if firewall_config["enabled"]:
            firewall = NftablesFirewall(firewall_config["protected_networks"])
            firewall.ensure_ready()
    except RuntimeError as error:
        console.print(f"[bold red]Ошибка настройки firewall:[/bold red] {error}")
        return False

    print_banner()
    firewall_status = (
        "[green]nftables включён[/green]" if firewall else "[yellow]только внутренний список (firewall выключен)[/yellow]"
    )
    duration_label = f"{duration:.0f} с" if duration is not None else "без ограничения"
    console.print(
        Panel(
            f"[bold]Захват реальных пакетов[/bold]\n"
            f"Интерфейс: [cyan]{interface}[/cyan] • Время: {duration_label}\n"
            f"Firewall: {firewall_status}\n"
            "[dim]Видны IP/порты уровня IP. HTTP анализируется только для незашифрованного HTTP; "
            "HTTPS содержимое не читается.[/dim]",
            border_style="cyan",
        )
    )

    mode = "live"
    live = None

    def output(message: str) -> None:
        (live.console if live else console).print(message)

    def handle_alert(alert: dict) -> None:
        alert["firewall_applied"] = False
        if firewall:
            try:
                alert["firewall_applied"] = firewall.block_ip(
                    alert["source_ip"],
                    alert["block_seconds"],
                )
                if not alert["firewall_applied"]:
                    output(
                        f"[yellow]Firewall пропустил {alert['source_ip']}: "
                        "адрес входит в защищённую сеть.[/yellow]"
                    )
            except (RuntimeError, ValueError) as error:
                output(
                    f"[bold red]Не удалось применить правило firewall для "
                    f"{alert['source_ip']}:[/bold red] {error}"
                )
        if discord_settings.get("enabled"):
            try:
                notifier.send_alert(alert)
            except RuntimeError as error:
                output(f"[bold red]Ошибка Discord-уведомления:[/bold red] {error}")
        mitigation = (
            "приложение + nftables" if alert["firewall_applied"]
            else "только внутренний список приложения"
        )
        output(
            f"[bold red]Обнаружена атака:[/bold red] {alert['attack']} • "
            f"{alert['source_ip']} • {alert['requests_in_window']} за "
            f"{alert['window_seconds']} с • {mitigation} на {alert['block_seconds']} с"
        )

    def refresh_dashboard() -> None:
        if live:
            live.update(dashboard(engine, mode, duration or 0))

    try:
        if console.is_terminal:
            with Live(
                dashboard(engine, mode, duration or 0),
                console=console,
                refresh_per_second=2,
            ) as live:
                run_live_capture(engine, interface, handle_alert, refresh_dashboard, duration)
        else:
            console.print(
                f"Захват пакетов: интерфейс {interface}; "
                f"firewall {'nftables' if firewall else 'выключен'}."
            )
            run_live_capture(engine, interface, handle_alert, refresh_dashboard, duration)
    except RuntimeError as error:
        console.print(f"[bold red]Ошибка мониторинга:[/bold red] {error}")
        return False

    console.print("[green]Захват пакетов остановлен.[/green]")
    show_alerts(engine)
    show_blocklist(engine)
    return True


def _read_positive_int(label: str, current: int, minimum: int = 1) -> int:
    while True:
        value = console.input(f"{label} [{current}]: ").strip()
        if not value:
            return current
        try:
            parsed = int(value)
        except ValueError:
            console.print("[red]Введите целое число.[/red]")
            continue
        if parsed < minimum:
            console.print(f"[red]Значение должно быть не меньше {minimum}.[/red]")
            continue
        return parsed


def configure_protection(config: Dict[str, object], config_path: Path) -> None:
    print_banner()
    attacks = config["attacks"]
    console.print("[bold cyan]Параметры обнаружения и блокировки[/bold cyan]")
    config["window_seconds"] = _read_positive_int(
        "Окно подсчёта запросов (секунды)", config["window_seconds"]
    )
    for attack, display_name in ATTACK_NAMES.items():
        policy = attacks[attack]
        console.print(f"\n[bold]{display_name}[/bold]")
        policy["threshold_requests"] = _read_positive_int(
            "  Порог запросов за окно", policy["threshold_requests"]
        )
        policy["block_seconds"] = _read_positive_int(
            "  Время блокировки (секунды)", policy["block_seconds"]
        )

    current_interface = config.get("interface", "")
    config["interface"] = console.input(
        f"\nСетевой интерфейс для мониторинга (Enter — оставить {current_interface or 'не задан'}): "
    ).strip() or current_interface
    firewall = config["firewall"]
    firewall_answer = console.input(
        f"Включить правила nftables при живом мониторинге? [{'Д/н' if firewall['enabled'] else 'д/Н'}]: "
    ).strip().lower()
    if firewall_answer in {"д", "да", "y", "yes"}:
        firewall["enabled"] = True
    elif firewall_answer in {"н", "нет", "n", "no"}:
        firewall["enabled"] = False
    protected_networks = ", ".join(firewall["protected_networks"])
    edited_networks = console.input(
        f"Защищённые сети (не блокировать через nftables) [{protected_networks}]: "
    ).strip()
    if edited_networks:
        firewall["protected_networks"] = [
            network.strip() for network in edited_networks.split(",") if network.strip()
        ]

    saved_path = save_config(config, config_path)
    console.print(f"\n[green]Настройки сохранены:[/green] {saved_path}")
    console.print("[dim]Конфигурация защищена правами доступа только для владельца (где поддерживается).[/dim]")


def configure_discord(config: Dict[str, object], config_path: Path) -> None:
    discord = config["discord"]
    print_banner()
    console.print("[bold cyan]Discord-уведомления[/bold cyan]")
    console.print("[dim]Создайте бота в Discord Developer Portal и выдайте ему право отправлять сообщения в канал.[/dim]")
    enabled_answer = console.input(
        f"Включить уведомления? [{'Д/н' if discord['enabled'] else 'д/Н'}]: "
    ).strip().lower()
    if enabled_answer in {"д", "да", "y", "yes"}:
        discord["enabled"] = True
    elif enabled_answer in {"н", "нет", "n", "no"}:
        discord["enabled"] = False

    if discord["enabled"]:
        token = getpass.getpass("Токен бота (ввод скрыт; Enter — оставить текущий): ").strip()
        if token:
            discord["bot_token"] = token
        discord["channel_id"] = console.input(
            f"ID канала [{discord['channel_id']}]: "
        ).strip() or discord["channel_id"]
        discord["guild_id"] = console.input(
            f"ID сервера [{discord['guild_id']}]: "
        ).strip() or discord["guild_id"]
        if (
            not discord["bot_token"]
            or not discord["channel_id"].isdigit()
            or not discord["guild_id"].isdigit()
        ):
            console.print("[red]Укажите токен и числовые ID канала и сервера; уведомления оставлены выключенными.[/red]")
            discord["enabled"] = False

    saved_path = save_config(config, config_path)
    console.print(f"[green]Настройки Discord сохранены:[/green] {saved_path}")


def interactive_menu(config: Dict[str, object], config_path: Path) -> None:
    engine = create_engine(config)
    while True:
        print_banner()
        table = Table(title="Главное меню", box=box.ROUNDED, border_style="cyan")
        table.add_column("№", style="bold cyan", justify="right")
        table.add_column("Действие", style="white")
        table.add_row("1", "Мониторинг событий (смешанный трафик)")
        table.add_row("2", "Тест: симуляция SYN flood")
        table.add_row("3", "Тест: симуляция UDP reflection")
        table.add_row("4", "Тест: симуляция HTTP flood")
        table.add_row("5", "Настройки порогов и блокировок")
        table.add_row("6", "Настройки Discord-уведомлений")
        table.add_row("7", "Состояние защиты")
        table.add_row("8", "Список блокировок")
        table.add_row("9", "Последние инциденты")
        table.add_row("10", "Захват реальных пакетов (Linux / Scapy)")
        table.add_row("0", "Выход")
        console.print(table)
        choice = console.input("[bold yellow]Выберите действие:[/bold yellow] ").strip()

        if choice == "1":
            run_watch(engine, config, duration=12.0, mode="mixed")
        elif choice in {"2", "3", "4"}:
            mode = {"2": "syn_flood", "3": "udp_reflection", "4": "http_flood"}[choice]
            run_watch(engine, config, duration=10.0, mode=mode)
        elif choice == "5":
            configure_protection(config, config_path)
            attacks = config["attacks"]
            engine.update_policy(config["window_seconds"], attacks)
        elif choice == "6":
            configure_discord(config, config_path)
        elif choice == "7":
            show_status(engine)
        elif choice == "8":
            show_blocklist(engine)
        elif choice == "9":
            show_alerts(engine)
        elif choice == "10":
            interface = config.get("interface", "")
            if not interface:
                console.print(
                    "[red]Сетевой интерфейс не задан. Укажите его в настройках или через --interface.[/red]"
                )
            else:
                run_live_watch(engine, config, interface)
        elif choice == "0":
            console.print("[green]BigSpeshl-GUARD завершил работу.[/green]")
            break
        else:
            console.print("[red]Нет такого пункта меню.[/red]")

        if choice != "0":
            console.input("\n[dim]Нажмите Enter, чтобы продолжить...[/dim]")
            os.system("cls" if os.name == "nt" else "clear")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="BigSpeshl-GUARD — система обнаружения сетевых угроз")
    parser.add_argument("--mode", choices=["mixed", "syn_flood", "udp_reflection", "http_flood"])
    parser.add_argument("--duration", type=float, help="длительность мониторинга в секундах (без параметра — до остановки)")
    parser.add_argument("--live", action="store_true", help="запустить захват реальных пакетов (Linux)")
    parser.add_argument("--interface", help="имя сетевого интерфейса для захвата, например eth0")
    parser.add_argument("--status", action="store_true", help="показать состояние защиты")
    parser.add_argument("--interactive", action="store_true", help="открыть интерактивное меню")
    parser.add_argument("--config", type=Path, help="путь к JSON-файлу конфигурации")
    return parser


def main() -> None:
    args = build_parser().parse_args()
    config_path = args.config or default_config_path()
    config = load_config(config_path)

    if args.status:
        print_banner()
        show_status(create_engine(config))
        return
    if args.live:
        if args.duration is not None and args.duration <= 0:
            raise SystemExit("--duration должен быть больше нуля.")
        interface = args.interface or config.get("interface", "")
        if not interface:
            raise SystemExit("Укажите сетевой интерфейс через --interface или конфигурацию.")
        if not run_live_watch(create_engine(config), config, interface, duration=args.duration):
            raise SystemExit(1)
        return
    if args.interactive or args.mode is None:
        interactive_menu(config, config_path)
        return
    duration = args.duration if args.duration is not None else 10.0
    if duration <= 0:
        raise SystemExit("--duration должен быть больше нуля.")

    run_watch(create_engine(config), config, duration=duration, mode=args.mode)


if __name__ == "__main__":
    main()
