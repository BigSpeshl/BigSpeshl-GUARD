from __future__ import annotations

import json
import ipaddress
import os
from pathlib import Path
from typing import Dict, Optional


DEFAULT_CONFIG: Dict[str, object] = {
    "window_seconds": 10,
    "interface": "",
    "attacks": {
        "syn_flood": {"threshold_requests": 300, "block_seconds": 1200},
        "udp_reflection": {"threshold_requests": 300, "block_seconds": 1200},
        "http_flood": {"threshold_requests": 300, "block_seconds": 1200},
    },
    "discord": {
        "enabled": False,
        "bot_token": "",
        "channel_id": "",
        "guild_id": "",
    },
    "firewall": {
        "enabled": False,
        "protected_networks": [
            "127.0.0.0/8",
            "::1/128",
            "10.0.0.0/8",
            "172.16.0.0/12",
            "192.168.0.0/16",
            "fc00::/7",
        ],
    },
}


def default_config_path() -> Path:
    if os.name == "nt":
        base = Path(os.environ.get("APPDATA", Path.home() / "AppData" / "Roaming"))
    else:
        base = Path(os.environ.get("XDG_CONFIG_HOME", Path.home() / ".config"))
    return base / "bigspeshl-guard" / "config.json"


def _positive_int(value: object, name: str) -> int:
    if isinstance(value, bool) or not isinstance(value, int) or value <= 0:
        raise ValueError(f"Параметр {name} должен быть целым числом больше нуля.")
    return value


def validate_config(data: object) -> Dict[str, object]:
    if not isinstance(data, dict):
        raise ValueError("Корень конфигурации должен быть JSON-объектом.")

    attacks = data.get("attacks", {})
    discord = data.get("discord", {})
    firewall = data.get("firewall", {})
    interface = data.get("interface", "")
    if not isinstance(attacks, dict) or not isinstance(discord, dict) or not isinstance(firewall, dict):
        raise ValueError("Поля attacks, discord и firewall должны быть JSON-объектами.")
    if not isinstance(interface, str) or any(char.isspace() for char in interface):
        raise ValueError("Имя сетевого интерфейса должно быть строкой без пробелов.")

    window = _positive_int(data.get("window_seconds", DEFAULT_CONFIG["window_seconds"]), "window_seconds")
    validated_attacks: Dict[str, Dict[str, int]] = {}
    defaults = DEFAULT_CONFIG["attacks"]
    assert isinstance(defaults, dict)
    for attack_name, default_policy in defaults.items():
        policy = attacks.get(attack_name, default_policy)
        if not isinstance(policy, dict):
            raise ValueError(f"Настройки атаки {attack_name} должны быть JSON-объектом.")
        validated_attacks[attack_name] = {
            "threshold_requests": _positive_int(
                policy.get("threshold_requests", default_policy["threshold_requests"]),
                f"{attack_name}.threshold_requests",
            ),
            "block_seconds": _positive_int(
                policy.get("block_seconds", default_policy["block_seconds"]),
                f"{attack_name}.block_seconds",
            ),
        }

    token = discord.get("bot_token", "")
    channel_id = discord.get("channel_id", "")
    guild_id = discord.get("guild_id", "")
    enabled = discord.get("enabled", False)
    if not isinstance(token, str) or not isinstance(channel_id, str) or not isinstance(guild_id, str):
        raise ValueError("Токен бота и Discord ID должны быть строками.")
    if not isinstance(enabled, bool):
        raise ValueError("Параметр discord.enabled должен быть логическим значением.")
    for name, value in (("channel_id", channel_id), ("guild_id", guild_id)):
        if value and not value.isdigit():
            raise ValueError(f"Параметр discord.{name} должен содержать только цифры.")
    if enabled and not all((token.strip(), channel_id, guild_id)):
        raise ValueError("Для Discord-уведомлений укажите токен бота, ID канала и ID сервера.")
    firewall_enabled = firewall.get("enabled", False)
    protected_networks = firewall.get(
        "protected_networks",
        DEFAULT_CONFIG["firewall"]["protected_networks"],
    )
    if not isinstance(firewall_enabled, bool):
        raise ValueError("Параметр firewall.enabled должен быть логическим значением.")
    if not isinstance(protected_networks, list) or not all(
        isinstance(network, str) for network in protected_networks
    ):
        raise ValueError("firewall.protected_networks должен быть списком CIDR-сетей.")
    try:
        normalized_networks = [
            str(ipaddress.ip_network(network, strict=False))
            for network in protected_networks
        ]
    except ValueError as error:
        raise ValueError(f"Некорректная сеть в firewall.protected_networks: {error}") from error

    return {
        "window_seconds": window,
        "interface": interface,
        "attacks": validated_attacks,
        "discord": {
            "enabled": enabled,
            "bot_token": token.strip(),
            "channel_id": channel_id,
            "guild_id": guild_id,
        },
        "firewall": {
            "enabled": firewall_enabled,
            "protected_networks": normalized_networks,
        },
    }


def load_config(path: Optional[Path] = None) -> Dict[str, object]:
    config_path = path or default_config_path()
    if not config_path.exists():
        return validate_config(DEFAULT_CONFIG)
    try:
        data = json.loads(config_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as error:
        raise RuntimeError(f"Не удалось прочитать конфигурацию {config_path}: {error}") from error
    try:
        return validate_config(data)
    except ValueError as error:
        raise RuntimeError(f"Некорректная конфигурация {config_path}: {error}") from error


def save_config(config: Dict[str, object], path: Optional[Path] = None) -> Path:
    config_path = path or default_config_path()
    validated = validate_config(config)
    try:
        config_path.parent.mkdir(parents=True, exist_ok=True)
        temporary_path = config_path.with_suffix(config_path.suffix + ".tmp")
        temporary_path.write_text(
            json.dumps(validated, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        try:
            os.chmod(temporary_path, 0o600)
        except OSError:
            if os.name != "nt":
                raise
        temporary_path.replace(config_path)
        try:
            os.chmod(config_path, 0o600)
        except OSError:
            if os.name != "nt":
                raise
    except OSError as error:
        raise RuntimeError(f"Не удалось сохранить конфигурацию {config_path}: {error}") from error
    return config_path
