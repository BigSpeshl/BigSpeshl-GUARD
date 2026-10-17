from __future__ import annotations

import json
from typing import Dict, Optional
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen


class DiscordNotifier:
    def __init__(self, config: Dict[str, object]) -> None:
        self.config = config
        self._guild_verified = False

    def _request(self, method: str, endpoint: str, payload: Optional[dict] = None) -> dict:
        token = self.config.get("bot_token", "")
        request = Request(
            "https://discord.com/api/v10" + endpoint,
            data=json.dumps(payload).encode("utf-8") if payload is not None else None,
            headers={
                "Authorization": f"Bot {token}",
                "Content-Type": "application/json",
                "User-Agent": "BigSpeshl-GUARD/0.1",
            },
            method=method,
        )
        try:
            with urlopen(request, timeout=5) as response:
                body = response.read()
            return json.loads(body.decode("utf-8")) if body else {}
        except HTTPError as error:
            detail = error.read().decode("utf-8", errors="replace")
            raise RuntimeError(f"Discord API вернул HTTP {error.code}: {detail[:300]}") from error
        except (URLError, TimeoutError, OSError) as error:
            raise RuntimeError(f"Не удалось связаться с Discord: {error}") from error
        except json.JSONDecodeError as error:
            raise RuntimeError("Discord API вернул некорректный JSON.") from error

    def _verify_channel(self) -> None:
        if self._guild_verified:
            return
        channel_id = self.config["channel_id"]
        guild_id = self.config["guild_id"]
        channel = self._request("GET", f"/channels/{channel_id}")
        if str(channel.get("guild_id", "")) != str(guild_id):
            raise RuntimeError("Указанный канал не принадлежит заданному Discord-серверу.")
        self._guild_verified = True

    def send_alert(self, alert: dict) -> None:
        if not self.config.get("enabled"):
            return
        self._verify_channel()

        blocked = alert.get("action") == "block"
        title = "Атака обнаружена и отражена" if blocked else "Обнаружена подозрительная активность"
        firewall_applied = alert.get("firewall_applied")
        if blocked and firewall_applied:
            response = "IP заблокирован во внутреннем списке и firewall nftables"
        elif blocked:
            response = "IP добавлен во внутренний список; системный firewall не применён"
        else:
            response = "Зафиксировано превышение порога запросов"
        color = 0xE74C3C if blocked else 0xF1C40F
        request_count = alert.get("requests_in_window", 0)
        window_seconds = alert.get("window_seconds", 0)
        embed = {
            "title": title,
            "description": (
                "**BigSpeshl-GUARD** зафиксировал сетевую угрозу и применил настроенную реакцию."
            ),
            "color": color,
            "fields": [
                {"name": "Тип угрозы", "value": str(alert.get("attack", "неизвестно")), "inline": True},
                {"name": "Источник", "value": f"`{alert.get('source_ip', 'неизвестно')}`", "inline": True},
                {"name": "Протокол / порт", "value": f"{alert.get('protocol', '?')} / {alert.get('port') or '?'}", "inline": True},
                {"name": "Запросов за окно", "value": f"{request_count} за {window_seconds} с", "inline": True},
                {"name": "Реакция", "value": response, "inline": False},
            ],
            "footer": {"text": f"Сервер Discord: {self.config['guild_id']}"},
        }
        self._request(
            "POST",
            f"/channels/{self.config['channel_id']}/messages",
            {"embeds": [embed], "allowed_mentions": {"parse": []}},
        )
