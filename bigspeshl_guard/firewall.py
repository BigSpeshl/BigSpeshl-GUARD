from __future__ import annotations

import ipaddress
import platform
import re
import shutil
import subprocess
from typing import Iterable, List, Optional


TABLE_NAME = "bigspeshl_guard"


class NftablesFirewall:
    """Manage only this application's nftables table; never flush other rules."""

    def __init__(
        self,
        protected_networks: Iterable[str] = (),
        runner=subprocess.run,
        system: Optional[str] = None,
    ) -> None:
        self.protected_networks = [
            ipaddress.ip_network(network, strict=False) for network in protected_networks
        ]
        self.runner = runner
        self.system = system or platform.system()

    def _run(self, arguments: List[str], input_text: Optional[str] = None) -> subprocess.CompletedProcess:
        try:
            result = self.runner(
                arguments,
                input=input_text,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as error:
            raise RuntimeError(f"Не удалось запустить nft: {error}") from error
        if result.returncode != 0:
            detail = (result.stderr or result.stdout or "нет подробностей").strip()
            raise RuntimeError(f"Команда nft завершилась с ошибкой: {detail}")
        return result

    def _exists(self, arguments: List[str]) -> bool:
        try:
            result = self.runner(
                arguments,
                capture_output=True,
                text=True,
                check=False,
            )
        except OSError as error:
            raise RuntimeError(f"Не удалось запустить nft: {error}") from error
        return result.returncode == 0

    def ensure_ready(self) -> None:
        if self.system != "Linux":
            raise RuntimeError("Системный firewall BigSpeshl-GUARD поддерживается только в Linux.")
        if shutil.which("nft") is None:
            raise RuntimeError("Не найдена команда nft. Установите nftables и повторите запуск.")
        if not self._exists(["nft", "list", "table", "inet", TABLE_NAME]):
            self._run(["nft", "add", "table", "inet", TABLE_NAME])

        ipv4_set = ["nft", "list", "set", "inet", TABLE_NAME, "blocked_ipv4"]
        if not self._exists(ipv4_set):
            self._run(
                ["nft", "-f", "-"],
                f"add set inet {TABLE_NAME} blocked_ipv4 "
                "{ type ipv4_addr; flags timeout; }\n",
            )
        else:
            details = self._run(ipv4_set).stdout
            if "type ipv4_addr" not in details or "flags timeout" not in details:
                raise RuntimeError("Таблица nftables содержит несовместимый набор blocked_ipv4.")

        ipv6_set = ["nft", "list", "set", "inet", TABLE_NAME, "blocked_ipv6"]
        if not self._exists(ipv6_set):
            self._run(
                ["nft", "-f", "-"],
                f"add set inet {TABLE_NAME} blocked_ipv6 "
                "{ type ipv6_addr; flags timeout; }\n",
            )
        else:
            details = self._run(ipv6_set).stdout
            if "type ipv6_addr" not in details or "flags timeout" not in details:
                raise RuntimeError("Таблица nftables содержит несовместимый набор blocked_ipv6.")

        chain_arguments = ["nft", "list", "chain", "inet", TABLE_NAME, "input_guard"]
        if not self._exists(chain_arguments):
            self._run(
                ["nft", "-f", "-"],
                f"add chain inet {TABLE_NAME} input_guard "
                "{ type filter hook input priority -100; policy accept; }\n",
            )
        chain = self._run(chain_arguments).stdout
        if "hook input" not in chain or "policy accept" not in chain:
            raise RuntimeError(
                "Цепочка nftables input_guard уже существует, но её hook/policy небезопасны."
            )
        if "ip saddr @blocked_ipv4 drop" not in chain:
            self._run(
                ["nft", "add", "rule", "inet", TABLE_NAME, "input_guard",
                 "ip", "saddr", "@blocked_ipv4", "drop"]
            )
        if "ip6 saddr @blocked_ipv6 drop" not in chain:
            self._run(
                ["nft", "add", "rule", "inet", TABLE_NAME, "input_guard",
                 "ip6", "saddr", "@blocked_ipv6", "drop"]
            )

    def block_ip(self, source_ip: str, duration_seconds: int) -> bool:
        try:
            address = ipaddress.ip_address(source_ip)
        except ValueError as error:
            raise ValueError(f"Некорректный IP-адрес для блокировки: {source_ip}") from error
        if duration_seconds <= 0:
            raise ValueError("Время блокировки должно быть больше нуля.")
        if any(address.version == network.version and address in network for network in self.protected_networks):
            return False

        set_name = "blocked_ipv4" if address.version == 4 else "blocked_ipv6"
        listed = self._run(["nft", "list", "set", "inet", TABLE_NAME, set_name]).stdout
        address_pattern = r"(?<![0-9A-Fa-f:.])" + re.escape(str(address)) + r"(?![0-9A-Fa-f:.])"
        if re.search(address_pattern, listed):
            return True
        self._run(
            ["nft", "-f", "-"],
            f"add element inet {TABLE_NAME} {set_name} "
            f"{{ {address} timeout {duration_seconds}s; }}\n",
        )
        return True
