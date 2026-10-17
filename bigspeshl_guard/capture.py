from __future__ import annotations

import platform
import re
import socket
import time
from typing import Callable, Optional

import psutil

from .engine import ThreatEvent

HTTP_REQUEST_LINE = re.compile(
    br"^(?:GET|HEAD|POST|PUT|DELETE|CONNECT|OPTIONS|TRACE|PATCH) "
    br"[^\r\n ]+ HTTP/1\.[01]\r\n"
)


def packet_to_event(packet: object) -> Optional[ThreatEvent]:
    try:
        from scapy.layers.inet import ICMP, IP, TCP, UDP
        from scapy.layers.inet6 import IPv6, ICMPv6Unknown
        from scapy.packet import Raw
    except ImportError as error:
        raise RuntimeError(
            "Для захвата трафика установите зависимости: pip install -r requirements.txt"
        ) from error

    if IP in packet:
        source_ip = packet[IP].src
        target_ip = packet[IP].dst
    elif IPv6 in packet:
        source_ip = packet[IPv6].src
        target_ip = packet[IPv6].dst
    else:
        return None

    transport = packet.getlayer(TCP) or packet.getlayer(UDP)
    if transport is not None and packet.haslayer(TCP):
        protocol = "TCP"
        port = int(transport.dport)
        flags = int(transport.flags)
        syn_only = bool(flags & 0x02) and not bool(flags & 0x10)
        attack_type = "syn_flood" if syn_only else None
        if (
            attack_type is None
            and port in {80, 8080, 8000}
            and packet.haslayer(Raw)
            and HTTP_REQUEST_LINE.match(bytes(packet[Raw].load))
        ):
            protocol = "HTTP"
            attack_type = "http_flood"
        metadata = {"capture_only": True}
        if attack_type:
            metadata["attack_type"] = attack_type
            metadata.pop("capture_only", None)
        return ThreatEvent(source_ip, target_ip, protocol, port=port, metadata=metadata)

    if packet.haslayer(UDP):
        udp = packet[UDP]
        return ThreatEvent(
            source_ip,
            target_ip,
            "UDP",
            port=int(udp.dport),
            metadata={"attack_type": "udp_reflection"},
        )

    if packet.haslayer(ICMP) or packet.haslayer(ICMPv6Unknown):
        return ThreatEvent(
            source_ip,
            target_ip,
            "ICMP",
            metadata={"capture_only": True},
        )

    return ThreatEvent(
        source_ip,
        target_ip,
        "IP",
        metadata={"capture_only": True},
    )


def run_live_capture(
    engine,
    interface: Optional[str],
    on_alert: Callable[[dict], None],
    on_update: Callable[[], None],
    duration: Optional[float] = None,
) -> None:
    if platform.system() != "Linux":
        raise RuntimeError("Захват пакетов через Scapy в этом режиме поддерживается только в Linux.")
    try:
        from scapy.sendrecv import sniff
        from scapy.error import Scapy_Exception
    except ImportError as error:
        raise RuntimeError(
            "Для захвата трафика установите зависимости: pip install -r requirements.txt"
        ) from error

    try:
        interface_records = psutil.net_if_addrs()
    except OSError as error:
        raise RuntimeError(f"Не удалось получить адреса сетевых интерфейсов: {error}") from error
    interface_addresses = set()
    for address in interface_records.get(interface, []):
        if address.family in {socket.AF_INET, socket.AF_INET6}:
            interface_addresses.add(address.address.split("%", 1)[0])
    if not interface_addresses:
        raise RuntimeError(
            f"Не удалось определить IP-адреса интерфейса {interface}; "
            "проверьте имя интерфейса и его конфигурацию."
        )

    start = time.monotonic()

    def process_packet(packet: object) -> None:
        event = packet_to_event(packet)
        if event is None or event.target_ip not in interface_addresses:
            return
        alert = engine.observe(event)
        if alert and "attack" in alert:
            on_alert(alert)

    try:
        while duration is None or time.monotonic() - start < duration:
            sniff(
                iface=interface or None,
                prn=process_packet,
                store=False,
                timeout=1,
            )
            on_update()
    except KeyboardInterrupt:
        return
    except (Scapy_Exception, OSError, PermissionError) as error:
        raise RuntimeError(
            f"Не удалось захватить пакеты на интерфейсе {interface or 'по умолчанию'}: {error}. "
            "Запустите от root или настройте CAP_NET_RAW."
        ) from error
