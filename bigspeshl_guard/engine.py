from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta, timezone
from random import randint
from typing import Deque, Dict, Iterable, List, Optional


ATTACK_NAMES = {
    "syn_flood": "SYN flood",
    "udp_reflection": "UDP reflection",
    "http_flood": "HTTP flood",
}

DEFAULT_ATTACK_POLICIES = {
    "syn_flood": {"threshold_requests": 300, "block_seconds": 1200},
    "udp_reflection": {"threshold_requests": 300, "block_seconds": 1200},
    "http_flood": {"threshold_requests": 300, "block_seconds": 1200},
}


@dataclass
class ThreatEvent:
    source_ip: str
    target_ip: str
    protocol: str
    packets: int = 1
    port: Optional[int] = None
    timestamp: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    metadata: Dict[str, object] = field(default_factory=dict)


class GuardEngine:
    def __init__(
        self,
        window_seconds: int = 10,
        attack_policies: Optional[Dict[str, Dict[str, int]]] = None,
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("Окно анализа должно быть больше нуля.")
        self.window_seconds = window_seconds
        self.attack_policies = attack_policies or DEFAULT_ATTACK_POLICIES
        self.events: Deque[ThreatEvent] = deque(maxlen=10000)
        self._events_by_source: Dict[str, Deque[ThreatEvent]] = defaultdict(deque)
        self.blocklist: Dict[str, datetime] = {}
        self.alerts: List[dict] = []

    def update_policy(
        self,
        window_seconds: int,
        attack_policies: Dict[str, Dict[str, int]],
    ) -> None:
        if window_seconds <= 0:
            raise ValueError("Окно анализа должно быть больше нуля.")
        if set(attack_policies) != set(ATTACK_NAMES):
            raise ValueError("Нужны политики для SYN flood, UDP reflection и HTTP flood.")
        for name, policy in attack_policies.items():
            if policy["threshold_requests"] <= 0 or policy["block_seconds"] <= 0:
                raise ValueError(f"Порог и время блокировки для {name} должны быть больше нуля.")
        self.window_seconds = window_seconds
        self.attack_policies = attack_policies

    def _prune_blocklist(self) -> None:
        now = datetime.now(timezone.utc)
        expired = [ip for ip, expiry in self.blocklist.items() if expiry <= now]
        for ip in expired:
            self.blocklist.pop(ip, None)

    def _attack_type(self, event: ThreatEvent) -> Optional[str]:
        if event.metadata.get("capture_only"):
            return None
        declared_type = event.metadata.get("attack_type")
        if isinstance(declared_type, str) and declared_type in self.attack_policies:
            return declared_type
        protocol = event.protocol.lower()
        if protocol in {"tcp", "syn"}:
            return "syn_flood"
        if protocol in {"udp", "icmp"}:
            return "udp_reflection"
        if protocol in {"http", "https"}:
            return "http_flood"
        return None

    def _recent_source_events(self, source_ip: str) -> List[ThreatEvent]:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.window_seconds)
        source_events = self._events_by_source[source_ip]
        while source_events and source_events[0].timestamp < cutoff:
            source_events.popleft()
        return [event for event in source_events if event.timestamp >= cutoff]

    def observe(self, event: ThreatEvent) -> Optional[dict]:
        self._prune_blocklist()
        if event.packets <= 0:
            raise ValueError("Количество запросов должно быть больше нуля.")

        if event.source_ip in self.blocklist:
            return {"source_ip": event.source_ip, "action": "blocked", "status": "denied"}

        if len(self.events) == self.events.maxlen:
            evicted = self.events[0]
            evicted_source_events = self._events_by_source[evicted.source_ip]
            if evicted_source_events and evicted_source_events[0] is evicted:
                evicted_source_events.popleft()
            if not evicted_source_events:
                self._events_by_source.pop(evicted.source_ip, None)
        self.events.append(event)
        self._events_by_source[event.source_ip].append(event)
        attack_type = self._attack_type(event)
        if attack_type is None:
            return None

        recent = self._recent_source_events(event.source_ip)
        attack_events = [
            item for item in recent if self._attack_type(item) == attack_type
        ]
        requests_in_window = sum(item.packets for item in attack_events)
        policy = self.attack_policies[attack_type]
        threshold = policy["threshold_requests"]
        if requests_in_window < threshold:
            return None

        block_seconds = policy["block_seconds"]
        self.blocklist[event.source_ip] = datetime.now(timezone.utc) + timedelta(seconds=block_seconds)
        alert = {
            "timestamp": event.timestamp.isoformat(timespec="seconds"),
            "source_ip": event.source_ip,
            "target_ip": event.target_ip,
            "protocol": event.protocol.upper(),
            "port": event.port,
            "action": "block",
            "severity": "high",
            "attack": ATTACK_NAMES[attack_type],
            "attack_type": attack_type,
            "requests_in_window": requests_in_window,
            "threshold_requests": threshold,
            "window_seconds": self.window_seconds,
            "block_seconds": block_seconds,
        }
        self.alerts.append(alert)
        return alert

    def traffic_stats(self) -> List[dict]:
        cutoff = datetime.now(timezone.utc) - timedelta(seconds=self.window_seconds)
        by_ip: Dict[str, List[ThreatEvent]] = defaultdict(list)
        for event in self.events:
            if event.timestamp >= cutoff:
                by_ip[event.source_ip].append(event)

        rows = []
        for source_ip, events in by_ip.items():
            protocols: Dict[str, int] = defaultdict(int)
            ports = set()
            requests = 0
            for event in events:
                protocols[event.protocol.upper()] += event.packets
                requests += event.packets
                if event.port is not None:
                    ports.add(event.port)
            rows.append(
                {
                    "source_ip": source_ip,
                    "requests": requests,
                    "requests_per_second": requests / self.window_seconds,
                    "protocols": protocols,
                    "ports": sorted(ports),
                    "blocked": source_ip in self.blocklist,
                }
            )
        rows.sort(key=lambda row: (row["blocked"], row["requests"]), reverse=True)
        return rows

    def recent_alerts(self, limit: int = 20) -> List[dict]:
        return list(reversed(self.alerts[-limit:]))

    def summary(self) -> dict:
        self._prune_blocklist()
        traffic = self.traffic_stats()
        active_sources = len(traffic)
        total_requests = sum(row["requests"] for row in traffic)
        return {
            "active_sources": active_sources,
            "blocked_sources": len(self.blocklist),
            "threat_count": len(self.alerts),
            "total_requests": total_requests,
            "window_seconds": self.window_seconds,
        }


def generate_attack_event(
    source_ip: str,
    target_ip: str,
    protocol: str,
    packets: int = 1,
    port: Optional[int] = None,
    attack_type: Optional[str] = None,
) -> ThreatEvent:
    metadata: Dict[str, object] = {"generated": True}
    if attack_type:
        metadata["attack_type"] = attack_type
    return ThreatEvent(
        source_ip=source_ip,
        target_ip=target_ip,
        protocol=protocol,
        packets=packets,
        port=port,
        metadata=metadata,
    )


def generate_synthetic_stream(mode: str = "mixed") -> Iterable[ThreatEvent]:
    protocols = ["tcp", "udp", "icmp", "http"]
    if mode == "syn_flood":
        source_ip = f"10.0.0.{randint(2, 20)}"
        for _ in range(30):
            yield generate_attack_event(
                source_ip, "192.168.1.10", "tcp", packets=randint(25, 50),
                port=80, attack_type="syn_flood",
            )
    elif mode == "udp_reflection":
        source_ip = f"198.51.100.{randint(1, 40)}"
        for _ in range(25):
            yield generate_attack_event(
                source_ip, "192.168.1.10", "udp", packets=randint(25, 60),
                port=53, attack_type="udp_reflection",
            )
    elif mode == "http_flood":
        source_ip = f"203.0.113.{randint(1, 255)}"
        for _ in range(40):
            yield generate_attack_event(
                source_ip, "192.168.1.10", "http", packets=randint(5, 15),
                port=443, attack_type="http_flood",
            )
    else:
        for _ in range(30):
            protocol = protocols[randint(0, len(protocols) - 1)]
            yield generate_attack_event(
                f"172.16.0.{randint(2, 99)}",
                "192.168.1.10",
                protocol,
                packets=randint(1, 12),
                port=randint(20, 65535),
            )


def simulate_mode(mode: str = "mixed", steps: int = 12) -> List[ThreatEvent]:
    return list(generate_synthetic_stream(mode))[:steps]
