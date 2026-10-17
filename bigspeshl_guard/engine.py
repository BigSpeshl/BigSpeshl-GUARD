from __future__ import annotations

from collections import defaultdict, deque
from dataclasses import dataclass, field
from datetime import datetime, timedelta
from random import randint, uniform
from statistics import mean
from typing import Deque, Dict, Iterable, List, Optional


@dataclass
class ThreatEvent:
    source_ip: str
    target_ip: str
    protocol: str
    packets: int = 1
    port: Optional[int] = None
    timestamp: datetime = field(default_factory=datetime.utcnow)
    metadata: Dict[str, object] = field(default_factory=dict)


class GuardEngine:
    def __init__(self, window_seconds: int = 10, warn_threshold: int = 25, block_threshold: int = 55) -> None:
        self.window_seconds = window_seconds
        self.warn_threshold = warn_threshold
        self.block_threshold = block_threshold
        self.events: Deque[ThreatEvent] = deque(maxlen=2000)
        self.blocklist: Dict[str, datetime] = {}
        self.alerts: List[dict] = []
        self.ip_stats: Dict[str, dict] = defaultdict(
            lambda: {
                "count": 0,
                "concurrent": 0,
                "ports": set(),
                "protocols": set(),
                "last_seen": datetime.utcnow(),
            }
        )

    def _prune_blocklist(self) -> None:
        now = datetime.utcnow()
        expired = [ip for ip, expiry in self.blocklist.items() if expiry <= now]
        for ip in expired:
            self.blocklist.pop(ip, None)

    def _recent_events_for_ip(self, source_ip: str) -> List[ThreatEvent]:
        cutoff = datetime.utcnow() - timedelta(seconds=self.window_seconds)
        return [event for event in self.events if event.source_ip == source_ip and event.timestamp >= cutoff]

    def _score_source(self, source_ip: str, event: ThreatEvent) -> tuple[int, List[str], Optional[str]]:
        recent = self._recent_events_for_ip(source_ip)
        stats = self.ip_stats[source_ip]
        reasons: List[str] = []
        score = 0

        packet_volume = sum(item.packets for item in recent)
        unique_ports = len({item.port for item in recent if item.port is not None})
        unique_protocols = len({item.protocol for item in recent})

        if packet_volume >= 120:
            score += 25
            reasons.append("sustained packet burst")
        if unique_ports >= 10:
            score += 18
            reasons.append("wide port spread")
        if unique_protocols >= 2:
            score += 8
            reasons.append("multi-protocol anomaly")

        if event.protocol.lower() == "tcp" and packet_volume >= 60 and unique_ports >= 6:
            score += 22
            reasons.append("possible SYN flood")
        if event.protocol.lower() in {"udp", "icmp"} and packet_volume >= 80:
            score += 20
            reasons.append("possible reflection flood")
        if stats["concurrent"] >= 25:
            score += 18
            reasons.append("high concurrency")
        if len(recent) >= 20:
            score += 20
            reasons.append("rapid repetition from one source")
        if len(recent) >= 30 and sum(1 for item in recent if item.port and item.port <= 1024) >= 12:
            score += 15
            reasons.append("targeted service abuse")
        if event.protocol.lower() == "tcp" and len(recent) >= 12 and sum(item.packets for item in recent) >= 300:
            score += 18
            reasons.append("connection saturation")

        if score >= self.block_threshold:
            attack = "DDoS-FLOOD"
        elif score >= self.warn_threshold:
            attack = "SUSPICIOUS"
        else:
            attack = None
        return score, reasons, attack

    def observe(self, event: ThreatEvent) -> Optional[dict]:
        self._prune_blocklist()

        if event.source_ip in self.blocklist:
            return {
                "source_ip": event.source_ip,
                "action": "blocked",
                "status": "denied",
            }

        self.events.append(event)
        stats = self.ip_stats[event.source_ip]
        stats["count"] += event.packets
        stats["last_seen"] = event.timestamp
        stats["concurrent"] += 1
        if event.port is not None:
            stats["ports"].add(event.port)
        stats["protocols"].add(event.protocol)

        score, reasons, attack = self._score_source(event.source_ip, event)
        if attack is None:
            return None

        action = "watch"
        if score >= self.block_threshold:
            action = "block"
            self.blocklist[event.source_ip] = datetime.utcnow() + timedelta(minutes=20)
        elif score >= self.warn_threshold:
            action = "rate-limit"

        alert = {
            "timestamp": event.timestamp.isoformat(timespec="seconds"),
            "source_ip": event.source_ip,
            "target_ip": event.target_ip,
            "protocol": event.protocol,
            "action": action,
            "severity": "high" if action == "block" else "medium",
            "score": score,
            "attack": attack,
            "reasons": reasons,
            "packets": stats["count"],
        }
        self.alerts.append(alert)

        return alert

    def recent_alerts(self, limit: int = 20) -> List[dict]:
        return list(reversed(self.alerts[-limit:]))

    def summary(self) -> dict:
        self._prune_blocklist()
        active_sources = len({event.source_ip for event in self.events if datetime.utcnow() - event.timestamp <= timedelta(seconds=self.window_seconds)})
        blocked = len(self.blocklist)
        threat_count = len(self.recent_alerts(limit=50))
        avg_targets = 0
        if self.events:
            by_target = defaultdict(int)
            for event in self.events:
                by_target[event.target_ip] += event.packets
            avg_targets = round(mean(by_target.values()) if by_target else 0, 2)
        return {
            "active_sources": active_sources,
            "blocked_sources": blocked,
            "threat_count": threat_count,
            "avg_target_load": avg_targets,
            "load_factor": round((len(self.events) / max(1, len(self.blocklist) + 1)) * 100, 2),
            "window_seconds": self.window_seconds,
        }


def generate_attack_event(source_ip: str, target_ip: str, protocol: str, packets: int = 1, port: Optional[int] = None) -> ThreatEvent:
    return ThreatEvent(
        source_ip=source_ip,
        target_ip=target_ip,
        protocol=protocol,
        packets=packets,
        port=port,
        metadata={"generated": True},
    )


def generate_synthetic_stream(mode: str = "mixed") -> Iterable[ThreatEvent]:
    protocols = ["tcp", "udp", "icmp", "http"]
    if mode == "syn_flood":
        attack_ip = f"10.0.0.{randint(2, 20)}"
        for i in range(1, 30):
            yield generate_attack_event(attack_ip, "192.168.1.10", "tcp", packets=randint(25, 50), port=80)
    elif mode == "udp_reflection":
        attack_ip = f"198.51.100.{randint(1, 40)}"
        for i in range(1, 25):
            yield generate_attack_event(attack_ip, "192.168.1.10", "udp", packets=randint(25, 60), port=53)
    elif mode == "http_flood":
        attack_ip = f"203.0.113.{randint(1, 255)}"
        for i in range(1, 40):
            yield generate_attack_event(attack_ip, "192.168.1.10", "http", packets=randint(5, 15), port=443)
    else:
        for _ in range(30):
            protocol = protocols[randint(0, len(protocols) - 1)]
            port = randint(20, 65535)
            packets = randint(1, 12)
            yield generate_attack_event(f"172.16.0.{randint(2, 99)}", "192.168.1.10", protocol, packets=packets, port=port)


def simulate_mode(mode: str = "mixed", steps: int = 12) -> List[ThreatEvent]:
    stream = list(generate_synthetic_stream(mode))
    if len(stream) < steps:
        return stream
    return stream[:steps]
