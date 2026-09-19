from __future__ import annotations

import time
from random import randint

from .engine import GuardEngine, ThreatEvent, generate_synthetic_stream


class TrafficSimulator:
    def __init__(self, engine: GuardEngine, mode: str = "mixed", interval: float = 0.3) -> None:
        self.engine = engine
        self.mode = mode
        self.interval = interval
        self.running = False

    def run_once(self) -> list:
        events = list(generate_synthetic_stream(self.mode))
        alerts = []
        for event in events:
            result = self.engine.observe(event)
            if result:
                alerts.append(result)
        return alerts

    def run(self, duration: float = 10.0) -> list:
        self.running = True
        all_alerts: list = []
        start = time.monotonic()
        while self.running and (time.monotonic() - start) < duration:
            alerts = self.run_once()
            if alerts:
                all_alerts.extend(alerts)
            time.sleep(self.interval)
        self.running = False
        return all_alerts

    def stop(self) -> None:
        self.running = False
