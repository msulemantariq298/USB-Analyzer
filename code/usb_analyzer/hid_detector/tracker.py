from collections import deque
from dataclasses import dataclass, field
import math
import time
from typing import NamedTuple


class KeystrokeMetric(NamedTuple):
    timestamp: float
    key: str


@dataclass
class InjectionAlert:
    """Alert generated when typing dynamics exceed human biological limits."""

    detected_at: float
    keystroke_count: int
    duration_seconds: float
    characters_per_second: float
    average_iki_ms: float
    std_dev_iki_ms: float
    is_robotic: bool
    summary: str


class KeystrokeDynamicsTracker:
    """Analyzes inter-keystroke intervals (IKIs) to detect automated BadUSB injection."""

    def __init__(
        self,
        window_size: int = 15,
        burst_threshold_cps: float = 22.0,
        max_avg_iki_ms: float = 45.0,
        robotic_std_dev_ms: float = 8.0,
    ) -> None:
        self.window_size = window_size
        self.burst_threshold_cps = burst_threshold_cps
        self.max_avg_iki_ms = max_avg_iki_ms
        self.robotic_std_dev_ms = robotic_std_dev_ms
        self._history: deque[KeystrokeMetric] = deque(maxlen=window_size)
        self._last_alert_time: float = 0.0

    def record_keystroke(
        self,
        key: str = "key",
        timestamp: float | None = None,
    ) -> InjectionAlert | None:
        """Record a keystroke event and evaluate sliding window for injection attacks."""
        ts = timestamp if timestamp is not None else time.monotonic()
        self._history.append(KeystrokeMetric(timestamp=ts, key=key))

        if len(self._history) < self.window_size:
            return None

        # Calculate time span of current window
        span = self._history[-1].timestamp - self._history[0].timestamp
        if span <= 0:
            span = 0.001  # Prevent division by zero for instant hardware injection

        cps = len(self._history) / span

        # Compute inter-keystroke intervals
        ikis_ms = [
            (self._history[i].timestamp - self._history[i - 1].timestamp) * 1000.0
            for i in range(1, len(self._history))
        ]
        avg_iki = sum(ikis_ms) / len(ikis_ms)

        variance = sum((x - avg_iki) ** 2 for x in ikis_ms) / len(ikis_ms)
        std_dev = math.sqrt(variance)

        is_robotic = std_dev <= self.robotic_std_dev_ms

        # Trigger alert if CPS exceeds threshold OR avg IKI is impossibly fast
        if cps >= self.burst_threshold_cps or (avg_iki <= self.max_avg_iki_ms and len(self._history) >= 10):
            # Suppress repeat alerts within 1.0s window
            if ts - self._last_alert_time < 1.0:
                return None
            self._last_alert_time = ts

            alert = InjectionAlert(
                detected_at=ts,
                keystroke_count=len(self._history),
                duration_seconds=round(span, 4),
                characters_per_second=round(cps, 1),
                average_iki_ms=round(avg_iki, 2),
                std_dev_iki_ms=round(std_dev, 2),
                is_robotic=is_robotic,
                summary=(
                    f"BadUSB injection detected: {round(cps, 1)} chars/sec "
                    f"(avg IKI {round(avg_iki, 1)}ms, std dev {round(std_dev, 1)}ms, "
                    f"{'robotic cadence' if is_robotic else 'high-speed burst'})"
                ),
            )
            # Reset history after alert so we don't repeatedly fire on same burst
            self._history.clear()
            return alert

        return None

    def reset(self) -> None:
        self._history.clear()
        self._last_alert_time = 0.0
