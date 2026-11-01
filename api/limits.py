from __future__ import annotations

import os
import sqlite3
import time
from pathlib import Path

from scanner.config import DAILY_CAP_USD, IP_SCANS_PER_HOUR

DAILY_LIMIT_MSG = "Daily limit reached, try the demo"
HOURLY_LIMIT_MSG = "Hourly limit reached, try the demo"
HOUR_S = 3600


def _env_float(name: str, default: float) -> float:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return float(raw)


def _env_int(name: str, default: int) -> int:
    raw = os.environ.get(name, "").strip()
    if not raw:
        return default
    return int(raw)


class LimitsStore:
    def __init__(
        self,
        path: str | Path,
        *,
        daily_cap: float | None = None,
        ip_per_hour: int | None = None,
        now=None,
    ) -> None:
        self.path = Path(path)
        self.path.parent.mkdir(parents=True, exist_ok=True)
        self.daily_cap = (
            daily_cap
            if daily_cap is not None
            else _env_float("TRUSTMAP_DAILY_CAP_USD", DAILY_CAP_USD)
        )
        self.ip_per_hour = (
            ip_per_hour
            if ip_per_hour is not None
            else _env_int("TRUSTMAP_IP_SCANS_PER_HOUR", IP_SCANS_PER_HOUR)
        )
        self._now = now or time.time
        with self._connect() as conn:
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS spend_ledger (
                    day TEXT PRIMARY KEY,
                    usd REAL NOT NULL
                )
                """
            )
            conn.execute(
                """
                CREATE TABLE IF NOT EXISTS scan_starts (
                    ip TEXT NOT NULL,
                    ts REAL NOT NULL
                )
                """
            )
            conn.execute(
                "CREATE INDEX IF NOT EXISTS scan_starts_ip_ts ON scan_starts (ip, ts)"
            )

    def _connect(self) -> sqlite3.Connection:
        conn = sqlite3.connect(self.path)
        conn.isolation_level = None
        return conn

    def day_key(self) -> str:
        return time.strftime("%Y-%m-%d", time.gmtime(self._now()))

    def spent_today(self) -> float:
        with self._connect() as conn:
            row = conn.execute(
                "SELECT usd FROM spend_ledger WHERE day = ?",
                (self.day_key(),),
            ).fetchone()
        return float(row[0]) if row else 0.0

    def starts_last_hour(self, ip: str) -> int:
        cutoff = self._now() - HOUR_S
        with self._connect() as conn:
            row = conn.execute(
                "SELECT COUNT(*) FROM scan_starts WHERE ip = ? AND ts >= ?",
                (ip, cutoff),
            ).fetchone()
        return int(row[0]) if row else 0

    def check(self, ip: str) -> str | None:
        if self.spent_today() >= self.daily_cap:
            return DAILY_LIMIT_MSG
        if self.starts_last_hour(ip) >= self.ip_per_hour:
            return HOURLY_LIMIT_MSG
        return None

    def record_start(self, ip: str) -> None:
        with self._connect() as conn:
            conn.execute(
                "INSERT INTO scan_starts (ip, ts) VALUES (?, ?)",
                (ip, self._now()),
            )

    def add_spend(self, usd: float) -> None:
        if usd <= 0:
            return
        day = self.day_key()
        with self._connect() as conn:
            conn.execute(
                """
                INSERT INTO spend_ledger (day, usd) VALUES (?, ?)
                ON CONFLICT(day) DO UPDATE SET usd = usd + excluded.usd
                """,
                (day, usd),
            )


def client_ip(request) -> str:
    forwarded = request.headers.get("x-forwarded-for")
    if forwarded:
        return forwarded.split(",", 1)[0].strip()
    if request.client is not None and request.client.host:
        return request.client.host
    return "unknown"
