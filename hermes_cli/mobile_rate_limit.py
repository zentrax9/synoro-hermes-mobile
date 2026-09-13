"""SQLite-backed authenticated-principal rate limits for Hermes Mobile."""

from __future__ import annotations

import hashlib
import math
from pathlib import Path
import sqlite3
import time


class MobileRateLimitExceeded(RuntimeError):
    def __init__(self, retry_after: int) -> None:
        self.retry_after = retry_after
        super().__init__("mobile request rate exceeded")


class MobileRateLimiter:
    def __init__(self, path: str | Path, *, clock=time.time) -> None:
        self._path = Path(path)
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._clock = clock
        with self._connect() as connection:
            connection.execute(
                """
                CREATE TABLE IF NOT EXISTS mobile_rate_limits (
                    principal_hash BLOB NOT NULL,
                    action TEXT NOT NULL,
                    window_start INTEGER NOT NULL,
                    request_count INTEGER NOT NULL,
                    PRIMARY KEY (principal_hash, action, window_start)
                )
                """
            )

    def _connect(self) -> sqlite3.Connection:
        connection = sqlite3.connect(self._path, isolation_level=None, timeout=5)
        connection.execute("PRAGMA busy_timeout = 5000")
        return connection

    def check(
        self,
        *,
        dimension: str,
        principal: str,
        action: str,
        limit: int,
        window_seconds: int,
    ) -> None:
        if not dimension or not principal or not action:
            raise ValueError("rate-limit identity and action are required")
        if not isinstance(limit, int) or limit <= 0:
            raise ValueError("rate-limit count must be positive")
        if not isinstance(window_seconds, int) or window_seconds <= 0:
            raise ValueError("rate-limit window must be positive")
        now = float(self._clock())
        if not math.isfinite(now) or now < 0:
            raise ValueError("invalid rate-limit clock")
        window_start = int(now // window_seconds) * window_seconds
        principal_hash = hashlib.sha256(f"{dimension}\0{principal}".encode()).digest()
        with self._connect() as connection:
            connection.execute("BEGIN IMMEDIATE")
            connection.execute(
                "DELETE FROM mobile_rate_limits WHERE window_start < ?",
                (window_start - window_seconds,),
            )
            row = connection.execute(
                "SELECT request_count FROM mobile_rate_limits "
                "WHERE principal_hash = ? AND action = ? AND window_start = ?",
                (principal_hash, action, window_start),
            ).fetchone()
            count = 0 if row is None else int(row[0])
            if count >= limit:
                connection.rollback()
                retry_after = max(1, math.ceil(window_start + window_seconds - now))
                raise MobileRateLimitExceeded(retry_after)
            connection.execute(
                """
                INSERT INTO mobile_rate_limits (
                    principal_hash, action, window_start, request_count
                ) VALUES (?, ?, ?, 1)
                ON CONFLICT(principal_hash, action, window_start)
                DO UPDATE SET request_count = request_count + 1
                """,
                (principal_hash, action, window_start),
            )
            connection.commit()
