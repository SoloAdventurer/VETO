"""Request rate limiting and sign-in lockout for the HTTP API (DECISIONS D-022).

In-memory and dependency-free, so there is no external store whose failure could open the gate (invariant 6).
These sit in front of the pipeline, not inside policy evaluation: a throttled request is never decided, never
executed and never audited (an audit row per rejected request would let a flood fill the evidence log).
"""

from __future__ import annotations

import math
import time
from collections import deque
from collections.abc import Callable

MAX_TRACKED = 10_000


class TokenBucketLimiter:
    """Classic token bucket: `burst` requests at once, refilled at `rate_per_min`. One bucket per key."""

    def __init__(self, rate_per_min: float, burst: int, clock: Callable[[], float] = time.time) -> None:
        if rate_per_min <= 0 or burst < 1:
            raise ValueError("rate_per_min must be > 0 and burst >= 1")
        self.rate_per_s = rate_per_min / 60.0
        self.burst = float(burst)
        self._clock = clock
        self._buckets: dict[str, tuple[float, float]] = {}      # key -> (tokens, last_refill)

    def allow(self, key: str) -> tuple[bool, float]:
        """Returns (allowed, seconds_until_a_token_is_available)."""
        now = self._clock()
        tokens, last = self._buckets.get(key, (self.burst, now))
        tokens = min(self.burst, tokens + max(0.0, now - last) * self.rate_per_s)
        if tokens >= 1.0:
            self._buckets[key] = (tokens - 1.0, now)
            return True, 0.0
        self._buckets[key] = (tokens, now)
        return False, (1.0 - tokens) / self.rate_per_s


class FailureLockout:
    """Blocks a client address after `max_failures` failed sign-ins within `window_s`, for `lockout_s`.

    Successful sign-ins deliberately do NOT reset the count: otherwise anyone holding one valid key could interleave
    it with guesses against other keys. Old failures simply age out of the window.
    """

    def __init__(self, max_failures: int = 10, window_s: float = 60.0, lockout_s: float = 300.0,
                 clock: Callable[[], float] = time.time) -> None:
        self.max_failures, self.window_s, self.lockout_s = max_failures, window_s, lockout_s
        self._clock = clock
        self._failures: dict[str, deque[float]] = {}
        self._locked_until: dict[str, float] = {}
        self.lockouts = 0

    def blocked(self, client: str) -> int:
        """Whole seconds the client must still wait (0 = not blocked)."""
        until = self._locked_until.get(client)
        if until is None:
            return 0
        remaining = until - self._clock()
        if remaining <= 0:
            del self._locked_until[client]
            return 0
        return math.ceil(remaining)

    def record_failure(self, client: str) -> None:
        now = self._clock()
        if len(self._failures) >= MAX_TRACKED:
            self._prune(now)
        dq = self._failures.setdefault(client, deque())
        dq.append(now)
        while dq and now - dq[0] > self.window_s:
            dq.popleft()
        if len(dq) >= self.max_failures:
            self._locked_until[client] = now + self.lockout_s
            self.lockouts += 1
            del self._failures[client]

    def _prune(self, now: float) -> None:
        for client in [c for c, dq in self._failures.items() if not dq or now - dq[-1] > self.window_s]:
            del self._failures[client]
        for client in [c for c, until in self._locked_until.items() if until <= now]:
            del self._locked_until[client]
        while len(self._failures) >= MAX_TRACKED:              # still full: drop the oldest tracked client
            del self._failures[next(iter(self._failures))]
