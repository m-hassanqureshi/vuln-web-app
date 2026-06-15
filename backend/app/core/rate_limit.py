import asyncio
import time
from collections import defaultdict, deque

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import JSONResponse


class RateLimitMiddleware(BaseHTTPMiddleware):
    """In-process, per-IP sliding-window rate limiter scoped to POST requests.

    Stdlib-only (collections.deque + asyncio.Lock + time.monotonic). Counter
    state is intentionally not persisted across restarts -- see the parent
    spec's Operational Note for the trade-off.
    """

    def __init__(self, app, max_requests: int, window_seconds: int):
        super().__init__(app)
        self._max = max_requests
        self._window = window_seconds
        self._buckets: dict[str, deque[float]] = defaultdict(deque)
        self._lock = asyncio.Lock()

    async def dispatch(self, request: Request, call_next):
        # FR-01 / FR-07: method check is the first statement. Every non-POST
        # request bypasses the limiter with zero state access.
        if request.method != "POST":
            return await call_next(request)

        # FR-03: client IP, with a defensive fallback so a missing
        # request.client never raises.
        client = request.client
        ip = client.host if client is not None else "unknown"

        try:
            now = time.monotonic()
            cutoff = now - self._window
            async with self._lock:
                bucket = self._buckets[ip]
                # FR-02 step 3: prune stale entries from the left.
                while bucket and bucket[0] < cutoff:
                    bucket.popleft()
                # FR-02 step 4: length check against the configured max.
                if len(bucket) >= self._max:
                    oldest = bucket[0]
                    # FR-04 + EC-11: integer floor of 1 second.
                    retry_after = max(1, int(self._window - (now - oldest)))
                    return JSONResponse(
                        status_code=429,
                        content={"error": "Too many requests", "retry_after": retry_after},
                        headers={"Retry-After": str(retry_after)},
                    )
                # FR-02 step 5: record this request and forward.
                bucket.append(now)
        except Exception:
            # NFR-07: fail-open on any unexpected bookkeeping error.
            return await call_next(request)

        return await call_next(request)
