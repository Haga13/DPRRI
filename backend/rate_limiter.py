import time
from collections import defaultdict, deque
from fastapi import HTTPException, Request, status

class InMemoryRateLimiter:
    def __init__(self, requests_limit: int, window_seconds: int):
        self.requests_limit = requests_limit
        self.window_seconds = window_seconds
        self.clients = defaultdict(deque)

    def check(self, key: str):
        now = time.time()
        timestamps = self.clients[key]

        while timestamps and timestamps[0] <= now - self.window_seconds:
            timestamps.popleft()

        if len(timestamps) >= self.requests_limit:
            retry_after = int(self.window_seconds - (now - timestamps[0])) + 1
            raise HTTPException(
                status_code=status.HTTP_429_TOO_MANY_REQUESTS,
                detail=f"Terlalu banyak permintaan. Silakan coba kembali dalam {retry_after} detik.",
                headers={"Retry-After": str(retry_after)}
            )

        timestamps.append(now)

login_limiter = InMemoryRateLimiter(requests_limit=5, window_seconds=60)

search_limiter = InMemoryRateLimiter(requests_limit=10, window_seconds=60)


def rate_limit_login(request: Request):
    client_ip = request.client.host if request.client else "127.0.0.1"
    login_limiter.check(client_ip)


def rate_limit_search(current_user: dict):
    user_id = current_user.get("sub", "anonymous")
    search_limiter.check(user_id)
    
def reset_all_limiters():
    """Mengosongkan memori pelacak kuota permintaan untuk kebutuhan otomasi pengujian."""
    login_limiter.clients.clear()
    search_limiter.clients.clear()