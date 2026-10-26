import asyncio
import time
import statistics
import httpx

BASE_URL = "http://127.0.0.1:8000"
ENDPOINT = "/api/v1/anggota/search/nik"

STAGES = [
    (1, 1),
    (5, 10),
    (20, 20),
    (50, 50),
    (100, 50),
    (250, 50),
    (500, 100),
    (1000, 100),
]

PAYLOAD = {"nik": "31740101017000"}
HEADERS = {"x-user-id": "staged_tester"}


async def user_worker(client: httpx.AsyncClient, req_count: int, latencies: list, stats: dict):
    for _ in range(req_count):
        start = time.perf_counter()
        try:
            resp = await client.post(
                f"{BASE_URL}{ENDPOINT}",
                json=PAYLOAD,
                headers=HEADERS
            )
            if resp.status_code in (200, 404):
                stats["success"] += 1
            else:
                stats["failed"] += 1
        except Exception:
            stats["failed"] += 1
        
        elapsed = (time.perf_counter() - start) * 1000
        latencies.append(elapsed)


async def run_stage(users: int, req_per_user: int):
    total_req = users * req_per_user
    print(f"\n[*] Menjalankan Tahap: {users} User | {req_per_user} Req/User (Total: {total_req:,} req)...")

    latencies = []
    stats = {"success": 0, "failed": 0}

    limits = httpx.Limits(max_connections=users + 50, max_keepalive_connections=users)
    
    async with httpx.AsyncClient(limits=limits, timeout=15.0) as client:
        start_time = time.perf_counter()
        tasks = [
            asyncio.create_task(user_worker(client, req_per_user, latencies, stats))
            for _ in range(users)
        ]
        await asyncio.gather(*tasks)
        duration = time.perf_counter() - start_time

    latencies.sort()
    rps = len(latencies) / duration if duration > 0 else 0
    p50 = statistics.median(latencies) if latencies else 0
    p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else (latencies[-1] if latencies else 0)

    print(f"    Selesai dalam : {duration:.2f} detik")
    print(f"    Throughput    : {rps:.2f} RPS")
    print(f"    Sukses/Gagal  : {stats['success']}/{stats['failed']}")
    print(f"    p50 / p95     : {p50:.2f} ms / {p95:.2f} ms")

    return {
        "users": users,
        "req_per_user": req_per_user,
        "total_req": total_req,
        "duration": duration,
        "rps": rps,
        "success": stats["success"],
        "failed": stats["failed"],
        "p50": p50,
        "p95": p95,
    }


async def main():
    print("=" * 70)
    print("   STAGED LOAD TESTING - DPR RI PDP ENCRYPTION BENCHMARK")
    print("   Target: " + BASE_URL + ENDPOINT)
    print("=" * 70)

    stage_summaries = []

    for users, req_count in STAGES:
        summary = await run_stage(users, req_count)
        stage_summaries.append(summary)
        await asyncio.sleep(2)

    print("\n" + "=" * 80)
    print(f"{'Users':>7} | {'Req/User':>8} | {'Total Req':>10} | {'Throughput':>12} | {'p50 (ms)':>9} | {'p95 (ms)':>9} | {'Error':>7}")
    print("-" * 80)
    for s in stage_summaries:
        print(f"{s['users']:>7} | {s['req_per_user']:>8} | {s['total_req']:>10:,} | {s['rps']:>9.1f} RPS | {s['p50']:>8.2f}  | {s['p95']:>8.2f}  | {s['failed']:>7}")
    print("=" * 80)


if __name__ == "__main__":
    asyncio.run(main())