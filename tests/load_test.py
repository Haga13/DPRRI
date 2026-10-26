import asyncio
import time
import statistics
import httpx

BASE_URL = "http://127.0.0.1:8000"
TOTAL_REQUESTS = 200
CONCURRENCY = 200

TEST_NIK = "31740101017000"


async def worker(queue: asyncio.Queue, results: dict, client: httpx.AsyncClient):
    while not queue.empty():
        test_type = await queue.get()
        start = time.perf_counter()
        status_code = None
        is_success = False

        try:
            if test_type == "public":
                resp = await client.get(f"{BASE_URL}/api/v1/anggota?limit=10")
            else:
                resp = await client.post(
                    f"{BASE_URL}/api/v1/anggota/search/nik",
                    json={"nik": TEST_NIK},
                    headers={"x-user-id": "loadtest_runner"}
                )
            status_code = resp.status_code
            if status_code in (200, 404):
                is_success = True
        except Exception:
            status_code = 500

        latency = (time.perf_counter() - start) * 1000
        results[test_type]["latencies"].append(latency)
        if is_success:
            results[test_type]["success"] += 1
        else:
            results[test_type]["failed"] += 1

        queue.task_done()


async def run_benchmark():
    print("=" * 60)
    print("   DPR RI SECURE BACKEND - BENCHMARK & LOAD TESTING")
    print("=" * 60)
    print(f"Target URL   : {BASE_URL}")
    print(f"Total Req    : {TOTAL_REQUESTS} per skenario")
    print(f"Concurrency  : {CONCURRENCY} workers")
    print("-" * 60)

    for test_scenario in ["public", "crypto_search"]:
        label = "GET /api/v1/anggota (Data Publik)" if test_scenario == "public" else "POST /api/v1/anggota/search/nik (Blind Index)"
        print(f"\n[*] Menjalankan pengujian: {label}...")

        queue = asyncio.Queue()
        for _ in range(TOTAL_REQUESTS):
            queue.put_nowait(test_scenario)

        results = {
            test_scenario: {
                "latencies": [],
                "success": 0,
                "failed": 0
            }
        }

        async with httpx.AsyncClient(timeout=10.0) as client:
            bench_start = time.perf_counter()
            tasks = [asyncio.create_task(worker(queue, results, client)) for _ in range(CONCURRENCY)]
            await queue.join()
            for t in tasks:
                t.cancel()
            total_duration = time.perf_counter() - bench_start

        latencies = sorted(results[test_scenario]["latencies"])
        success = results[test_scenario]["success"]
        failed = results[test_scenario]["failed"]
        rps = len(latencies) / total_duration

        p50 = statistics.median(latencies)
        p90 = statistics.quantiles(latencies, n=10)[8] if len(latencies) >= 10 else latencies[-1]
        p95 = statistics.quantiles(latencies, n=20)[18] if len(latencies) >= 20 else latencies[-1]

        print(f"[+] Selesai dalam : {total_duration:.2f} detik")
        print(f"[+] Throughput    : {rps:.2f} req/sec (RPS)")
        print(f"[+] Berhasil      : {success}/{TOTAL_REQUESTS}")
        print(f"[+] Gagal/Error   : {failed}")
        print(f"[+] Latensi Min   : {min(latencies):.2f} ms")
        print(f"[+] Latensi p50   : {p50:.2f} ms")
        print(f"[+] Latensi p90   : {p90:.2f} ms")
        print(f"[+] Latensi p95   : {p95:.2f} ms")
        print(f"[+] Latensi Max   : {max(latencies):.2f} ms")

    print("\n" + "=" * 60)
    print("[V] PENGUJIAN BEBAN SELESAI")
    print("=" * 60)


if __name__ == "__main__":
    asyncio.run(run_benchmark())