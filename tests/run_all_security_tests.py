import subprocess
import sys
import time
import urllib.request

TEST_SUITES = [
    ("Autentikasi JWT & Otorisasi RBAC", "tests/test_auth_jwt.py"),
    ("Token Revocation & Logout", "tests/test_logout_revocation.py"),
    ("Pemusnahan Retensi Data (Right to be Forgotten)", "tests/test_data_retention.py"),
    ("Alur Kerja End-to-End Multi-Peran", "tests/test_end_to_end.py"),
    ("Validasi Input & Rate Limiting", "tests/test_rate_limit.py"),
]


def reset_server_limiter():
    """Mengirim sinyal reset ke backend sebelum setiap pengujian dieksekusi."""
    try:
        req = urllib.request.Request(
            "http://127.0.0.1:8000/api/v1/system/reset-limiter",
            data=b"{}",
            headers={"Content-Type": "application/json"},
            method="POST"
        )
        with urllib.request.urlopen(req) as resp:
            return resp.getcode() == 200
    except Exception:
        return False


def run_master_suite():
    print("=" * 70)
    print("      DPR RI PDP SYSTEM - MASTER SECURITY & COMPLIANCE TEST RUNNER")
    print("=" * 70)

    results = []
    total_start = time.time()

    for title, script_path in TEST_SUITES:
        reset_server_limiter()

        print(f"\n[>] Menjalankan pengujian: {title} ({script_path})...")
        start_time = time.time()
        
        proc = subprocess.run([sys.executable, script_path], capture_output=True, text=True)
        duration = round(time.time() - start_time, 2)

        if proc.returncode == 0:
            print(f"    Status: LULUS ({duration}s)")
            results.append((title, "LULUS", duration, None))
        else:
            print(f"    Status: GAGAL ({duration}s)")
            err_snippet = proc.stderr.strip() or proc.stdout.strip()
            results.append((title, "GAGAL", duration, err_snippet[-300:]))

    reset_server_limiter()

    total_duration = round(time.time() - total_start, 2)

    print("\n" + "=" * 70)
    print("                    RINGKASAN HASIL EVALUASI")
    print("=" * 70)
    all_passed = True
    for title, status, duration, error in results:
        badge = "[✓] PASS" if status == "LULUS" else "[✗] FAIL"
        print(f" {badge:<10} | {duration:>5}s | {title}")
        if error:
            all_passed = False
            print(f"     -> Cuplikan Error:\n{error}\n")

    print("-" * 70)
    print(f" Total Durasi: {total_duration} detik")
    if all_passed:
        print(" HASIL AKHIR : SELURUH MODUL KEAMANAN & KEPATUHAN DINYATAKAN LULUS!")
    else:
        print(" HASIL AKHIR : TERDAPAT PENGUJIAN YANG GAGAL. SILAKAN PERIKSA KEMBALI.")
    print("=" * 70)


if __name__ == "__main__":
    run_master_suite()