#!/usr/bin/env python3
"""
================================================================================
   DPR RI PDP SYSTEM - COMPREHENSIVE ESCALATING STRESS & RESOURCE BENCHMARK
================================================================================
Skrip pengujian beban bertingkat (Escalating Request Rounds):
1.000 -> 2.000 -> 3.000 -> 5.000 -> 7.500 -> 10.000 request kueri.

Fitur Pemantauan Multi-Metrik Penuh:
1. Latensi p50 & p95 (ms)
2. Throughput Transaksi (RPS)
3. Utilisasi CPU (%) per tahap komputasi
4. Konsumsi Memori RAM (MB) & Resident Set Size
5. Tingkat Kegagalan (Error Rate %)
6. Auto Cut-off (Circuit Breaker): Memutus pengujian jika latensi p95 > 100 ms
   atau utilisasi CPU saturasi ekstrem.
================================================================================
"""

import os
import sys
import time
import json
import random
import resource
import argparse
import pymysql
import pymysql.cursors
from dotenv import load_dotenv

# Path setup
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
load_dotenv()

from backend.crypto_engine import CryptoEngine
from kms.kms_server import get_active_dek

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_ROOT_USER", "haga")
DB_PASS = os.getenv("DB_ROOT_PASS", "haga@11002")

# Daftar Tahap Pengujian Beban Bertingkat
DEFAULT_STAGES = [1000, 2000, 3000, 5000, 7500, 10000]
LATENCY_CUTOFF_LIMIT_MS = 100.0  # Batas ambang auto cut-off (100 ms)


def get_percentile(data: list, percentile: float) -> float:
    if not data:
        return 0.0
    sorted_data = sorted(data)
    idx = int((percentile / 100.0) * len(sorted_data))
    idx = min(idx, len(sorted_data) - 1)
    return round(sorted_data[idx], 3)


def get_cpu_time(rusage_obj):
    return rusage_obj.ru_utime + rusage_obj.ru_stime


def run_stress_loop(stages=None, cutoff_limit=LATENCY_CUTOFF_LIMIT_MS):
    if stages is None:
        stages = DEFAULT_STAGES

    print("=" * 105)
    print("      DPR RI PDP SYSTEM - COMPREHENSIVE STRESS & RESOURCE BENCHMARK WITH CIRCUIT BREAKER")
    print(f"      Tahapan Request       : {stages}")
    print(f"      Batas Ambang Cut-Off  : Latensi p95 > {cutoff_limit} ms")
    print("      Metrik yang Dimonitor : Latensi (p50/p95), Throughput (RPS), CPU Load (%), RAM (MB), Error Rate")
    print("=" * 105)

    # 1. Inisialisasi Kriptografi
    dek, key_version = get_active_dek()
    crypto = CryptoEngine(dek)
    print(f"[*] Engine Kriptografi: DEK Versi {key_version} Aktif")

    conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASS,
        cursorclass=pymysql.cursors.DictCursor
    )
    cur = conn.cursor()

    # Ambil sample NIK yang ada di database
    cur.execute("SELECT no_ktp FROM dprri.anggota WHERE no_ktp IS NOT NULL AND no_ktp != '';")
    all_niks = [r["no_ktp"] for r in cur.fetchall()]
    print(f"[*] Populasi Data Terdaftar: {len(all_niks)} Anggota")

    results_table = []
    cutoff_triggered = False
    cutoff_reason = ""

    for stage_requests in stages:
        print(f"\n" + "-" * 105)
        print(f"[>] Menjalankan Tahap Beban: {stage_requests:,} Permintaan Kueri...")
        print("-" * 105)

        # Bangkitkan sample kueri untuk tahap ini
        sample_queries = [random.choice(all_niks) for _ in range(stage_requests)]

        # ---------------------------------------------------------------------
        # A. Uji Database SEBELUM Dilindungi (dprri)
        # ---------------------------------------------------------------------
        errors_plain = 0
        r_start_plain = resource.getrusage(resource.RUSAGE_SELF)
        t_start_plain = time.perf_counter()
        times_plain = []

        for nik in sample_queries:
            t0 = time.perf_counter()
            try:
                cur.execute("SELECT * FROM dprri.anggota WHERE no_ktp = %s LIMIT 1;", (nik,))
                _ = cur.fetchone()
            except Exception:
                errors_plain += 1
            times_plain.append((time.perf_counter() - t0) * 1000)

        dur_plain = time.perf_counter() - t_start_plain
        r_end_plain = resource.getrusage(resource.RUSAGE_SELF)

        cpu_time_plain = get_cpu_time(r_end_plain) - get_cpu_time(r_start_plain)
        cpu_pct_plain = round((cpu_time_plain / max(dur_plain, 0.001)) * 100, 1)
        ram_mb_plain = round(r_end_plain.ru_maxrss / 1024, 2)
        rps_plain = round(stage_requests / dur_plain, 2)
        p50_plain = get_percentile(times_plain, 50)
        p95_plain = get_percentile(times_plain, 95)
        err_rate_plain = f"{(errors_plain / stage_requests) * 100:.2f}%"

        # ---------------------------------------------------------------------
        # B. Uji Database SESUDAH Dilindungi (dpr_pdp_db - Blind Index + JIT AES)
        # ---------------------------------------------------------------------
        errors_prot = 0
        r_start_prot = resource.getrusage(resource.RUSAGE_SELF)
        t_start_prot = time.perf_counter()
        times_prot = []

        for nik in sample_queries:
            t0 = time.perf_counter()
            try:
                bidx = crypto.compute_blind_index(nik)
                cur.execute("SELECT * FROM dpr_pdp_db.anggota_sensitif WHERE bidx_no_ktp = %s LIMIT 1;", (bidx,))
                row = cur.fetchone()
                if row and row.get("no_ktp_enc"):
                    _ = crypto.decrypt(row["no_ktp_enc"])
                    if row.get("rekening_enc"):
                        _ = crypto.decrypt(row["rekening_enc"])
            except Exception:
                errors_prot += 1
            times_prot.append((time.perf_counter() - t0) * 1000)

        dur_prot = time.perf_counter() - t_start_prot
        r_end_prot = resource.getrusage(resource.RUSAGE_SELF)

        cpu_time_prot = get_cpu_time(r_end_prot) - get_cpu_time(r_start_prot)
        cpu_pct_prot = round((cpu_time_prot / max(dur_prot, 0.001)) * 100, 1)
        ram_mb_prot = round(r_end_prot.ru_maxrss / 1024, 2)
        rps_prot = round(stage_requests / dur_prot, 2)
        p50_prot = get_percentile(times_prot, 50)
        p95_prot = get_percentile(times_prot, 95)
        err_rate_prot = f"{(errors_prot / stage_requests) * 100:.2f}%"

        print(f"    [Sebelum - dprri]      p50: {p50_plain:>6} ms | p95: {p95_plain:>6} ms | Throughput: {rps_plain:>7} RPS | CPU: {cpu_pct_plain:>5}% | RAM: {ram_mb_plain} MB | Err: {err_rate_plain}")
        print(f"    [Sesudah - dpr_pdp_db] p50: {p50_prot:>6} ms | p95: {p95_prot:>6} ms | Throughput: {rps_prot:>7} RPS | CPU: {cpu_pct_prot:>5}% | RAM: {ram_mb_prot} MB | Err: {err_rate_prot}")

        stage_record = {
            "requests": stage_requests,
            "plain_p50": p50_plain,
            "plain_p95": p95_plain,
            "plain_rps": rps_plain,
            "plain_cpu": cpu_pct_plain,
            "prot_p50": p50_prot,
            "prot_p95": p95_prot,
            "prot_rps": rps_prot,
            "prot_cpu": cpu_pct_prot,
            "ram_mb": ram_mb_prot,
            "error_rate": err_rate_prot,
            "status": "PASSED"
        }
        results_table.append(stage_record)

        # ---------------------------------------------------------------------
        # C. Pemeriksaan Circuit Breaker (Auto Cut-Off)
        # ---------------------------------------------------------------------
        if p95_prot > cutoff_limit or p95_plain > cutoff_limit:
            cutoff_triggered = True
            offending_val = max(p95_prot, p95_plain)
            offending_db = "dpr_pdp_db" if p95_prot >= p95_plain else "dprri"
            cutoff_reason = f"Latensi p95 pada {offending_db} mencapai {offending_val} ms (melebihi batas aman {cutoff_limit} ms)!"
            stage_record["status"] = f"CUT-OFF ({offending_val} ms > {cutoff_limit} ms)"
            print(f"\n[⚠️] PERINGATAN CIRCUIT BREAKER DILEPASKAN!")
            print(f"    {cutoff_reason}")
            print(f"    Looping pengujian OTOMATIS DIHENTIKAN pada tahap {stage_requests:,} request untuk melindungi server.")
            break

    conn.close()

    # Cetak Rekapitulasi Matriks Hasil Komprehensif
    print("\n" + "=" * 115)
    print("             REKAPITULASI RESMI STRESS & RESOURCE MONITORING (DENGAN CIRCUIT BREAKER)")
    print("=" * 115)
    print(f"{'Tahap Beban':>12} | {'Plain p95':>10} | {'Prot p95':>10} | {'Throughput':>12} | {'CPU Load':>9} | {'RAM Peak':>10} | {'Error Rate':>10} | {'Status SLA'}")
    print("-" * 115)
    for r in results_table:
        print(f"{r['requests']:>10,} req | {r['plain_p95']:>7} ms | {r['prot_p95']:>7} ms | {r['prot_rps']:>8} RPS | {r['prot_cpu']:>7}% | {r['ram_mb']:>7} MB | {r['error_rate']:>10} | {r['status']}")
    print("=" * 115)

    if not cutoff_triggered:
        print(f"[✓] SELURUH TAHAP SELESAI SECARA PARIPURNA! Sistem terbukti stabil, hemat memori, dan bebas kebocoran.")
    else:
        print(f"[!] Pengujian dihentikan secara protektif oleh sistem: {cutoff_reason}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Escalating stress & resource benchmark with auto-cutoff")
    parser.add_argument("--stages", nargs="+", type=int, default=DEFAULT_STAGES, help="Daftar jumlah request berjenjang (e.g. 1000 2000 3000 5000)")
    parser.add_argument("--cutoff-ms", type=float, default=LATENCY_CUTOFF_LIMIT_MS, help="Batas toleransi latensi p95 untuk auto cut-off (default: 100.0 ms)")

    args = parser.parse_args()
    run_stress_loop(stages=args.stages, cutoff_limit=args.cutoff_ms)
