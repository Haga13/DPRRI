#!/usr/bin/env python3
"""
================================================================================
   DPR RI PDP SYSTEM - ESCALATING STRESS BENCHMARK WITH AUTO-CUTOFF
================================================================================
Skrip pengujian beban bertingkat (Escalating Request Rounds):
1.000 -> 2.000 -> 3.000 -> 5.000 -> 7.500 -> 10.000 request kueri.

Fitur Utama:
- Auto Cut-off (Circuit Breaker): Jika latensi p95 melebihi batas ambang (Default: 100 ms),
  skrip otomatis memutus pengujian untuk mencegah kejenuhan/saturasi basis data.
- Komparasi Langsung: Database Sebelum (`dprri`) vs Database Sesudah (`dpr_pdp_db`).
- Mengukur stabilitas p50, p95, Throughput RPS, dan Error Rate di setiap eskalasi beban.
================================================================================
"""

import os
import sys
import time
import json
import random
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


def run_stress_loop(stages=None, cutoff_limit=LATENCY_CUTOFF_LIMIT_MS):
    if stages is None:
        stages = DEFAULT_STAGES

    print("=" * 85)
    print("      DPR RI PDP SYSTEM - STRESS BENCHMARK DENGAN AUTO CUT-OFF (100 ms)")
    print(f"      Tahapan Request : {stages}")
    print(f"      Batas Ambang Cut-Off : Latensi p95 > {cutoff_limit} ms")
    print("=" * 85)

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
        print(f"\n" + "-" * 85)
        print(f"[>] Menjalankan Tahap Pengujian: {stage_requests:,} Permintaan Kueri...")
        print("-" * 85)

        # Bangkitkan sample kueri untuk tahap ini
        sample_queries = [random.choice(all_niks) for _ in range(stage_requests)]

        # --- A. Uji Database SEBELUM Dilindungi (dprri) ---
        times_plain = []
        t_start = time.perf_counter()
        for nik in sample_queries:
            t0 = time.perf_counter()
            cur.execute("SELECT * FROM dprri.anggota WHERE no_ktp = %s LIMIT 1;", (nik,))
            _ = cur.fetchone()
            times_plain.append((time.perf_counter() - t0) * 1000)
        dur_plain = time.perf_counter() - t_start
        rps_plain = round(stage_requests / dur_plain, 2)
        p50_plain = get_percentile(times_plain, 50)
        p95_plain = get_percentile(times_plain, 95)

        # --- B. Uji Database SESUDAH Dilindungi (dpr_pdp_db - Blind Index + JIT AES) ---
        times_prot = []
        t_start = time.perf_counter()
        for nik in sample_queries:
            t0 = time.perf_counter()
            bidx = crypto.compute_blind_index(nik)
            cur.execute("SELECT * FROM dpr_pdp_db.anggota_sensitif WHERE bidx_no_ktp = %s LIMIT 1;", (bidx,))
            row = cur.fetchone()
            if row and row.get("no_ktp_enc"):
                _ = crypto.decrypt(row["no_ktp_enc"])
                if row.get("rekening_enc"):
                    _ = crypto.decrypt(row["rekening_enc"])
            times_prot.append((time.perf_counter() - t0) * 1000)
        dur_prot = time.perf_counter() - t_start
        rps_prot = round(stage_requests / dur_prot, 2)
        p50_prot = get_percentile(times_prot, 50)
        p95_prot = get_percentile(times_prot, 95)

        print(f"    [Sebelum - dprri]       Durasi: {dur_plain:.2f}s | p50: {p50_plain} ms | p95: {p95_plain} ms | Throughput: {rps_plain} RPS")
        print(f"    [Sesudah - dpr_pdp_db]  Durasi: {dur_prot:.2f}s | p50: {p50_prot} ms | p95: {p95_prot} ms | Throughput: {rps_prot} RPS")

        stage_record = {
            "requests": stage_requests,
            "plain_p50": p50_plain,
            "plain_p95": p95_plain,
            "plain_rps": rps_plain,
            "prot_p50": p50_prot,
            "prot_p95": p95_prot,
            "prot_rps": rps_prot,
            "status": "PASSED (Dalam Batas SLA)"
        }
        results_table.append(stage_record)

        # --- C. Pemeriksaan Circuit Breaker (Auto Cut-Off) ---
        if p95_prot > cutoff_limit or p95_plain > cutoff_limit:
            cutoff_triggered = True
            offending_val = max(p95_prot, p95_plain)
            offending_db = "dpr_pdp_db" if p95_prot >= p95_plain else "dprri"
            cutoff_reason = f"Latensi p95 pada {offending_db} mencapai {offending_val} ms (melebihi batas aman {cutoff_limit} ms)!"
            stage_record["status"] = f"CUT-OFF TRIGGERED ({offending_val} ms > {cutoff_limit} ms)"
            print(f"\n[⚠️] PERINGATAN CIRCUIT BREAKER DILEPASKAN!")
            print(f"    {cutoff_reason}")
            print(f"    Looping pengujian OTOMATIS DIHENTIKAN pada tahap {stage_requests:,} request untuk menjaga kesehatan server.")
            break

    conn.close()

    # Cetak Rekapitulasi Matriks Hasil
    print("\n" + "=" * 95)
    print("               REKAPITULASI HASIL STRESS TEST BERJENJANG DENGAN CIRCUIT BREAKER")
    print("=" * 95)
    print(f"{'Tahap Beban':>12} | {'Plain p50':>10} | {'Plain p95':>10} | {'Prot p50':>10} | {'Prot p95':>10} | {'Prot RPS':>10} | {'Status SLA'}")
    print("-" * 95)
    for r in results_table:
        print(f"{r['requests']:>10,} req | {r['plain_p50']:>8} ms | {r['plain_p95']:>8} ms | {r['prot_p50']:>7} ms | {r['prot_p95']:>8} ms | {r['prot_rps']:>7} RPS | {r['status']}")
    print("=" * 95)

    if not cutoff_triggered:
        print(f"[✓] SELURUH TAHAP SELESAI DENGAN SUKSES! Latensi sistem selalu berada di bawah {cutoff_limit} ms.")
    else:
        print(f"[!] Pengujian dihentikan secara protektif oleh sistem: {cutoff_reason}")


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Escalating stress benchmark with auto-cutoff")
    parser.add_argument("--stages", nargs="+", type=int, default=DEFAULT_STAGES, help="Daftar jumlah request berjenjang (e.g. 1000 2000 3000 5000)")
    parser.add_argument("--cutoff-ms", type=float, default=LATENCY_CUTOFF_LIMIT_MS, help="Batas toleransi latensi p95 untuk auto cut-off (default: 100.0 ms)")

    args = parser.parse_args()
    run_stress_loop(stages=args.stages, cutoff_limit=args.cutoff_ms)

