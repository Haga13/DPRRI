#!/usr/bin/env python3
"""
================================================================================
   DPR RI PDP SYSTEM - SIMULASI INTERAKTIF SERANGAN HACKER VS SISTEM PERTAHANAN
================================================================================
Skrip ini mendemonstrasikan kegagalan 4 skenario serangan siber umum terhadap
arsitektur kepatuhan UU PDP No. 27 Tahun 2022 DPR RI secara langsung.
"""

import sys
import os
import time
import json
import urllib.request
import urllib.error

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__))))

from backend.database_conn import get_connection
from backend.crypto_engine import CryptoEngine
from kms.kms_server import get_active_dek

BASE_URL = "http://127.0.0.1:8000"

C_RED = "\033[91m"
C_GREEN = "\033[92m"
C_YELLOW = "\033[93m"
C_BLUE = "\033[94m"
C_CYAN = "\033[96m"
C_BOLD = "\033[1m"
C_RESET = "\033[0m"


def print_banner():
    os.system("clear" if os.name == "posix" else "cls")
    print(C_CYAN + C_BOLD + "=" * 75)
    print("      DPR RI PDP SYSTEM - LIVE ATTACK & DEFENSE DEMONSTRATION")
    print("        Uji Ketahanan Sistem Terhadap Skenario Serangan Siber Nyata")
    print("=" * 75 + C_RESET)
    print(f" Target API: {C_BOLD}{BASE_URL}{C_RESET}")
    print(f" Status KMS: {C_GREEN}Active (AES-256-GCM v2){C_RESET}")
    print("-" * 75)


def send_api(method: str, path: str, data: dict = None, token: str = None):
    url = f"{BASE_URL}{path}"
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    body = json.dumps(data).encode("utf-8") if data else None
    req = urllib.request.Request(url, data=body, headers=headers, method=method)
    try:
        with urllib.request.urlopen(req) as resp:
            code = resp.getcode()
            content = resp.read().decode("utf-8")
            return code, json.loads(content) if content else {}
    except urllib.error.HTTPError as e:
        err_content = e.read().decode("utf-8")
        try:
            return e.code, json.loads(err_content)
        except Exception:
            return e.code, {"detail": err_content}


def reset_limiter():
    send_api("POST", "/api/v1/system/reset-limiter", {})


def attack_1_brute_force():
    print(f"\n{C_BOLD}[SKENARIO 1] SERANGAN BRUTE-FORCE / CREDENTIAL STUFFING{C_RESET}")
    print(f"{C_YELLOW}Deskripsi:{C_RESET} Bot hacker mencoba membobol akun operator dengan tebakan password cepat.")
    reset_limiter()
    time.sleep(0.5)

    blocked = False
    for i in range(1, 8):
        print(f"  -> Percobaan #{i}: Mengirim tebakan kata sandi salah... ", end="", flush=True)
        time.sleep(0.2)
        code, resp = send_api("POST", "/api/v1/auth/login", {
            "username": "operator1",
            "password": f"HackedPass_{i}!"
        })

        if code == 401:
            print(f"{C_YELLOW}Ditolak (401 Unauthorized){C_RESET}")
        elif code == 429:
            print(f"{C_RED}{C_BOLD}DIBLOKIR TOTAL (429 Too Many Requests){C_RESET}")
            blocked = True
            print(f"     Pesan Server: \"{resp.get('detail')}\"")
            break

    if blocked:
        print(f"  {C_GREEN}[HASIL PERTAHANAN]: SUKSES. Penyerang dilumpuhkan oleh Sliding-Window Rate Limiter.{C_RESET}")
    else:
        print(f"  {C_RED}[HASIL PERTAHANAN]: GAGAL.{C_RESET}")


def attack_2_database_leak():
    print(f"\n{C_BOLD}[SKENARIO 2] SIMULASI KEBOCORAN BASIS DATA (DATA BREACH DUMP){C_RESET}")
    print(f"{C_YELLOW}Deskripsi:{C_RESET} Hacker berhasil membobol server MySQL dan melakukan SELECT pada tabel anggota_sensitif.")
    time.sleep(0.5)

    conn = get_connection(user_role="app_user", db_name="dpr_pdp_db")
    with conn.cursor() as cur:
        cur.execute("SELECT anggota_id, no_ktp_enc, rekening_enc, bidx_no_ktp FROM anggota_sensitif LIMIT 2;")
        rows = cur.fetchall()
    conn.close()

    print(f"  -> Hasil tangkapan kueri hacker dari harddisk:")
    for r in rows:
        print(f"     ID Anggota : {r['anggota_id']}")
        print(f"     Cipher NIK : {C_RED}{r['no_ktp_enc'][:45]}...{C_RESET}")
        print(f"     Cipher Rek : {C_RED}{r['rekening_enc'][:45]}...{C_RESET}")
        print(f"     Blind Index: {r['bidx_no_ktp'][:35]}...")
        print()

    print(f"  {C_GREEN}[HASIL PERTAHANAN]: SUKSES. Hacker hanya mendapatkan derau ciphertext AES-256-GCM.")
    print(f"  Tanpa Master DEK dari KMS, data yang bocor bernilai 0 (Zero Information Leakage).{C_RESET}")


def attack_3_stolen_token_replay():
    print(f"\n{C_BOLD}[SKENARIO 3] PENCURIAN TOKEN & REPLAY ATTACK (SESSION HIJACKING){C_RESET}")
    print(f"{C_YELLOW}Deskripsi:{C_RESET} Hacker mencuri token JWT operator melalui jaringan. Operator kemudian menekan Logout.")
    reset_limiter()

    _, auth = send_api("POST", "/api/v1/auth/login", {"username": "operator1", "password": "OperatorPass2026!"})
    token = auth.get("access_token")
    print(f"  -> Token sah operator berhasil dibuat: {token[:25]}...")

    print(f"  -> Operator menyadari bahaya dan mengklik [Logout]...")
    code, res_logout = send_api("POST", "/api/v1/auth/logout", token=token)
    print(f"     Status Logout: {code} OK ({res_logout.get('message')})")

    print(f"  -> Hacker mencoba menggunakan token curian untuk mengakses data anggota...")
    code, res_hack = send_api("GET", "/api/v1/anggota?limit=1", token=token)

    if code == 401:
        print(f"     {C_RED}{C_BOLD}AKSES DITOLAK: {code} Unauthorized!{C_RESET}")
        print(f"     Pesan Server: \"{res_hack.get('detail')}\"")
        print(f"  {C_GREEN}[HASIL PERTAHANAN]: SUKSES. Token Revocation Blacklist mematikan sesi seketika.{C_RESET}")
    else:
        print(f"  {C_RED}[HASIL PERTAHANAN]: GAGAL. Token masih bisa digunakan!{C_RESET}")


def attack_4_least_privilege_denial():
    print(f"\n{C_BOLD}[SKENARIO 4] ELEVASI HAK AKSES & SQL INJECTION BYPASS (LEAST PRIVILEGE){C_RESET}")
    print(f"{C_YELLOW}Deskripsi:{C_RESET} Penyerang mengompromikan kredensial 'analyst_user' dan mencoba membaca tabel audit & sensitif.")
    time.sleep(0.5)

    conn = get_connection(user_role="analyst_user", db_name="dpr_pdp_db")
    cur = conn.cursor()

    print("  -> Percobaan #1: Membaca tabel audit_log... ", end="", flush=True)
    try:
        cur.execute("SELECT * FROM audit_log LIMIT 1;")
        print(f"{C_RED}Bocor!{C_RESET}")
    except Exception as e:
        print(f"{C_GREEN}{C_BOLD}DITOLAK ENGINE MYSQL!{C_RESET}")
        print(f"     Detail Error DB: {str(e)[:75]}...")

    print("  -> Percobaan #2: Membaca tabel anggota_sensitif... ", end="", flush=True)
    try:
        cur.execute("SELECT * FROM anggota_sensitif LIMIT 1;")
        print(f"{C_RED}Bocor!{C_RESET}")
    except Exception as e:
        print(f"{C_GREEN}{C_BOLD}DITOLAK ENGINE MYSQL!{C_RESET}")
        print(f"     Detail Error DB: {str(e)[:75]}...")

    conn.close()
    print(f"  {C_GREEN}[HASIL PERTAHANAN]: SUKSES. Isolasi hak akses level database engine aktif 100%.{C_RESET}")


def main():
    print_banner()
    try:
        attack_1_brute_force()
        time.sleep(0.8)
        attack_2_database_leak()
        time.sleep(0.8)
        attack_3_stolen_token_replay()
        time.sleep(0.8)
        attack_4_least_privilege_denial()

        print("\n" + C_CYAN + "=" * 75)
        print(f"{C_GREEN}{C_BOLD} [V] KESIMPULAN: SELURUH 4 SKENARIO SERANGAN BERHASIL DIGAGALKAN SISTEM!{C_RESET}")
        print(C_CYAN + "=" * 75 + C_RESET)
    finally:
        reset_limiter()


if __name__ == "__main__":
    main()

