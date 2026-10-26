import sys
import os

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

import json
import urllib.request
import urllib.error
import pymysql
from dotenv import load_dotenv

load_dotenv()

from kms.kms_server import get_active_dek
from backend.crypto_engine import CryptoEngine

BASE_URL = "http://127.0.0.1:8000"


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


def run_e2e_verification():
    print("=" * 65)
    print("   DPR RI PDP SYSTEM - PENGUJIAN END-TO-END WORKFLOW")
    print("=" * 65)

    print("\n[+] Skenario 1: Operator mencari data anggota via NIK...")
    
    status, auth_op = send_api("POST", "/api/v1/auth/login", {
        "username": "operator1",
        "password": "OperatorPass2026!"
    })
    assert status == 200, f"Login operator gagal: {auth_op}"
    token_op = auth_op["access_token"]
    print("  -> Operator1 login berhasil.")

    status, pub_list = send_api("GET", "/api/v1/anggota?limit=1", token=token_op)
    assert status == 200 and len(pub_list) > 0, "Gagal mengambil data publik."
    target_id = pub_list[0]["id"]

    dek, _ = get_active_dek()
    crypto = CryptoEngine(dek=dek, pepper=os.getenv("MASTER_PEPPER", "dpr-ri-pdp-secret-pepper-2026"))
    
    conn = pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", 3306)),
        user="app_user",
        password=os.getenv("DB_APP_PASS", "App_P@ssw0rd_2026!"),
        database=os.getenv("DB_NAME", "dpr_pdp_db"),
        cursorclass=pymysql.cursors.DictCursor
    )
    with conn.cursor() as cur:
        cur.execute("SELECT no_ktp_enc FROM anggota_sensitif WHERE anggota_id = %s;", (target_id,))
        sample_ktp_enc = cur.fetchone()["no_ktp_enc"]
        sample_nik = crypto.decrypt(sample_ktp_enc)
    conn.close()

    status, res_search = send_api("POST", "/api/v1/anggota/search/nik", {"nik": sample_nik}, token=token_op)
    assert status == 200, f"Pencarian NIK gagal: {res_search}"
    print(f"  -> Hasil Sensor NIK     : {res_search.get('no_ktp_masked')}")
    print(f"  -> Hasil Sensor Nama    : {res_search.get('nama_lengkap')}")
    print(f"  -> Hasil Sensor Rekening: {res_search.get('rekening_masked')}")
    assert "*" in res_search.get("no_ktp_masked", ""), "NIK harus tersensor"
    assert "*" in res_search.get("nama_lengkap", ""), "Nama harus tersensor"

    print("\n[+] Skenario 2: Administrator mengakses data sensitif penuh...")
    
    status, auth_adm = send_api("POST", "/api/v1/auth/login", {
        "username": "admin1",
        "password": "AdminPass2026!"
    })
    assert status == 200, f"Login admin gagal: {auth_adm}"
    token_adm = auth_adm["access_token"]
    print("  -> Admin1 login berhasil.")

    status, res_sens = send_api("GET", f"/api/v1/anggota/{target_id}/sensitive", token=token_adm)
    assert status == 200, f"Akses data sensitif gagal: {res_sens}"
    print(f"  -> NIK Terdekripsi   : {res_sens.get('no_ktp')}")
    print(f"  -> NPWP Terdekripsi  : {res_sens.get('npwp')}")
    print(f"  -> KMS Key Version   : {res_sens.get('key_version')}")
    assert res_sens.get("no_ktp") == sample_nik, "Data dekripsi harus cocok dengan NIK sumber"

    print("\n[+] Skenario 3: Auditor memverifikasi rekaman jejak audit...")
    
    status, auth_aud = send_api("POST", "/api/v1/auth/login", {
        "username": "auditor1",
        "password": "AuditorPass2026!"
    })
    assert status == 200, f"Login auditor gagal: {auth_aud}"
    token_aud = auth_aud["access_token"]
    print("  -> Auditor1 login berhasil.")

    status, logs = send_api("GET", "/api/v1/audit-logs?limit=5", token=token_aud)
    assert status == 200 and len(logs) >= 2, f"Gagal membaca log: {logs}"
    
    print("  -> Log aktivitas terbaru:")
    for log in logs[:2]:
        print(f"     * [{log.get('accessed_at')}] User: {log.get('user_id')} ({log.get('role')}) -> Aksi: {log.get('action')} (Target ID: {log.get('target_anggota_id')})")

    print("\n" + "=" * 65)
    print("[V] INTEGRASI SELESAI: SELURUH ALUR KERJA BERHASIL TERVERIFIKASI!")
    print("=" * 65)


if __name__ == "__main__":
    run_e2e_verification()