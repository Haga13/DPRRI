import requests

BASE_URL = "http://127.0.0.1:8000"

def run_tests():
    print("=" * 65)
    print("   PENGUJIAN AUTENTIKASI JWT & OTORISASI API (RBAC)")
    print("=" * 65)

    print("\n[*] 1. Login sebagai operator1 (app_user)...")
    res_op = requests.post(f"{BASE_URL}/api/v1/auth/login", json={
        "username": "operator1",
        "password": "OperatorPass2026!"
    })
    assert res_op.status_code == 200, f"Login gagal: {res_op.text}"
    token_op = res_op.json()["access_token"]
    print("  [PASS] Login berhasil, JWT diterima.")

    print("\n[*] 2. Uji login kredensial tidak valid...")
    res_fail = requests.post(f"{BASE_URL}/api/v1/auth/login", json={
        "username": "operator1",
        "password": "SalahPassword!"
    })
    assert res_fail.status_code == 401, "Seharusnya ditolak 401 Unauthorized"
    print("  [PASS] Kredensial salah berhasil ditolak (401 Unauthorized).")

    print("\n[*] 3. Akses /api/v1/anggota dengan Bearer Token operator...")
    res_data = requests.get(
        f"{BASE_URL}/api/v1/anggota?limit=2",
        headers={"Authorization": f"Bearer {token_op}"}
    )
    assert res_data.status_code == 200, f"Akses ditolak: {res_data.text}"
    print("  [PASS] Akses berhasil diberikan (200 OK).")

    print("\n[*] 4. Coba akses audit log menggunakan token app_user (wajib ditolak)...")
    res_forbidden = requests.get(
        f"{BASE_URL}/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {token_op}"}
    )
    assert res_forbidden.status_code == 403, f"Seharusnya ditolak 403: {res_forbidden.text}"
    print("  [PASS] Pelanggaran RBAC ditolak (403 Forbidden).")

    print("\n[*] 5. Login sebagai auditor1 dan akses audit log...")
    res_aud = requests.post(f"{BASE_URL}/api/v1/auth/login", json={
        "username": "auditor1",
        "password": "AuditorPass2026!"
    })
    token_aud = res_aud.json()["access_token"]
    res_audit_ok = requests.get(
        f"{BASE_URL}/api/v1/audit-logs",
        headers={"Authorization": f"Bearer {token_aud}"}
    )
    assert res_audit_ok.status_code == 200, f"Gagal akses log: {res_audit_ok.text}"
    print("  [PASS] Auditor berhasil membaca audit_log (200 OK).")

    print("\n" + "=" * 65)
    print("[V] SELURUH PENGUJIAN JWT & RBAC BERHASIL TERVERIFIKASI.")
    print("=" * 65)

if __name__ == "__main__":
    run_tests()