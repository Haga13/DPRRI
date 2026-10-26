import sys
import os
import json
import urllib.request
import urllib.error

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

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


def test_token_revocation():
    print("=" * 65)
    print("   PENGUJIAN TOKEN REVOCATION & LOGOUT (JWT BLACKLIST)")
    print("=" * 65)

    print("\n[*] 1. Login operator1...")
    status, auth = send_api("POST", "/api/v1/auth/login", {
        "username": "operator1",
        "password": "OperatorPass2026!"
    })
    assert status == 200, f"Login gagal: {auth}"
    token = auth["access_token"]
    print("  [PASS] Login berhasil, token diperoleh.")

    print("\n[*] 2. Akses /api/v1/anggota sebelum logout...")
    status, _ = send_api("GET", "/api/v1/anggota?limit=1", token=token)
    assert status == 200, "Token sah harusnya dapat mengakses endpoint."
    print("  [PASS] Akses berhasil dengan token aktif (200 OK).")

    print("\n[*] 3. Menjalankan POST /api/v1/auth/logout...")
    status, res_logout = send_api("POST", "/api/v1/auth/logout", token=token)
    assert status == 200, f"Logout gagal: {res_logout}"
    print(f"  [PASS] Logout berhasil: {res_logout.get('message')}")

    print("\n[*] 4. Akses ulang endpoint menggunakan token yang telah dicabut...")
    status, res_blocked = send_api("GET", "/api/v1/anggota?limit=1", token=token)
    assert status == 401, f"Harusnya ditolak 401, didapat {status}: {res_blocked}"
    print(f"  [PASS] Token yang dicabut berhasil ditolak (401 Unauthorized): {res_blocked.get('detail')}")

    print("\n" + "=" * 65)
    print("[V] PENGUJIAN LOGOUT & TOKEN REVOCATION SELESAI DENGAN SUKSES.")
    print("=" * 65)


if __name__ == "__main__":
    test_token_revocation()