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


def test_validation_and_rate_limit():
    print("=" * 65)
    print("   PENGUJIAN VALIDASI INPUT & RATE LIMITING API")
    print("=" * 65)

    print("\n[*] 1. Login operator untuk mendapatkan token...")
    code, auth = send_api("POST", "/api/v1/auth/login", {
        "username": "operator1",
        "password": "OperatorPass2026!"
    })
    assert code == 200, f"Login gagal: {auth}"
    token = auth["access_token"]

    print("[*] 2. Uji kirim NIK tidak valid (hanya 5 digit: '12345')...")
    code, res_invalid = send_api("POST", "/api/v1/anggota/search/nik", {"nik": "12345"}, token=token)
    assert code == 422, f"Harusnya ditolak 422 Unprocessable Entity, dapat {code}: {res_invalid}"
    print("  [PASS] NIK tidak valid berhasil ditolak validator Pydantic (422).")

    print("\n[*] 3. Uji simulasi brute force pada endpoint login...")
    blocked = False
    for i in range(1, 8):
        status, res = send_api("POST", "/api/v1/auth/login", {
            "username": "operator1",
            "password": "WrongPassword!"
        })
        print(f"  -> Percobaan ke-{i}: Status {status}")
        if status == 429:
            blocked = True
            print(f"  [PASS] Request ke-{i} diblokir dengan status 429 Too Many Requests.")
            break

    assert blocked, "Rate limiter gagal memblokir serangan brute force login."

    print("\n" + "=" * 65)
    print("[V] VALIDASI INPUT & RATE LIMITING TERVERIFIKASI BERHASIL.")
    print("=" * 65)


if __name__ == "__main__":
    test_validation_and_rate_limit()