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


def test_retention_purge():
    print("=" * 65)
    print("   PENGUJIAN PEMUSNAHAN DATA RETENSI (RIGHT TO BE FORGOTTEN)")
    print("=" * 65)

    print("\n[*] 1. Login admin1...")
    code, auth_adm = send_api("POST", "/api/v1/auth/login", {
        "username": "admin1",
        "password": "AdminPass2026!"
    })
    assert code == 200, f"Login gagal: {auth_adm}"
    token_adm = auth_adm["access_token"]
    print("  [PASS] Admin1 login berhasil.")

    code, pub_list = send_api("GET", "/api/v1/anggota?limit=1&offset=730", token=token_adm)
    assert code == 200 and len(pub_list) > 0, "Gagal mengambil target uji."
    target_id = pub_list[-1]["id"]
    print(f"  -> Target ID yang akan diuji pemusnahan: {target_id}")

    print(f"\n[*] 2. Menjalankan pemusnahan data sensitif ID {target_id}...")
    code, res_purge = send_api("DELETE", f"/api/v1/anggota/{target_id}/retention-purge", token=token_adm)
    assert code == 200, f"Purge gagal: {res_purge}"
    print(f"  [PASS] Respons API: {res_purge.get('message')}")

    print("\n[*] 3. Memverifikasi akses data sensitif ID tersebut...")
    code, res_check = send_api("GET", f"/api/v1/anggota/{target_id}/sensitive", token=token_adm)
    assert code == 404, f"Harusnya 404 Not Found, tetapi didapat {code}"
    print("  [PASS] Data sensitif terkonfirmasi sudah musnah total (404 Not Found).")

    print("\n" + "=" * 65)
    print("[V] PENGUJIAN PEMUSNAHAN DATA RETENSI BERHASIL TERVERIFIKASI.")
    print("=" * 65)


if __name__ == "__main__":
    test_retention_purge()