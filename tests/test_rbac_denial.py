import sys
import os
import pymysql
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_NAME = os.getenv("DB_NAME", "dpr_pdp_db")

CREDENTIALS = {
    "app_user": os.getenv("DB_APP_PASS", "App_P@ssw0rd_2026!"),
    "analyst_user": os.getenv("DB_ANALYST_PASS", "Analyst_P@ssw0rd_2026!"),
    "auditor_user": os.getenv("DB_AUDITOR_PASS", "Auditor_P@ssw0rd_2026!"),
    "backup_user": os.getenv("DB_BACKUP_PASS", "Backup_P@ssw0rd_2026!")
}


def test_connection(user: str, password: str):
    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=user,
        password=password,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )


def run_rbac_verification():
    print("=" * 65)
    print("   PENGUJIAN RBAC & PENOLAKAN AKSES TIDAK SAH (LEAST PRIVILEGE)")
    print("=" * 65)

    passed_tests = 0
    total_tests = 0

    print("\n[*] Menguji Role: app_user")
    try:
        conn = test_connection("app_user", CREDENTIALS["app_user"])
        cur = conn.cursor()

        total_tests += 1
        try:
            cur.execute("SELECT COUNT(*) AS total FROM `anggota`;")
            print("  [PASS] Akses Sah: Berhasil membaca tabel `anggota`.")
            passed_tests += 1
        except Exception as e:
            print(f"  [FAIL] Akses Sah Gagal: {e}")

        total_tests += 1
        try:
            cur.execute("DROP TABLE `audit_log`;")
            print("  [FAIL] Pelanggaran Keamanan: app_user diizinkan melakukan DROP TABLE!")
        except pymysql.err.OperationalError as e:
            print(f"  [PASS] Penolakan Akses: Percobaan DROP TABLE ditolak ({e.args[1]}).")
            passed_tests += 1
        conn.close()
    except Exception as e:
        print(f"  [-] Gagal terhubung sebagai app_user: {e}")

    print("\n[*] Menguji Role: analyst_user")
    try:
        conn = test_connection("analyst_user", CREDENTIALS["analyst_user"])
        cur = conn.cursor()

        total_tests += 1
        try:
            cur.execute("SELECT * FROM `v_analyst_anggota` LIMIT 1;")
            row = cur.fetchone()
            print(f"  [PASS] Akses Sah: Membaca View data tersensor (`nama_samaran`: {row.get('nama_samaran')}).")
            passed_tests += 1
        except Exception as e:
            print(f"  [FAIL] Akses View Gagal: {e}")

        total_tests += 1
        try:
            cur.execute("SELECT * FROM `anggota_sensitif` LIMIT 1;")
            print("  [FAIL] Pelanggaran Keamanan: analyst_user bisa membaca `anggota_sensitif`!")
        except pymysql.err.OperationalError as e:
            print(f"  [PASS] Penolakan Akses: Pembacaan tabel `anggota_sensitif` ditolak ({e.args[1]}).")
            passed_tests += 1

        total_tests += 1
        try:
            cur.execute("SELECT * FROM `audit_log` LIMIT 1;")
            print("  [FAIL] Pelanggaran Keamanan: analyst_user bisa membaca `audit_log`!")
        except pymysql.err.OperationalError as e:
            print(f"  [PASS] Penolakan Akses: Pembacaan tabel `audit_log` ditolak ({e.args[1]}).")
            passed_tests += 1
        conn.close()
    except Exception as e:
        print(f"  [-] Gagal terhubung sebagai analyst_user: {e}")

    print("\n[*] Menguji Role: auditor_user")
    try:
        conn = test_connection("auditor_user", CREDENTIALS["auditor_user"])
        cur = conn.cursor()

        total_tests += 1
        try:
            cur.execute("SELECT COUNT(*) AS total FROM `audit_log`;")
            print("  [PASS] Akses Sah: Berhasil membaca tabel `audit_log`.")
            passed_tests += 1
        except Exception as e:
            print(f"  [FAIL] Akses Sah Gagal: {e}")

        total_tests += 1
        try:
            cur.execute("SELECT * FROM `anggota` LIMIT 1;")
            print("  [FAIL] Pelanggaran Keamanan: auditor_user bisa membaca tabel `anggota`!")
        except pymysql.err.OperationalError as e:
            print(f"  [PASS] Penolakan Akses: Pembacaan tabel `anggota` ditolak ({e.args[1]}).")
            passed_tests += 1
        conn.close()
    except Exception as e:
        print(f"  [-] Gagal terhubung sebagai auditor_user: {e}")

    print("\n[*] Menguji Role: backup_user")
    try:
        conn = test_connection("backup_user", CREDENTIALS["backup_user"])
        cur = conn.cursor()

        total_tests += 1
        try:
            cur.execute("LOCK TABLES `anggota` READ, `anggota_sensitif` READ;")
            cur.execute("UNLOCK TABLES;")
            print("  [PASS] Akses Sah: Izin LOCK TABLES & SELECT dump berhasil.")
            passed_tests += 1
        except Exception as e:
            print(f"  [FAIL] Akses Dump Gagal: {e}")

        total_tests += 1
        try:
            cur.execute("DELETE FROM `anggota` WHERE id = 1;")
            print("  [FAIL] Pelanggaran Keamanan: backup_user diizinkan memodifikasi data!")
        except pymysql.err.OperationalError as e:
            print(f"  [PASS] Penolakan Akses: Modifikasi data ditolak ({e.args[1]}).")
            passed_tests += 1
        conn.close()
    except Exception as e:
        print(f"  [-] Gagal terhubung sebagai backup_user: {e}")

    print("\n" + "=" * 65)
    print(f"[V] HASIL PENGUJIAN: {passed_tests}/{total_tests} Skenario Berhasil Terverifikasi.")
    print("=" * 65)


if __name__ == "__main__":
    run_rbac_verification()