import os
import sys
import subprocess
import hashlib
import pymysql
from dotenv import load_dotenv

load_dotenv()

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.crypto_engine import CryptoEngine

BACKUP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backups"))
DB_NAME = os.getenv("DB_NAME", "dpr_pdp_db")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
RESTORE_USER = os.getenv("DB_ROOT_USER", "haga")
RESTORE_PASS = os.getenv("DB_ROOT_PASS", "haga@11002")

BACKUP_KEY = os.getenv("BACKUP_PEPPER", "dpr-backup-pepper-2026").ljust(32, "0")[:32].encode("utf-8")
crypto = CryptoEngine(dek=BACKUP_KEY, pepper="backup-integrity-salt")


def get_latest_backup_file():
    """Mengambil file backup .enc paling mutakhir di direktori backups."""
    if not os.path.exists(BACKUP_DIR):
        return None
    enc_files = [
        os.path.join(BACKUP_DIR, f) for f in os.listdir(BACKUP_DIR)
        if f.startswith(f"backup_{DB_NAME}_") and f.endswith(".sql.enc")
    ]
    if not enc_files:
        return None
    enc_files.sort(key=os.path.getmtime, reverse=True)
    return enc_files[0]


def verify_checksum(enc_filepath: str) -> bool:
    """Verifikasi integritas file backup sebelum didekripsi menggunakan hash SHA-256."""
    sha_filepath = enc_filepath.replace(".enc", ".sha256")
    if not os.path.exists(sha_filepath):
        print(f"[-] Berkas checksum tidak ditemukan: {os.path.basename(sha_filepath)}")
        return False

    with open(sha_filepath, "r", encoding="utf-8") as f:
        expected_hash = f.read().strip()

    with open(enc_filepath, "rb") as f:
        actual_hash = hashlib.sha256(f.read()).hexdigest()

    print(f"[*] Expected Hash : {expected_hash}")
    print(f"[*] Computed Hash : {actual_hash}")

    if expected_hash.lower() == actual_hash.lower():
        print("[+] Integritas Checksum SHA-256: VALID (Berkas asli & tidak rusak).")
        return True
    else:
        print("[-] ALARM KEAMANAN: Checksum tidak cocok! File terindikasi rusak atau dimanipulasi.")
        return False


def verify_database_record_count():
    """Memeriksa jumlah baris data di database setelah proses restore selesai."""
    try:
        conn = pymysql.connect(
            host=DB_HOST,
            port=int(DB_PORT),
            user=RESTORE_USER,
            password=RESTORE_PASS,
            database=DB_NAME,
            cursorclass=pymysql.cursors.DictCursor
        )
        cur = conn.cursor()
        cur.execute("SELECT COUNT(*) AS total FROM `anggota`;")
        count_anggota = cur.fetchone()["total"]

        cur.execute("SELECT COUNT(*) AS total FROM `anggota_sensitif`;")
        count_sensitif = cur.fetchone()["total"]

        conn.close()
        print(f"[+] Verifikasi Data Pasca-Restore:")
        print(f"    - Tabel `anggota`          : {count_anggota} baris")
        print(f"    - Tabel `anggota_sensitif` : {count_sensitif} baris")
        return count_anggota, count_sensitif
    except Exception as e:
        print(f"[-] Gagal melakukan query verifikasi: {e}")
        return 0, 0


def run_restore(backup_file_path: str = None):
    print("=" * 65)
    print("   DPR RI SECURE DATABASE RESTORE ENGINE")
    print("=" * 65)

    target_file = backup_file_path or get_latest_backup_file()
    if not target_file or not os.path.exists(target_file):
        print(f"[-] Berkas cadangan terenkripsi tidak ditemukan di {BACKUP_DIR}.")
        return False

    print(f"Target Restore    : {os.path.basename(target_file)}")
    print(f"Target Database   : {DB_NAME}")
    print(f"Operator Restore  : {RESTORE_USER} (Disaster Recovery Administrator)")

    print("\n[*] Langkah 1: Memeriksa Integritas Hash SHA-256...")
    if not verify_checksum(target_file):
        print("[-] Pemulihan dibatalkan demi keamanan sistem.")
        return False

    print("\n[*] Langkah 2: Mendekripsi Berkas Backup via AES-256-GCM...")
    try:
        with open(target_file, "r", encoding="utf-8") as f:
            encrypted_payload = f.read()

        decrypted_sql = crypto.decrypt(encrypted_payload)
        print("[+] Dekripsi berhasil. Menyiapkan injeksi database...")
    except Exception as e:
        print(f"[-] Gagal mendekripsi berkas backup: {e}")
        return False

    print("\n[*] Langkah 3: Mengimpor Data SQL ke MySQL...")
    restore_cmd = [
        "mysql",
        f"-h{DB_HOST}",
        f"-P{DB_PORT}",
        f"-u{RESTORE_USER}",
        DB_NAME
    ]

    env_safe = os.environ.copy()
    env_safe["MYSQL_PWD"] = RESTORE_PASS

    try:
        proc = subprocess.Popen(
            restore_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            env=env_safe
        )
        out, err = proc.communicate(input=decrypted_sql.encode("utf-8"))

        if proc.returncode != 0:
            print(f"[-] Gagal melakukan injeksi ke MySQL: {err.decode('utf-8', errors='ignore')}")
            return False

        print("[+] Injeksi SQL selesai tanpa error.")
    except Exception as e:
        print(f"[-] Terjadi kesalahan eksekusi perintah mysql: {e}")
        return False

    print("\n[*] Langkah 4: Validasi Integritas Data Basis Data...")
    c_pub, c_sens = verify_database_record_count()

    print("\n" + "=" * 65)
    if c_pub == 734 and c_sens == 734:
        print("[V] PEMULIHAN SUKSES! Seluruh 734 data berhasil dipulihkan secara utuh.")
    else:
        print(f"[!] PEMULIHAN SELESAI DENGAN CATATAN: Jumlah baris data ({c_pub}) perlu diperiksa.")
    print("=" * 65)
    return True


if __name__ == "__main__":
    file_arg = sys.argv[1] if len(sys.argv) > 1 else None
    run_restore(file_arg)