import os
import sys
import time
import subprocess
import hashlib
from datetime import datetime
from dotenv import load_dotenv

load_dotenv()

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
from backend.crypto_engine import CryptoEngine

BACKUP_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "backups"))
RETENTION_DAYS = 30
DB_NAME = os.getenv("DB_NAME", "dpr_pdp_db")
DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = os.getenv("DB_PORT", "3306")
BACKUP_USER = "backup_user"
BACKUP_PASS = os.getenv("DB_BACKUP_PASS", "Backup_P@ssw0rd_2026!")

BACKUP_KEY = os.getenv("BACKUP_PEPPER", "dpr-backup-pepper-2026").ljust(32, "0")[:32].encode("utf-8")
crypto = CryptoEngine(dek=BACKUP_KEY, pepper="backup-integrity-salt")


def secure_shred_file(filepath: str, passes: int = 3):
    """
    Menghapus berkas secara aman dengan teknik overwriting (shredding)
    agar data tidak dapat dipulihkan melalui tool forensik disk.
    """
    if not os.path.exists(filepath):
        return
    try:
        file_size = os.path.getsize(filepath)
        with open(filepath, "ba+", buffering=0) as f:
            for _ in range(passes):
                f.seek(0)
                f.write(os.urandom(file_size))
                f.flush()
                os.fsync(f.fileno())
        os.remove(filepath)
        print(f"[+] Berkas kadaluwarsa dimusnahkan secara aman (shredded): {os.path.basename(filepath)}")
    except Exception as e:
        print(f"[-] Gagal melakukan secure shred pada {filepath}: {e}")
        if os.path.exists(filepath):
            os.remove(filepath)


def enforce_retention_policy(backup_dir: str, max_days: int = RETENTION_DAYS):
    """Menghapus berkas cadangan dan checksum yang melebihi batas waktu retensi."""
    now = time.time()
    cutoff_time = now - (max_days * 86400)
    print(f"[*] Menjalankan audit retensi backup (Batas simpan: {max_days} hari)...")

    for fname in os.listdir(backup_dir):
        fpath = os.path.join(backup_dir, fname)
        if (fname.endswith(".enc") or fname.endswith(".sha256")) and os.path.isfile(fpath):
            file_mtime = os.path.getmtime(fpath)
            if file_mtime < cutoff_time:
                secure_shred_file(fpath)


def run_backup():
    os.makedirs(BACKUP_DIR, exist_ok=True)
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    target_enc_file = os.path.join(BACKUP_DIR, f"backup_{DB_NAME}_{timestamp}.sql.enc")
    target_sha_file = target_enc_file.replace(".enc", ".sha256")

    print("=" * 60)
    print("   DPR RI SECURE DATABASE BACKUP ENGINE")
    print("=" * 60)
    print(f"Database Target : {DB_NAME}")
    print(f"Operator DB     : {BACKUP_USER} (Least Privilege)")
    print(f"Enkripsi File   : AES-256-GCM + Checksum SHA-256")

    dump_cmd = [
        "mysqldump",
        f"-h{DB_HOST}",
        f"-P{DB_PORT}",
        f"-u{BACKUP_USER}",
        "--single-transaction",
        "--quick",
        DB_NAME
    ]

    env_safe = os.environ.copy()
    env_safe["MYSQL_PWD"] = BACKUP_PASS

    try:
        proc = subprocess.Popen(dump_cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, env=env_safe)
        raw_sql_data, err_data = proc.communicate()

        if proc.returncode != 0:
            print(f"[-] mysqldump gagal dieksekusi: {err_data.decode('utf-8', errors='ignore')}")
            return False

        ciphertext_b64 = crypto.encrypt(raw_sql_data.decode("utf-8", errors="ignore"))

        with open(target_enc_file, "w", encoding="utf-8") as f:
            f.write(ciphertext_b64)

        with open(target_enc_file, "rb") as f:
            file_hash = hashlib.sha256(f.read()).hexdigest()

        with open(target_sha_file, "w", encoding="utf-8") as f:
            f.write(file_hash)

        print(f"[+] Berkas dump berhasil diamankan : {os.path.basename(target_enc_file)}")
        print(f"[+] Checksum SHA-256 integritas    : {file_hash}")

        enforce_retention_policy(BACKUP_DIR, RETENTION_DAYS)

        print("=" * 60)
        print("[V] PROSES PENCADANGAN SELESAI & AMAN")
        print("=" * 60)
        return True

    except Exception as e:
        print(f"[-] Terjadi kesalahan saat proses backup: {e}")
        return False


if __name__ == "__main__":
    run_backup()