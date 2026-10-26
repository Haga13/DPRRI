import os
import sys
import pymysql
from dotenv import load_dotenv

load_dotenv()

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.crypto_engine import CryptoEngine
from kms.kms_server import rotate_active_dek, get_dek_by_version, get_active_dek

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_NAME = os.getenv("DB_NAME", "dpr_pdp_db")
SECRET_PEPPER = os.getenv("MASTER_PEPPER", "dpr-ri-pdp-secret-pepper-2026")

SENSITIVE_FIELDS = [
    "no_ktp_enc",
    "npwp_enc",
    "rekening_enc",
    "nama_rekening_enc",
    "nip_kppn_enc",
    "handphone_enc",
    "email_enc",
    "agama_enc",
    "alamat_jakarta_enc",
    "alamat_daerah_enc"
]


def execute_key_rotation(batch_size: int = 50):
    print("=" * 65)
    print("   DPR RI KMS - ZERO-DOWNTIME KEY ROTATION ENGINE")
    print("=" * 65)

    conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=os.getenv("DB_ROOT_USER", "haga"),
        password=os.getenv("DB_ROOT_PASS", "haga@11002"),
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )
    cursor = conn.cursor()

    _, active_version = get_active_dek()

    cursor.execute(
        "SELECT COUNT(*) AS total FROM `anggota_sensitif` WHERE `key_version` < %s;",
        (active_version,)
    )
    pending_records = cursor.fetchone()["total"]

    if pending_records > 0:
        target_version = active_version
        print(f"[*] Melanjutkan migrasi tertunda ke DEK aktif : Versi {target_version}")
    else:
        target_version = rotate_active_dek()
        print(f"[+] DEK Baru Berhasil Diterbitkan di KMS    : Versi {target_version}")

    target_dek = get_dek_by_version(target_version)
    target_crypto = CryptoEngine(dek=target_dek, pepper=SECRET_PEPPER)
    crypto_cache = {target_version: target_crypto}

    cursor.execute(
        "SELECT COUNT(*) AS total FROM `anggota_sensitif` WHERE `key_version` < %s;",
        (target_version,)
    )
    total_records = cursor.fetchone()["total"]
    print(f"[*] Ditemukan {total_records} baris data yang akan dimigrasikan ke Versi {target_version}...")

    if total_records == 0:
        print("[V] Seluruh data sudah menggunakan versi terbaru.")
        conn.close()
        return

    processed = 0

    while True:
        cursor.execute(
            f"SELECT anggota_id, key_version, {', '.join(SENSITIVE_FIELDS)} "
            f"FROM `anggota_sensitif` WHERE `key_version` < %s LIMIT %s;",
            (target_version, batch_size)
        )
        rows = cursor.fetchall()
        if not rows:
            break

        for row in rows:
            target_anggota_id = row["anggota_id"]
            row_version = row["key_version"]

            if row_version not in crypto_cache:
                old_dek = get_dek_by_version(row_version)
                crypto_cache[row_version] = CryptoEngine(dek=old_dek, pepper=SECRET_PEPPER)

            source_crypto = crypto_cache[row_version]
            updated_fields = {}

            for col in SENSITIVE_FIELDS:
                ciphertext_old = row[col]
                if ciphertext_old:
                    plaintext = source_crypto.decrypt(ciphertext_old)
                    ciphertext_new = target_crypto.encrypt(plaintext)
                    updated_fields[col] = ciphertext_new
                else:
                    updated_fields[col] = None

            set_clause = ", ".join([f"`{col}` = %s" for col in updated_fields.keys()])
            set_clause += ", `key_version` = %s"
            values = list(updated_fields.values()) + [target_version, target_anggota_id]

            update_sql = f"UPDATE `anggota_sensitif` SET {set_clause} WHERE `anggota_id` = %s;"
            cursor.execute(update_sql, tuple(values))

        conn.commit()
        processed += len(rows)
        print(f"  -> Berhasil me-re-enkripsi {processed}/{total_records} baris...")

    conn.close()
    print("\n" + "=" * 65)
    print(f"[V] ROTASI KUNCI SUKSES: Seluruh {processed} baris data bermigrasi ke Versi {target_version}.")
    print("=" * 65)


if __name__ == "__main__":
    execute_key_rotation()