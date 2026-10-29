#!/usr/bin/env python3
"""
================================================================================
   DPR RI PDP SYSTEM - SYNTHETIC DATA POPULATION SUITE (SCALING BENCHMARK)
================================================================================
Skrip untuk mengisi data sintetis anggota DPR RI secara masif ke dua database:
1. `dprri` (Format Plaintext - Kondisi Sebelum Dilindungi)
2. `dpr_pdp_db` (Format Terenkripsi AES-256-GCM + HMAC Blind Index - Sesudah Dilindungi)

Fitur:
- Parameter `--count <N>` (Default: 2000 rekaman)
- Parameter `--cleanup` (Menghapus seluruh data sintetis & merestorasi ke 734 data asli)
- Menjaga integritas relasi foreign key dan KMS Keyring
================================================================================
"""

import os
import sys
import random
import string
import argparse
import pymysql
import pymysql.cursors
from datetime import date, timedelta
from dotenv import load_dotenv

# Path setup
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))
load_dotenv()

from backend.crypto_engine import CryptoEngine
from kms.kms_server import get_active_dek

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DB_USER = os.getenv("DB_ROOT_USER", "haga")
DB_PASS = os.getenv("DB_ROOT_PASS", "haga@11002")

# Generator Kosa Kata Realistis Indonesia
NAMA_DEPAN_L = ["Ahmad", "Budi", "Dedi", "Eko", "Fajar", "Hadi", "Hendra", "Irfan", "Joko", "Muhammad", "Prabowo", "Rian", "Surya", "Wahyu", "Zul"]
NAMA_DEPAN_P = ["Annisa", "Citra", "Dewi", "Fitri", "Gita", "Indah", "Kartika", "Lestari", "Maya", "Nurul", "Putri", "Rina", "Siti", "Tri", "Yuni"]
NAMA_BELAKANG = ["Santoso", "Wijaya", "Kusuma", "Pratama", "Hidayat", "Saputra", "Wibowo", "Nugroho", "Setiawan", "Utomo", "Siregar", "Nasution", "Lubis", "Hutapea", "Simanjuntak", "Pasaribu"]
KOTA = ["Jakarta", "Surabaya", "Bandung", "Medan", "Semarang", "Makassar", "Palembang", "Yogyakarta", "Denpasar", "Padang", "Banjarmasin", "Manado"]
AGAMA_LIST = ["Islam", "Kristen Protestan", "Katolik", "Hindu", "Buddha", "Khonghucu"]
BANK_LIST = [("Bank Mandiri", "008"), ("Bank BRI", "002"), ("Bank BNI", "009"), ("Bank BCA", "014"), ("Bank BSI", "451")]
RUANGAN_LIST = ["F-PDI-P 01", "F-Golkar 02", "F-Gerindra 03", "F-NasDem 04", "F-PKB 05", "F-PKS 06", "F-PAN 07", "F-Demokrat 08"]


def generate_random_date(start_year=1960, end_year=1995):
    start_date = date(start_year, 1, 1)
    end_date = date(end_year, 12, 31)
    days_between = (end_date - start_date).days
    random_days = random.randint(0, days_between)
    return (start_date + timedelta(days=random_days)).isoformat()


def run_cleanup():
    print("=" * 80)
    print("      DPR RI PDP SYSTEM - CLEANUP DATA SINTETIS")
    print("=" * 80)
    conn = pymysql.connect(host=DB_HOST, port=DB_PORT, user=DB_USER, password=DB_PASS)
    cur = conn.cursor()

    # 1. Hapus dari dprri
    cur.execute("DELETE FROM dprri.anggota WHERE pengguna = 'SYNTHETIC_BENCHMARK';")
    count_plain = cur.rowcount
    print(f"[+] Berhasil menghapus {count_plain} rekaman sintetis dari `dprri.anggota`.")

    # 2. Hapus dari dpr_pdp_db
    cur.execute("USE dpr_pdp_db;")
    cur.execute("DELETE s FROM anggota_sensitif s JOIN anggota a ON s.anggota_id = a.id WHERE a.retention_status = 'synthetic';")
    count_sen = cur.rowcount
    cur.execute("DELETE FROM anggota WHERE retention_status = 'synthetic';")
    count_pub = cur.rowcount
    print(f"[+] Berhasil menghapus {count_pub} rekaman publik & {count_sen} rekaman sensitif dari `dpr_pdp_db`.")

    conn.commit()
    conn.close()
    print("[V] Pembersihan selesai. Database kembali ke data master asli.")
    print("[V] Pembersihan selesai. Database kembali ke data master asli.")


def run_seed(total_count: int):
    print("=" * 80)
    print(f"      DPR RI PDP SYSTEM - SEEDING {total_count} DATA SINTETIS")
    print("          Injeksi Sinkron: `dprri` & `dpr_pdp_db`")
    print("=" * 80)

    # Inisialisasi Kriptografi
    active_dek, key_version = get_active_dek()
    secret_pepper = os.environ.get("MASTER_PEPPER", "dpr-ri-pdp-secret-pepper-2026")
    crypto = CryptoEngine(dek=active_dek, pepper=secret_pepper)
    print(f"[*] Engine Kriptografi: DEK Versi {key_version}")

    conn = pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=DB_USER,
        password=DB_PASS,
        cursorclass=pymysql.cursors.DictCursor
    )
    cur = conn.cursor()

    # Hitung jumlah awal
    cur.execute("SELECT COUNT(*) AS total FROM dprri.anggota;")
    initial_plain = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) AS total FROM dpr_pdp_db.anggota;")
    initial_prot = cur.fetchone()["total"]

    print(f"[*] Jumlah Awal Data `dprri`       : {initial_plain} baris")
    print(f"[*] Jumlah Awal Data `dpr_pdp_db`  : {initial_prot} baris\n")
    print(f"[*] Memulai pembuatan dan enkripsi {total_count} data sintetis...")

    # Batch insertion loop
    batch_size = 200
    current_idx = 1

    for batch_start in range(0, total_count, batch_size):
        current_batch_count = min(batch_size, total_count - batch_start)
        
        # 1. Generate Batch Data di Memori
        batch_records = []
        for _ in range(current_batch_count):
            gender = random.choice(["L", "P"])
            nama_depan = random.choice(NAMA_DEPAN_L if gender == "L" else NAMA_DEPAN_P)
            nama_belakang = random.choice(NAMA_BELAKANG)
            gelar_depan = random.choice(["Dr. ", "H. ", "Hj. ", "Ir. ", "Drs. ", ""])
            gelar_belakang = random.choice([", S.H., M.H.", ", S.E., M.M.", ", S.T.", ", M.Si.", ", Ph.D.", ""])
            nama_lengkap = f"{gelar_depan}{nama_depan} {nama_belakang}{gelar_belakang}".strip()
            
            nik = f"317{random.randint(1000000000000, 9999999999999)}"[:16]
            npwp = f"{random.randint(10,99)}.{random.randint(100,999)}.{random.randint(100,999)}.{random.randint(1,9)}-{random.randint(100,999)}.000"
            bank_name, bank_code = random.choice(BANK_LIST)
            rekening = f"{random.randint(1000000000, 9999999999)}"
            email = f"{nama_depan.lower()}.{nama_belakang.lower()}{random.randint(10,999)}@dpr.go.id"
            hp = f"0812{random.randint(10000000, 99999999)}"
            tempat_lhr = random.choice(KOTA)
            tgl_lhr = generate_random_date()
            alamat = f"Jl. Gatot Subroto No. {random.randint(1, 500)}, Komplek Parlemen, {tempat_lhr}"
            agama = random.choice(AGAMA_LIST)
            ruangan = random.choice(RUANGAN_LIST)
            kppn_name = f"KPPN {tempat_lhr}"
            nip_kppn = f"1980{random.randint(100000000000, 999999999999)}"

            batch_records.append({
                "nama_lengkap": nama_lengkap,
                "nama_depan": nama_depan,
                "nama_belakang": nama_belakang,
                "jenis_kelamin": gender,
                "tempat_lahir": tempat_lhr,
                "tanggal_lahir": tgl_lhr,
                "no_ktp": nik,
                "npwp": npwp,
                "rekening": rekening,
                "nama_rekening": nama_lengkap,
                "nama_bank": bank_name,
                "kode_bank": bank_code,
                "email": email,
                "handphone": hp,
                "alamat": alamat,
                "agama": agama,
                "ruangan": ruangan,
                "nama_kppn": kppn_name,
                "nip_kppn": nip_kppn
            })

        # 2. Insert ke `dprri.anggota` (Plaintext)
        sql_plain = """
            INSERT INTO dprri.anggota (
                nama, nama_lengkap, nama_tanpa_gelar, jenis_kelamin, tempat_lahir, tanggal_lahir,
                no_ktp, rekening, nama_rekening, npwp, nama_bank, kode_bank,
                email, handphone, alamat_jakarta, agama, ruangan, nama_kppn, nip_kppn, pengguna
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, 'SYNTHETIC_BENCHMARK');
        """
        vals_plain = [
            (
                r["nama_lengkap"], r["nama_lengkap"], f"{r['nama_depan']} {r['nama_belakang']}", r["jenis_kelamin"], r["tempat_lahir"], r["tanggal_lahir"],
                r["no_ktp"], r["rekening"], r["nama_rekening"], r["npwp"], r["nama_bank"], r["kode_bank"],
                r["email"], r["handphone"], r["alamat"], r["agama"], r["ruangan"], r["nama_kppn"], r["nip_kppn"]
            )
            for r in batch_records
        ]
        cur.executemany(sql_plain, vals_plain)

        # 3. Insert ke `dpr_pdp_db` (Terproteksi: Publik + Sensitif AES-256-GCM + Blind Index)
        for r in batch_records:
            # A. Insert Publik
            sql_pub = """
                INSERT INTO dpr_pdp_db.anggota (
                    nama_lengkap, jenis_kelamin, tempat_lahir, tanggal_lahir,
                    ruangan, nama_bank, kode_bank, nama_kppn, retention_status
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, 'synthetic');
            """
            cur.execute(sql_pub, (
                r["nama_lengkap"], r["jenis_kelamin"], r["tempat_lahir"], r["tanggal_lahir"],
                r["ruangan"], r["nama_bank"], r["kode_bank"], r["nama_kppn"]
            ))
            new_id = cur.lastrowid

            # B. Enkripsi dan Hitung Blind Index
            enc_ktp = crypto.encrypt(r["no_ktp"])
            enc_npwp = crypto.encrypt(r["npwp"])
            enc_rek = crypto.encrypt(r["rekening"])
            enc_nm_rek = crypto.encrypt(r["nama_rekening"])
            enc_nip_kppn = crypto.encrypt(r["nip_kppn"])
            enc_hp = crypto.encrypt(r["handphone"])
            enc_mail = crypto.encrypt(r["email"])
            enc_agama = crypto.encrypt(r["agama"])
            enc_alm = crypto.encrypt(r["alamat"])

            bidx_ktp = crypto.compute_blind_index(r["no_ktp"])
            bidx_mail = crypto.compute_blind_index(r["email"])

            sql_sen = """
                INSERT INTO dpr_pdp_db.anggota_sensitif (
                    anggota_id, no_ktp_enc, npwp_enc, rekening_enc, nama_rekening_enc,
                    nip_kppn_enc, handphone_enc, email_enc, agama_enc, alamat_jakarta_enc,
                    bidx_no_ktp, bidx_email, key_version
                ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
            """
            cur.execute(sql_sen, (
                new_id, enc_ktp, enc_npwp, enc_rek, enc_nm_rek,
                enc_nip_kppn, enc_hp, enc_mail, enc_agama, enc_alm,
                bidx_ktp, bidx_mail, key_version
            ))

        conn.commit()
        print(f"    [+] Progres: {min(batch_start + batch_size, total_count)} / {total_count} rekaman selesai diproses...")

    # Verifikasi Akhir
    cur.execute("SELECT COUNT(*) AS total FROM dprri.anggota;")
    final_plain = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) AS total FROM dpr_pdp_db.anggota;")
    final_prot = cur.fetchone()["total"]
    cur.execute("SELECT COUNT(*) AS total FROM dpr_pdp_db.anggota_sensitif;")
    final_sen = cur.fetchone()["total"]

    conn.close()

    print("\n" + "=" * 80)
    print("      HASIL AKHIR SEEDING DATA SINTETIS")
    print("=" * 80)
    print(f"[✓] Database `dprri` (Plaintext)        : {final_plain} baris (+{final_plain - initial_plain})")
    print(f"[✓] Database `dpr_pdp_db.anggota`      : {final_prot} baris (+{final_prot - initial_prot})")
    print(f"[✓] Database `dpr_pdp_db.sensitif`     : {final_sen} baris (+{final_sen - initial_prot})")
    print("=" * 80)
    print("[TIP] Untuk menghapus kembali 2000 data ini kapan saja, jalankan:")
    print("      python3 database/seed_synthetic_data.py --cleanup")
    print("=" * 80)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Seed synthetic DPR RI members to dprri & dpr_pdp_db")
    parser.add_argument("--count", type=int, default=2000, help="Jumlah data sintetis yang dibangkitkan (Default: 2000)")
    parser.add_argument("--cleanup", action="store_true", help="Hapus data sintetis dan kembalikan ke data asli")

    args = parser.parse_args()

    if args.cleanup:
        run_cleanup()
    else:
        run_seed(args.count)
