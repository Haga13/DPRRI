import sys
import os
from dotenv import load_dotenv

load_dotenv()

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from kms.kms_server import get_active_dek
from backend.database_conn import get_connection
from backend.crypto_engine import CryptoEngine


def run_migration():
    active_dek, key_version = get_active_dek()
    secret_pepper = os.environ.get("MASTER_PEPPER", "dpr-ri-pdp-secret-pepper-2026")
    crypto = CryptoEngine(dek=active_dek, pepper=secret_pepper)
    print(f"[+] Menggunakan DEK dari KMS (Versi: {key_version})")

    try:
        conn_src = get_connection(user_role="root", db_name="dprri")
        cur_src = conn_src.cursor()
        print("[+] Terhubung ke basis data sumber: `dprri`")
    except Exception as e:
        print(f"[-] Gagal terhubung ke basis data `dprri`: {e}")
        return

    try:
        conn_tgt = get_connection(user_role="root", db_name="dpr_pdp_db")
        cur_tgt = conn_tgt.cursor()
        print("[+] Terhubung ke basis data target: `dpr_pdp_db`")
    except Exception as e:
        print(f"[-] Gagal terhubung ke basis data `dpr_pdp_db`: {e}")
        print("    Pastikan schema_secure.sql sudah dieksekusi di database dpr_pdp_db.")
        conn_src.close()
        return

    cur_tgt.execute("DELETE FROM `anggota_sensitif`;")
    cur_tgt.execute("DELETE FROM `anggota`;")
    cur_tgt.execute("ALTER TABLE `anggota` AUTO_INCREMENT = 1;")

    cur_src.execute("SELECT * FROM `anggota`;")
    raw_rows = cur_src.fetchall()
    print(f"[+] Ditemukan {len(raw_rows)} baris data mentah di `dprri.anggota`.")

    success_count = 0
    print("[*] Melakukan enkripsi AES-256-GCM, pembuatan blind index, dan segregasi tabel...")

    for row in raw_rows:
        nama_final = row.get("nama_lengkap") or row.get("nama") or "Tanpa Nama"

        sql_anggota = """
            INSERT INTO `anggota` (
                `nama_lengkap`, `jenis_kelamin`, `tempat_lahir`, `tanggal_lahir`,
                `pekerjaan_terakhir`, `ruangan`, `nama_bank`, `kode_bank`, `nama_kppn`
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
        val_anggota = (
            nama_final,
            row.get("jenis_kelamin"),
            row.get("tempat_lahir"),
            row.get("tanggal_lahir"),
            row.get("pekerjaan_terakhir"),
            row.get("ruangan"),
            row.get("nama_bank"),
            row.get("kode_bank"),
            row.get("nama_kppn")
        )
        cur_tgt.execute(sql_anggota, val_anggota)
        new_id = cur_tgt.lastrowid

        enc_no_ktp = crypto.encrypt(str(row.get("no_ktp", "")))
        enc_npwp = crypto.encrypt(str(row.get("npwp", "")))
        enc_rekening = crypto.encrypt(str(row.get("rekening", "")))
        enc_nama_rekening = crypto.encrypt(str(row.get("nama_rekening", "")))
        enc_nip_kppn = crypto.encrypt(str(row.get("nip_kppn", "")))
        enc_handphone = crypto.encrypt(str(row.get("handphone", "")))
        enc_email = crypto.encrypt(str(row.get("email", "")))
        enc_agama = crypto.encrypt(str(row.get("agama", "")))
        enc_alamat_jkt = crypto.encrypt(str(row.get("alamat_jakarta", "")))
        enc_alamat_daerah = crypto.encrypt(str(row.get("alamat_daerah", "")))

        bidx_ktp = crypto.compute_blind_index(str(row.get("no_ktp", "")))
        bidx_mail = crypto.compute_blind_index(str(row.get("email", "")))

        sql_sensitif = """
            INSERT INTO `anggota_sensitif` (
                `anggota_id`, `no_ktp_enc`, `npwp_enc`, `rekening_enc`, `nama_rekening_enc`,
                `nip_kppn_enc`, `handphone_enc`, `email_enc`, `agama_enc`,
                `alamat_jakarta_enc`, `alamat_daerah_enc`, `bidx_no_ktp`, `bidx_email`, `key_version`
            ) VALUES (%s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s, %s);
        """
        val_sensitif = (
            new_id,
            enc_no_ktp, enc_npwp, enc_rekening, enc_nama_rekening,
            enc_nip_kppn, enc_handphone, enc_email, enc_agama,
            enc_alamat_jkt, enc_alamat_daerah,
            bidx_ktp, bidx_mail,
            key_version
        )
        cur_tgt.execute(sql_sensitif, val_sensitif)
        success_count += 1

    conn_tgt.commit()
    conn_src.close()
    conn_tgt.close()

    print(f"\n[V] MIGRASI SUKSES! Sebanyak {success_count} baris data berhasil dipindahkan dan diamankan ke `dpr_pdp_db`.")


if __name__ == "__main__":
    run_migration()