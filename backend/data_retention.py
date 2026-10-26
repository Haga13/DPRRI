import os
import base64
import pymysql
from backend.database_conn import get_connection

def secure_shred_record(anggota_id: int) -> bool:
    """
    Melakukan cryptographic shredding pada rekaman data pribadi spesifik:
    1. Timpa data cipher dan blind index dengan bytes acak (zeroization/noise).
    2. Hapus baris dari tabel anggota_sensitif.
    3. Update status retensi pada tabel anggota menjadi 'purged'.
    """
    conn = get_connection(user_role="root", db_name="dpr_pdp_db")
    cursor = conn.cursor()

    try:
        cursor.execute("SELECT id FROM anggota WHERE id = %s;", (anggota_id,))
        if not cursor.fetchone():
            conn.close()
            return False

        dummy_noise = base64.b64encode(os.urandom(64)).decode("utf-8")
        dummy_bidx = base64.b64encode(os.urandom(32)).decode("utf-8")

        shred_sql = """
            UPDATE anggota_sensitif
            SET no_ktp_enc = %s,
                email_enc = %s,
                handphone_enc = %s,
                rekening_enc = %s,
                nama_rekening_enc = %s,
                npwp_enc = %s,
                nip_kppn_enc = %s,
                agama_enc = %s,
                alamat_jakarta_enc = %s,
                alamat_daerah_enc = %s,
                bidx_no_ktp = %s,
                bidx_email = %s
            WHERE anggota_id = %s;
        """
        cursor.execute(shred_sql, (
            dummy_noise, dummy_noise, dummy_noise, dummy_noise,
            dummy_noise, dummy_noise, dummy_noise, dummy_noise,
            dummy_noise, dummy_noise, dummy_bidx, dummy_bidx,
            anggota_id
        ))

        cursor.execute("DELETE FROM anggota_sensitif WHERE anggota_id = %s;", (anggota_id,))

        cursor.execute(
            "UPDATE anggota SET retention_status = 'purged' WHERE id = %s;",
            (anggota_id,)
        )

        conn.commit()
        conn.close()
        return True
    except Exception as e:
        conn.rollback()
        conn.close()
        print(f"[-] Gagal menjalankan shredding data: {e}")
        return False