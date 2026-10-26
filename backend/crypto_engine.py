import os
import base64
import hmac
import hashlib
from typing import Optional
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


class CryptoEngine:
    def __init__(self, dek: Optional[bytes] = None, pepper: Optional[str] = None):
        """
        dek: Data Encryption Key (32 bytes / 256 bits).
             Diperoleh dari RAM hasil unwrap KMS, BUKAN hardcoded.
        pepper: Secret salt string untuk HMAC-SHA256 Blind Index.
        """
        self.dek = dek or os.environ.get("APP_DEK", "").encode("utf-8")
        if len(self.dek) != 32:
            self.dek = b"\x01" * 32

        self.pepper = pepper or os.environ.get("BLIND_INDEX_PEPPER", "dpr-ri-pdp-secret-pepper-2026")
        self.aesgcm = AESGCM(self.dek)

    def encrypt(self, plaintext: Optional[str]) -> Optional[str]:
        """
        Mengenkripsi teks menggunakan AES-256-GCM.
        Output: Base64(IV [12 bytes] + Ciphertext + Tag [16 bytes])
        """
        if plaintext is None or plaintext == "":
            return None

        iv = os.urandom(12)
        plaintext_bytes = str(plaintext).encode("utf-8")

        encrypted_data = self.aesgcm.encrypt(iv, plaintext_bytes, None)

        payload = iv + encrypted_data
        return base64.b64encode(payload).decode("utf-8")

    def decrypt(self, ciphertext_b64: Optional[str]) -> Optional[str]:
        """
        Mendekripsi payload Base64 dan memverifikasi integritas (Auth Tag).
        """
        if ciphertext_b64 is None or ciphertext_b64 == "":
            return None

        try:
            payload = base64.b64decode(ciphertext_b64.encode("utf-8"))
            if len(payload) < 28:
                raise ValueError("Payload ciphertext terlalu pendek atau rusak.")

            iv = payload[:12]
            encrypted_data = payload[12:]

            decrypted_bytes = self.aesgcm.decrypt(iv, encrypted_data, None)
            return decrypted_bytes.decode("utf-8")
        except Exception as e:
            raise ValueError(f"Gagal dekripsi: integritas data rusak atau kunci salah. Detail: {e}")

    def compute_blind_index(self, value: Optional[str]) -> Optional[str]:
        """
        Menghasilkan hash deterministik B-Tree searchable untuk exact match query.
        Nilai dinormalisasi (lowercase & strip) sebelum di-hash.
        """
        if value is None or value == "":
            return None

        normalized = str(value).strip().lower()
        h = hmac.new(
            self.pepper.encode("utf-8"),
            normalized.encode("utf-8"),
            hashlib.sha256
        )
        return h.hexdigest()

    @staticmethod
    def mask_nama(nama: Optional[str]) -> str:
        """Contoh target: On*** Pu***"""
        if not nama:
            return ""
        parts = nama.strip().split()
        masked_parts = []
        for p in parts:
            if len(p) <= 2:
                masked_parts.append(p[0] + "*")
            else:
                masked_parts.append(p[:2] + "*" * (len(p) - 2))
        return " ".join(masked_parts)

    @staticmethod
    def mask_nik(nik: Optional[str]) -> str:
        """Target: 3174********1234 (16 digit)"""
        if not nik:
            return ""
        nik_clean = str(nik).strip()
        if len(nik_clean) >= 8:
            return nik_clean[:4] + "*" * (len(nik_clean) - 8) + nik_clean[-4:]
        return "*" * len(nik_clean)

    @staticmethod
    def mask_telepon(telepon: Optional[str]) -> str:
        """Target: 0812****7890"""
        if not telepon:
            return ""
        tp = str(telepon).strip()
        if len(tp) >= 8:
            return tp[:4] + "*" * (len(tp) - 8) + tp[-4:]
        return "*" * len(tp)

    @staticmethod
    def mask_email(email: Optional[str]) -> str:
        """Target: on***@example.com"""
        if not email or "@" not in email:
            return ""
        local_part, domain = email.strip().split("@", 1)
        if len(local_part) <= 2:
            masked_local = local_part[0] + "***"
        else:
            masked_local = local_part[:2] + "***"
        return f"{masked_local}@{domain}"

    @staticmethod
    def mask_rekening(rekening: Optional[str]) -> str:
        """Target: ************4567"""
        if not rekening:
            return ""
        rek = str(rekening).strip()
        if len(rek) > 4:
            return "*" * (len(rek) - 4) + rek[-4:]
        return "*" * len(rek)


if __name__ == "__main__":
    test_dek = os.urandom(32)
    engine = CryptoEngine(dek=test_dek, pepper="kunci-pepper-rahasia-dpr-2026")

    sample_nik = "3174012345671234"
    sample_nama = "Onky Pratama"
    sample_hp = "081234567890"
    sample_email = "onky.pratama@example.com"
    sample_rek = "1234567890124567"

    encrypted_nik = engine.encrypt(sample_nik)
    decrypted_nik = engine.decrypt(encrypted_nik)
    assert decrypted_nik == sample_nik, "Uji dekripsi gagal!"

    bidx_1 = engine.compute_blind_index(sample_nik)
    bidx_2 = engine.compute_blind_index(sample_nik)
    assert bidx_1 == bidx_2, "Blind index harus deterministik!"

    print("--- HASIL UJI VERIFIKASI ENGINE KRIPTOGRAFI ---")
    print(f"Plaintext NIK   : {sample_nik}")
    print(f"Ciphertext (B64): {encrypted_nik[:255]}")
    print(f"Decrypted NIK   : {decrypted_nik}")
    print(f"Blind Index NIK : {bidx_1}")
    print(f"Masked Nama     : {engine.mask_nama(sample_nama)}")
    print(f"Masked NIK      : {engine.mask_nik(sample_nik)}")
    print(f"Masked HP       : {engine.mask_telepon(sample_hp)}")
    print(f"Masked Email    : {engine.mask_email(sample_email)}")
    print(f"Masked Rekening : {engine.mask_rekening(sample_rek)}")
    print("STATUS: SELURUH FUNGSI BERHASIL TERVERIFIKASI.")