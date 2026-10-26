import os
import json
import base64
import secrets
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from dotenv import load_dotenv

load_dotenv()

KEYRING_PATH = os.path.abspath(os.path.join(os.path.dirname(__file__), "keyring.json"))

RAW_KEK = os.getenv("MASTER_KEK")
if not RAW_KEK:
    RAW_KEK = os.getenv("MASTER_PEPPER", "")
    if not RAW_KEK:
        raise ValueError("FATAL KMS ERROR: MASTER_KEK atau MASTER_PEPPER tidak ditemukan di environment.")

KEK = RAW_KEK.ljust(32, "0")[:32].encode("utf-8")


def _wrap_dek(dek: bytes, kek: bytes) -> str:
    """Membungkus (mengenkripsi) DEK menggunakan KEK via AES-256-GCM."""
    aesgcm = AESGCM(kek)
    nonce = secrets.token_bytes(12)
    ciphertext = aesgcm.encrypt(nonce, dek, None)
    return base64.b64encode(nonce + ciphertext).decode("utf-8")


def _unwrap_dek(wrapped_dek_b64: str, kek: bytes) -> bytes:
    """Membuka bungkus (mendekripsi) DEK menggunakan KEK."""
    raw = base64.b64decode(wrapped_dek_b64)
    nonce = raw[:12]
    ciphertext = raw[12:]
    aesgcm = AESGCM(kek)
    return aesgcm.decrypt(nonce, ciphertext, None)


def _load_keyring() -> dict:
    if not os.path.exists(KEYRING_PATH):
        initial_dek = secrets.token_bytes(32)
        wrapped = _wrap_dek(initial_dek, KEK)
        data = {
            "active_version": 1,
            "keys": {
                "1": {
                    "wrapped_dek": wrapped,
                    "created_at": "2026-01-01T00:00:00Z"
                }
            }
        }
        with open(KEYRING_PATH, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2)
        return data

    with open(KEYRING_PATH, "r", encoding="utf-8") as f:
        return json.load(f)


def get_active_dek() -> tuple[bytes, int]:
    """Mengambil DEK aktif saat ini beserta versi kuncinya."""
    keyring = _load_keyring()
    active_ver = keyring["active_version"]
    wrapped_dek = keyring["keys"][str(active_ver)]["wrapped_dek"]
    return _unwrap_dek(wrapped_dek, KEK), active_ver


def get_dek_by_version(version: int) -> bytes:
    """Mengambil DEK spesifik berdasarkan nomor versinya untuk kebutuhan dekripsi data historis."""
    keyring = _load_keyring()
    key_info = keyring["keys"].get(str(version))
    if not key_info:
        raise ValueError(f"DEK versi {version} tidak ditemukan di KMS keyring.")
    return _unwrap_dek(key_info["wrapped_dek"], KEK)


def rotate_active_dek() -> int:
    """Membuat DEK versi baru, membungkusnya dengan KEK, dan menjadikannya kunci aktif di KMS."""
    keyring = _load_keyring()
    current_ver = keyring["active_version"]
    new_ver = current_ver + 1

    new_dek = secrets.token_bytes(32)
    wrapped = _wrap_dek(new_dek, KEK)

    keyring["keys"][str(new_ver)] = {
        "wrapped_dek": wrapped,
        "created_at": "ROTATED_KEY"
    }
    keyring["active_version"] = new_ver

    with open(KEYRING_PATH, "w", encoding="utf-8") as f:
        json.dump(keyring, f, indent=2)

    return new_ver