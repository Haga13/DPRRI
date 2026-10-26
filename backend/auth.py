import os
import sys
import time
import base64
import hashlib
import hmac
import json
from datetime import datetime, timedelta
from typing import Optional
from dotenv import load_dotenv
import hashlib
from datetime import datetime
from backend.database_conn import get_connection
load_dotenv()

JWT_SECRET = os.getenv("JWT_SECRET", os.getenv("MASTER_PEPPER", "dpr-jwt-secret-key-2026"))
JWT_ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

try:
    from argon2 import PasswordHasher
    from argon2.exceptions import VerifyMismatchError
    ph = PasswordHasher(time_cost=3, memory_cost=65536, parallelism=4, hash_len=32)
    USE_ARGON2 = True
except ImportError:
    USE_ARGON2 = False




def get_token_hash(token: str) -> str:
    """Menghasilkan SHA-256 hash dari token untuk identifikasi unik yang hemat memori."""
    return hashlib.sha256(token.encode("utf-8")).hexdigest()

def revoke_token(token: str, user_id: str, exp_timestamp: int) -> bool:
    """Menyimpan hash token ke tabel revoked_tokens sampai masa berlakunya habis."""
    token_hash = get_token_hash(token)
    expires_at = datetime.fromtimestamp(exp_timestamp)
    try:
        conn = get_connection(user_role="app_user", db_name="dpr_pdp_db")
        cursor = conn.cursor()
        sql = """
            INSERT INTO revoked_tokens (token_hash, user_id, expires_at)
            VALUES (%s, %s, %s)
            ON DUPLICATE KEY UPDATE revoked_at = CURRENT_TIMESTAMP;
        """
        cursor.execute(sql, (token_hash, user_id, expires_at))
        conn.commit()
        conn.close()
        return True
    except Exception as e:
        print(f"[-] Gagal mencabut token: {e}")
        return False

def is_token_revoked(token: str) -> bool:
    """Memeriksa apakah token sudah masuk daftar blokir (revoked)."""
    token_hash = get_token_hash(token)
    try:
        conn = get_connection(user_role="app_user", db_name="dpr_pdp_db")
        cursor = conn.cursor()
        cursor.execute("SELECT id FROM revoked_tokens WHERE token_hash = %s LIMIT 1;", (token_hash,))
        row = cursor.fetchone()
        conn.close()
        return row is not None
    except Exception as e:
        print(f"[-] Gagal memeriksa status pencabutan token: {e}")
        return False
def hash_password(plain_password: str) -> str:
    """Menghasilkan hash adaptif satu arah (irreversible)."""
    if USE_ARGON2:
        return ph.hash(plain_password)
    
    salt = os.urandom(16)
    key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100000)
    return f"pbkdf2:sha256:100000${base64.b64encode(salt).decode('utf-8')}${base64.b64encode(key).decode('utf-8')}"


def verify_password(plain_password: str, hashed_password: str) -> bool:
    """Verifikasi kata sandi dengan hash tanpa dekripsi."""
    if USE_ARGON2 and hashed_password.startswith("$argon2"):
        try:
            return ph.verify(hashed_password, plain_password)
        except VerifyMismatchError:
            return False
    elif hashed_password.startswith("pbkdf2:"):
        try:
            parts = hashed_password.split("$")
            salt = base64.b64decode(parts[1])
            key = base64.b64decode(parts[2])
            new_key = hashlib.pbkdf2_hmac("sha256", plain_password.encode("utf-8"), salt, 100000)
            return hmac.compare_digest(key, new_key)
        except Exception:
            return False
    return False


def _b64url_encode(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("utf-8").rstrip("=")


def _b64url_decode(data: str) -> bytes:
    padding = "=" * (4 - (len(data) % 4)) if len(data) % 4 != 0 else ""
    return base64.urlsafe_b64decode(data + padding)


def create_access_token(data: dict, expires_delta: Optional[timedelta] = None) -> str:
    to_encode = data.copy()
    
    now_ts = int(time.time())
    expire_seconds = int(expires_delta.total_seconds()) if expires_delta else (ACCESS_TOKEN_EXPIRE_MINUTES * 60)
    to_encode.update({
        "iat": now_ts,
        "exp": now_ts + expire_seconds,
        "jti": os.urandom(8).hex()
    })

    header = {"alg": JWT_ALGORITHM, "typ": "JWT"}
    header_b64 = _b64url_encode(json.dumps(header, separators=(',', ':')).encode("utf-8"))
    payload_b64 = _b64url_encode(json.dumps(to_encode, separators=(',', ':')).encode("utf-8"))

    signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
    signature = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()
    sig_b64 = _b64url_encode(signature)

    return f"{header_b64}.{payload_b64}.{sig_b64}"


def decode_access_token(token: str) -> Optional[dict]:
    """Mendekode dan memverifikasi token JWT."""
    try:
        parts = token.split(".")
        if len(parts) != 3:
            return None

        header_b64, payload_b64, sig_b64 = parts
        signing_input = f"{header_b64}.{payload_b64}".encode("utf-8")
        expected_sig = hmac.new(JWT_SECRET.encode("utf-8"), signing_input, hashlib.sha256).digest()

        if not hmac.compare_digest(expected_sig, _b64url_decode(sig_b64)):
            return None

        payload = json.loads(_b64url_decode(payload_b64).decode("utf-8"))
        
        current_time = int(time.time())
        if payload.get("exp", 0) < current_time:
            return None

        return payload
    except Exception:
        return None