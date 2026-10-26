import sys
import os
import time
from fastapi.responses import FileResponse
from typing import List, Optional
from pydantic import BaseModel
from fastapi import FastAPI, HTTPException, Request, Depends, status
from fastapi.responses import JSONResponse
from fastapi.middleware.cors import CORSMiddleware
from fastapi.security import HTTPBearer, HTTPAuthorizationCredentials
from dotenv import load_dotenv
from backend.data_retention import secure_shred_record
from backend.rate_limiter import rate_limit_login, rate_limit_search, reset_all_limiters


load_dotenv()

sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.database_conn import get_connection
from backend.crypto_engine import CryptoEngine
from kms.kms_server import get_active_dek
from backend.auth import (
    verify_password,
    create_access_token,
    decode_access_token,
    is_token_revoked,
    revoke_token
)
from backend.models_dto import (
    AnggotaPublicResponse,
    AnggotaMaskedResponse,
    AnggotaFullSensitiveResponse,
    SearchByNikRequest,
    AuditLogResponse
)

app = FastAPI(
    title="DPR RI Secure Data Ecosystem API",
    version="1.0.0",
    description="Sistem Proteksi Data Pribadi Anggota DPR RI berbasis UU PDP No. 27 Tahun 2022"
)

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

MASTER_DEK, KEY_VERSION = get_active_dek()
SECRET_PEPPER = os.environ.get("MASTER_PEPPER", "dpr-ri-pdp-secret-pepper-2026")
crypto = CryptoEngine(dek=MASTER_DEK, pepper=SECRET_PEPPER)

security = HTTPBearer()


def get_current_user(credentials: HTTPAuthorizationCredentials = Depends(security)) -> dict:
    token = credentials.credentials
    
    if is_token_revoked(token):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token telah dicabut (sesi telah berakhir). Silakan login kembali.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    payload = decode_access_token(token)
    if not payload:
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Token autentikasi tidak valid atau sudah kedaluwarsa.",
            headers={"WWW-Authenticate": "Bearer"},
        )
    
    payload["raw_token"] = token
    return payload


def require_role(allowed_roles: List[str]):
    """Memeriksa hak akses (RBAC) berdasarkan klaim peran di dalam token JWT."""
    def role_checker(current_user: dict = Depends(get_current_user)):
        user_role = current_user.get("role")
        if user_role not in allowed_roles:
            raise HTTPException(
                status_code=status.HTTP_403_FORBIDDEN,
                detail=f"Akses ditolak: Peran '{user_role}' tidak memiliki izin mengakses endpoint ini."
            )
        return current_user
    return role_checker


def mask_nama(nama: str) -> str:
    if not nama:
        return ""
    words = nama.strip().split()
    masked_words = []
    for w in words:
        if len(w) <= 2:
            masked_words.append(w[:2] + "***")
        else:
            masked_words.append(w[:2] + "*" * max(3, len(w) - 2))
    return " ".join(masked_words)
@app.get("/demo", tags=["Demo UI"], include_in_schema=False)
def serve_demo_ui():
    return FileResponse("frontend/index.html")

@app.get("/api/v1/demo/compare/{anggota_id}", tags=["Demo UI"])
def get_security_comparison(anggota_id: int):
    old_row = None
    try:
        conn_old = get_connection(user_role="root", db_name="dprri")
        cur_old = conn_old.cursor()
        cur_old.execute("SELECT * FROM `anggota` WHERE id = %s;", (anggota_id,))
        old_row = cur_old.fetchone()
        conn_old.close()
    except Exception as e:
        print(f"[-] Catatan: Database lama `dprri` tidak dapat diakses ({e}), menggunakan fallback.")

    conn_new = get_connection(user_role="app_user", db_name="dpr_pdp_db")
    cursor_new = conn_new.cursor()
    cursor_new.execute("""
        SELECT a.id, a.nama_lengkap, a.nama_bank,
               s.no_ktp_enc, s.rekening_enc, s.npwp_enc, s.bidx_no_ktp, s.key_version
        FROM `anggota` a
        LEFT JOIN `anggota_sensitif` s ON a.id = s.anggota_id
        WHERE a.id = %s;
    """, (anggota_id,))
    row_new = cursor_new.fetchone()
    conn_new.close()

    if not row_new:
        raise HTTPException(status_code=404, detail="Data anggota tidak ditemukan.")

    if not row_new.get("no_ktp_enc"):
        return {
            "anggota_id": anggota_id,
            "status": "purged",
            "message": "Data sensitif anggota ini telah dimusnahkan secara permanen (Right to be Forgotten)."
        }

    plain_nik = crypto.decrypt(row_new["no_ktp_enc"])
    plain_rek = crypto.decrypt(row_new["rekening_enc"]) if row_new.get("rekening_enc") else "-"
    plain_npwp = crypto.decrypt(row_new["npwp_enc"]) if row_new.get("npwp_enc") else "-"

    raw_nik_before = old_row.get("no_ktp") if old_row else plain_nik
    raw_rek_before = old_row.get("rekening") if old_row else plain_rek
    raw_npwp_before = old_row.get("npwp") if old_row else plain_npwp

    return {
        "anggota_id": anggota_id,
        "nama_publik": row_new["nama_lengkap"],
        "before": {
            "mode": "DATABASE LAMA (dprri)",
            "arsitektur_db": "1 Tabel Monolitik (dprri.anggota) - 32 kolom campur aduk",
            "nama_tampil": old_row.get("nama_lengkap", row_new["nama_lengkap"]) if old_row else row_new["nama_lengkap"],
            "nik": raw_nik_before,
            "rekening": raw_rek_before,
            "npwp": raw_npwp_before,
            "db_storage": f"Plaintext ({raw_nik_before}) mentah di disk MySQL tabel `dprri.anggota`",
            "search_method": f"SELECT * FROM `dprri`.`anggota` WHERE no_ktp = '{raw_nik_before}' (Terekspos di log SQL)",
            "session_security": "Stateless (Token tetap aktif setelah logout - rentan replay attack)",
            "audit_trail": "❌ Tidak Ada (Zero Traceability di database lama)",
            "pdp_status": "❌ NON-COMPLIANT (Pelanggaran UU PDP No. 27/2022)"
        },
        "after": {
            "mode": "DATABASE BARU (dpr_pdp_db)",
            "arsitektur_db": "Tersegregasi: dpr_pdp_db.anggota (Publik) + dpr_pdp_db.anggota_sensitif (Terenkripsi ALE)",
            "nama_tampil": mask_nama(row_new["nama_lengkap"]),
            "nik": crypto.mask_nik(plain_nik),
            "rekening": crypto.mask_rekening(plain_rek),
            "npwp": crypto.mask_nik(plain_npwp),
            "db_storage": f"AES-256-GCM Ciphertext ({row_new['no_ktp_enc'][:30]}...) [KMS v{row_new.get('key_version', 2)}]",
            "search_method": f"HMAC-SHA256 Blind Index ({row_new['bidx_no_ktp'][:24]}...)",
            "session_security": "Stateful Blacklist (Token dicabut seketika pasca logout - 401)",
            "audit_trail": "✅ Immutable Audit Logging per aksi (Role, IP, Timestamp)",
            "pdp_status": "✅ 100% COMPLIANT (Kepatuhan UU PDP No. 27/2022)"
        }
    }

@app.get("/api/v1/demo/raw-dump", tags=["Demo UI"])
def get_raw_database_dump():
    """Simulasi data mentah yang didapatkan penyerang jika berhasil mendump tabel database."""
    conn = get_connection(user_role="app_user", db_name="dpr_pdp_db")
    cursor = conn.cursor()
    cursor.execute("""
        SELECT anggota_id, no_ktp_enc, npwp_enc, rekening_enc, bidx_no_ktp, key_version
        FROM `anggota_sensitif`
        LIMIT 3;
    """)
    rows = cursor.fetchall()
    conn.close()
    return {
        "status": "DATA_BREACH_SIMULATION",
        "disk_format": "AES-256-GCM Raw Payloads (IV + Tag + Ciphertext)",
        "leaked_rows": rows
    }
@app.post("/api/v1/system/reset-limiter", tags=["System Internal"])
def reset_rate_limit_state():
    reset_all_limiters()
    return {"message": "Memori rate limiter berhasil dikosongkan."}

@app.delete("/api/v1/anggota/{anggota_id}/retention-purge", tags=["Data Retention"])
def purge_anggota_data(
    anggota_id: int,
    request: Request,
    current_user: dict = Depends(require_role(["admin_user"]))
):
    success = secure_shred_record(anggota_id)
    if not success:
        raise HTTPException(status_code=404, detail="Data anggota tidak ditemukan atau gagal dimusnahkan.")

    record_audit_log(
        user_id=current_user["sub"],
        role=current_user["role"],
        action="DATA_PURGE_RETENTION",
        target_id=anggota_id,
        req=request
    )

    return {
        "message": f"Data sensitif anggota ID {anggota_id} telah dimusnahkan secara kriptografis (Right to be Forgotten).",
        "status": "purged"
    }
@app.exception_handler(Exception)
async def global_exception_handler(request: Request, exc: Exception):
    print(f"[!] Server Error pada {request.method} {request.url.path}: {type(exc).__name__}")
    return JSONResponse(
        status_code=500,
        content={"detail": "Terjadi kesalahan internal pada server. Silakan hubungi administrator."}
    )


def record_audit_log(user_id: str, role: str, action: str, target_id: Optional[int], req: Request):
    try:
        conn = get_connection(user_role="app_user", db_name="dpr_pdp_db")
        cursor = conn.cursor()
        sql = """
            INSERT INTO `audit_log` (`user_id`, `role`, `action`, `target_anggota_id`, `ip_address`, `user_agent`)
            VALUES (%s, %s, %s, %s, %s, %s);
        """
        client_ip = req.client.host if req.client else "127.0.0.1"
        user_agent = req.headers.get("user-agent", "unknown")[:255]
        cursor.execute(sql, (user_id, role, action, target_id, client_ip, user_agent))
        conn.close()
    except Exception as e:
        print(f"[-] Gagal mencatat audit log: {e}")


class LoginRequest(BaseModel):
    username: str
    password: str


@app.post("/api/v1/auth/login", tags=["Autentikasi"], dependencies=[Depends(rate_limit_login)])
def login(payload: LoginRequest):
    conn = get_connection(user_role="app_user")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM users WHERE username = %s AND is_active = TRUE LIMIT 1;", (payload.username,))
    user = cursor.fetchone()
    conn.close()

    if not user or not verify_password(payload.password, user["password_hash"]):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Kredensial username atau kata sandi tidak valid."
        )

    token = create_access_token(data={
        "sub": user["username"],
        "role": user["role"],
        "user_id": user["id"]
    })

    return {
        "access_token": token,
        "token_type": "bearer",
        "role": user["role"],
        "full_name": user["full_name"]
    }


@app.post("/api/v1/auth/logout", tags=["Autentikasi"])
def logout(
    request: Request,
    current_user: dict = Depends(get_current_user)
):
    token = current_user.get("raw_token")
    user_id = current_user.get("sub", "unknown")
    exp_ts = current_user.get("exp", int(time.time()) + 3600)

    success = revoke_token(token, user_id, exp_ts)
    if not success:
        raise HTTPException(status_code=500, detail="Gagal mengakhiri sesi pengguna.")

    record_audit_log(
        user_id=user_id,
        role=current_user.get("role", "unknown"),
        action="AUTH_LOGOUT",
        target_id=None,
        req=request
    )

    return {"message": "Sesi berhasil diakhiri. Token telah dicabut."}


@app.get("/api/v1/anggota", response_model=List[AnggotaPublicResponse], tags=["Anggota"])
def get_all_anggota_public(
    limit: int = 50,
    offset: int = 0,
    current_user: dict = Depends(require_role(["app_user", "analyst_user", "admin_user"]))
):
    conn = get_connection(user_role="app_user", db_name="dpr_pdp_db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM `anggota` LIMIT %s OFFSET %s;", (limit, offset))
    rows = cursor.fetchall()
    conn.close()
    return rows


@app.post("/api/v1/anggota/search/nik", response_model=AnggotaMaskedResponse, tags=["Pencarian"])
def search_by_nik(
    payload: SearchByNikRequest,
    request: Request,
    current_user: dict = Depends(require_role(["app_user", "admin_user"]))
):
    rate_limit_search(current_user)
    search_nik = payload.nik
    search_nik = getattr(payload, "nik", None) or getattr(payload, "no_ktp", None)
    if not search_nik:
        raise HTTPException(status_code=400, detail="Parameter NIK wajib disertakan.")

    bidx = crypto.compute_blind_index(str(search_nik))
    
    conn = get_connection(user_role="app_user", db_name="dpr_pdp_db")
    cursor = conn.cursor()
    
    sql = """
        SELECT a.*, s.no_ktp_enc, s.email_enc, s.handphone_enc, s.rekening_enc
        FROM `anggota_sensitif` s
        JOIN `anggota` a ON a.id = s.anggota_id
        WHERE s.bidx_no_ktp = %s
        LIMIT 1;
    """
    cursor.execute(sql, (bidx,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Data anggota dengan NIK tersebut tidak ditemukan.")

    record_audit_log(
        user_id=current_user["sub"],
        role=current_user["role"],
        action="SEARCH_BY_NIK_MASKED",
        target_id=row["id"],
        req=request
    )

    plain_nik = crypto.decrypt(row["no_ktp_enc"])
    plain_email = crypto.decrypt(row["email_enc"])
    plain_hp = crypto.decrypt(row["handphone_enc"])
    plain_rek = crypto.decrypt(row["rekening_enc"])

    return AnggotaMaskedResponse(
        id=row["id"],
        nama_lengkap=mask_nama(row.get("nama_lengkap", "")),
        jenis_kelamin=row["jenis_kelamin"],
        ruangan=row["ruangan"],
        no_ktp_masked=crypto.mask_nik(plain_nik),
        email_masked=crypto.mask_email(plain_email),
        handphone_masked=crypto.mask_telepon(plain_hp),
        rekening_masked=crypto.mask_rekening(plain_rek),
        nama_bank=row["nama_bank"],
        nama_kppn=row["nama_kppn"]
    )


@app.get("/api/v1/anggota/{anggota_id}/sensitive", response_model=AnggotaFullSensitiveResponse, tags=["Admin Privileged"])
def get_anggota_sensitive_full(
    anggota_id: int,
    request: Request,
    current_user: dict = Depends(require_role(["admin_user"]))
):
    conn = get_connection(user_role="root", db_name="dpr_pdp_db")
    cursor = conn.cursor()

    sql = """
        SELECT a.*, s.*
        FROM `anggota` a
        JOIN `anggota_sensitif` s ON a.id = s.anggota_id
        WHERE a.id = %s;
    """
    cursor.execute(sql, (anggota_id,))
    row = cursor.fetchone()
    conn.close()

    if not row:
        raise HTTPException(status_code=404, detail="Data tidak ditemukan.")

    record_audit_log(
        user_id=current_user["sub"],
        role=current_user["role"],
        action="READ_FULL_SENSITIVE",
        target_id=anggota_id,
        req=request
    )

    return AnggotaFullSensitiveResponse(
        id=row["id"],
        nama_lengkap=row["nama_lengkap"],
        jenis_kelamin=row["jenis_kelamin"],
        tempat_lahir=row["tempat_lahir"],
        tanggal_lahir=row["tanggal_lahir"],
        pekerjaan_terakhir=row["pekerjaan_terakhir"],
        ruangan=row["ruangan"],
        no_ktp=crypto.decrypt(row["no_ktp_enc"]),
        npwp=crypto.decrypt(row["npwp_enc"]),
        rekening=crypto.decrypt(row["rekening_enc"]),
        nama_rekening=crypto.decrypt(row["nama_rekening_enc"]),
        nip_kppn=crypto.decrypt(row["nip_kppn_enc"]),
        handphone=crypto.decrypt(row["handphone_enc"]),
        email=crypto.decrypt(row["email_enc"]),
        agama=crypto.decrypt(row["agama_enc"]),
        alamat_jakarta=crypto.decrypt(row["alamat_jakarta_enc"]),
        alamat_daerah=crypto.decrypt(row["alamat_daerah_enc"]),
        nama_bank=row["nama_bank"],
        kode_bank=row["kode_bank"],
        nama_kppn=row["nama_kppn"],
        key_version=row["key_version"]
    )


@app.get("/api/v1/audit-logs", response_model=List[AuditLogResponse], tags=["Auditor"])
def get_audit_logs(
    limit: int = 20,
    current_user: dict = Depends(require_role(["auditor_user", "admin_user"]))
):
    conn = get_connection(user_role="auditor_user", db_name="dpr_pdp_db")
    cursor = conn.cursor()
    cursor.execute("SELECT * FROM `audit_log` ORDER BY `accessed_at` DESC LIMIT %s;", (limit,))
    rows = cursor.fetchall()
    conn.close()
    return rows