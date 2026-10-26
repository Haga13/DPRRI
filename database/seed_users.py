import os
import sys
import pymysql
from dotenv import load_dotenv

load_dotenv()
sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))

from backend.auth import hash_password

INITIAL_USERS = [
    ("operator1", "OperatorPass2026!", "Operator Data Sekretariat", "app_user"),
    ("analyst1", "AnalystPass2026!", "Tim Analis Kebijakan", "analyst_user"),
    ("auditor1", "AuditorPass2026!", "Auditor Kepatuhan Internal", "auditor_user"),
    ("admin1", "AdminPass2026!", "Administrator Keamanan Sistem", "admin_user"),
]

def seed_users():
    conn = pymysql.connect(
        host=os.getenv("DB_HOST", "127.0.0.1"),
        port=int(os.getenv("DB_PORT", 3306)),
        user=os.getenv("DB_ROOT_USER", "haga"),
        password=os.getenv("DB_ROOT_PASS", "haga@11002"),
        database=os.getenv("DB_NAME", "dpr_pdp_db")
    )
    cur = conn.cursor()

    print("[*] Melakukan seeding akun pengguna dengan Adaptive Password Hashing...")
    for username, plain_pass, full_name, role in INITIAL_USERS:
        pwd_hash = hash_password(plain_pass)
        sql = """
            INSERT INTO users (username, password_hash, full_name, role)
            VALUES (%s, %s, %s, %s)
            ON DUPLICATE KEY UPDATE password_hash = VALUES(password_hash), role = VALUES(role);
        """
        cur.execute(sql, (username, pwd_hash, full_name, role))
        print(f"  [+] Akun '{username}' ({role}) terdaftar.")

    conn.commit()
    conn.close()
    print("[V] Seeding user selesai.")

if __name__ == "__main__":
    seed_users()