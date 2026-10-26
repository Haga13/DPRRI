import os
import pymysql
from dotenv import load_dotenv

load_dotenv()

DB_HOST = os.getenv("DB_HOST", "127.0.0.1")
DB_PORT = int(os.getenv("DB_PORT", 3306))
DEFAULT_DB_NAME = os.getenv("DB_NAME", "dpr_pdp_db")

ROLE_CREDENTIALS = {
    "app_user": {
        "user": "app_user",
        "password": os.getenv("DB_APP_PASS", "App_P@ssw0rd_2026!")
    },
    "analyst_user": {
        "user": "analyst_user",
        "password": os.getenv("DB_ANALYST_PASS", "Analyst_P@ssw0rd_2026!")
    },
    "auditor_user": {
        "user": "auditor_user",
        "password": os.getenv("DB_AUDITOR_PASS", "Auditor_P@ssw0rd_2026!")
    },
    "backup_user": {
        "user": "backup_user",
        "password": os.getenv("DB_BACKUP_PASS", "Backup_P@ssw0rd_2026!")
    },
    "root": {
        "user": os.getenv("DB_ROOT_USER", "haga"),
        "password": os.getenv("DB_ROOT_PASS", "haga@11002")
    }
}


def get_connection(user_role: str = "app_user", db_name: str = None):
    """
    Membuka koneksi ke MySQL berdasarkan wewenang peran tertentu.
    Default diarahkan ke 'app_user' demi prinsip least privilege.
    """
    target_db = db_name or DEFAULT_DB_NAME
    cred = ROLE_CREDENTIALS.get(user_role, ROLE_CREDENTIALS["app_user"])

    return pymysql.connect(
        host=DB_HOST,
        port=DB_PORT,
        user=cred["user"],
        password=cred["password"],
        database=target_db,
        cursorclass=pymysql.cursors.DictCursor,
        autocommit=True
    )