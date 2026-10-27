# PANDUAN DEPLOYMENT

## Arsitektur Keamanan 4-Tier Privilege Separation



## DAFTAR LANGKAH DEPLOYMENT

### TAHAP 1: Persiapan Server & User Terisolasi (Login: `ubuntu` / Sudo)

Jalankan perintah ini di VPS untuk mengupdate sistem, menginstal paket pendukung, dan membuat akun layanan terisolasi:

```bash
#remote vps via ssh
ssh host@ipvps

# 1. Update OS dan instalasi dependensi dasar
sudo apt update && sudo apt upgrade -y
sudo apt install -y python3.12-venv python3-pip mysql-server nginx git curl

# 2. Buat 3 User Sistem Khusus (Tanpa Password / No SSH Direct)
sudo adduser --disabled-password --gecos "" dpr_backend
sudo adduser --system --group --no-create-home dpr_kms
sudo adduser --disabled-password --gecos "" dpr_backup
```

---

### TAHAP 2: Konfigurasi Basis Data MySQL & RBAC Tersegregasi

```bash
# 1. Pastikan service MySQL aktif
sudo systemctl enable --now mysql

# 2. Setup user administrator MySQL 'haga' untuk localhost & 127.0.0.1
sudo mysql -e " (untuk usernama dan password sql bisa diganti sesuai kebutuhan)
CREATE USER IF NOT EXISTS 'haga'@'localhost' IDENTIFIED BY 'haga@11002';
CREATE USER IF NOT EXISTS 'haga'@'127.0.0.1' IDENTIFIED BY 'haga@11002';
CREATE USER IF NOT EXISTS 'haga'@'%' IDENTIFIED BY 'haga@11002';
GRANT ALL PRIVILEGES ON *.* TO 'haga'@'localhost' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'haga'@'127.0.0.1' WITH GRANT OPTION;
GRANT ALL PRIVILEGES ON *.* TO 'haga'@'%' WITH GRANT OPTION;
FLUSH PRIVILEGES;
"

# 3. Buat database dan tabel dasar
mysql -u haga -phaga@11002 -e "
CREATE DATABASE IF NOT EXISTS dpr_pdp_db CHARACTER SET utf8mb4 COLLATE utf8mb4_unicode_ci;
USE dpr_pdp_db;

CREATE TABLE IF NOT EXISTS users (
    id INT AUTO_INCREMENT PRIMARY KEY,
    username VARCHAR(50) NOT NULL UNIQUE,
    password_hash VARCHAR(255) NOT NULL,
    role VARCHAR(20) NOT NULL,
    full_name VARCHAR(100) NOT NULL,
    is_active BOOLEAN DEFAULT TRUE,
    created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE IF NOT EXISTS revoked_tokens (
    jti VARCHAR(64) PRIMARY KEY,
    user_id VARCHAR(50) NOT NULL,
    revoked_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
    expires_at TIMESTAMP NOT NULL,
    INDEX idx_expires (expires_at)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;
"
```

---

### TAHAP 3: Setup Kode Backend & Lingkungan Python (`dpr_backend`)

```bash
# 1. Pindah ke sesi user dpr_backend dan clone repository
sudo -u dpr_backend git clone https://github.com/Haga13/DPRRI.git /home/dpr_backend/backend

# 2. Siapkan Virtual Environment Python dan instal seluruh library yang dibutuhkan
sudo -u dpr_backend python3 -m venv /home/dpr_backend/backend/.venv
sudo -u dpr_backend /home/dpr_backend/backend/.venv/bin/pip install --upgrade pip
sudo -u dpr_backend /home/dpr_backend/backend/.venv/bin/pip install \
    fastapi uvicorn gunicorn pymysql cryptography argon2-cffi python-dotenv httpx requests

# 3. Buat file .env backend
sudo bash -c 'cat << "EOF" > /home/dpr_backend/backend/.env
# Konfigurasi Koneksi Database
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=dpr_pdp_db
DB_ROOT_USER=haga
DB_ROOT_PASS=haga@11002

# Password Pengguna Peran Tersegregasi
DB_APP_PASS=App_P@ssw0rd_2026!
DB_ANALYST_PASS=Analyst_P@ssw0rd_2026!
DB_AUDITOR_PASS=Auditor_P@ssw0rd_2026!
DB_BACKUP_PASS=Backup_P@ssw0rd_2026!

# Kunci Enkripsi Master & Pepper
MASTER_PEPPER=dpr-ri-pdp-secret-pepper-2026
BACKUP_PEPPER=dpr-backup-pepper-2026
EOF'

sudo chown dpr_backend:dpr_backend /home/dpr_backend/backend/.env
sudo chmod 600 /home/dpr_backend/backend/.env
```

---

### TAHAP 4: Inisialisasi Skema & Pengguna Aplikasi (RBAC)

```bash
# 1. Terapkan skema tabel anggota & audit log
sudo cat /home/dpr_backend/backend/database/schema_secure.sql | mysql -u haga -phaga@11002 dpr_pdp_db

# 2. Terapkan konfigurasi segregasi user MySQL & hak SELECT tabel users
mysql -u haga -phaga@11002 -e "
USE dpr_pdp_db;
CREATE USER IF NOT EXISTS 'app_user'@'%' IDENTIFIED BY 'App_P@ssw0rd_2026!';
CREATE USER IF NOT EXISTS 'analyst_user'@'%' IDENTIFIED BY 'Analyst_P@ssw0rd_2026!';
CREATE USER IF NOT EXISTS 'auditor_user'@'%' IDENTIFIED BY 'Auditor_P@ssw0rd_2026!';
CREATE USER IF NOT EXISTS 'backup_user'@'%' IDENTIFIED BY 'Backup_P@ssw0rd_2026!';

CREATE OR REPLACE VIEW v_analyst_anggota AS
SELECT 
    a.id AS pseudo_id,
    CONCAT(LEFT(a.nama_lengkap, 2), '***') AS nama_samaran,
    a.jenis_kelamin,
    a.tempat_lahir,
    TIMESTAMPDIFF(YEAR, a.tanggal_lahir, CURDATE()) AS usia,
    a.pekerjaan_terakhir,
    a.ruangan,
    a.nama_bank,
    a.nama_kppn
FROM anggota a;

GRANT SELECT, INSERT, UPDATE ON dpr_pdp_db.anggota TO 'app_user'@'%';
GRANT SELECT, INSERT, UPDATE ON dpr_pdp_db.anggota_sensitif TO 'app_user'@'%';
GRANT INSERT, SELECT ON dpr_pdp_db.audit_log TO 'app_user'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON dpr_pdp_db.revoked_tokens TO 'app_user'@'%';
GRANT SELECT ON dpr_pdp_db.users TO 'app_user'@'%';

GRANT SELECT ON dpr_pdp_db.v_analyst_anggota TO 'analyst_user'@'%';
GRANT SELECT ON dpr_pdp_db.audit_log TO 'auditor_user'@'%';

GRANT SELECT, LOCK TABLES, SHOW VIEW, TRIGGER ON dpr_pdp_db.* TO 'backup_user'@'%';
GRANT RELOAD, PROCESS ON *.* TO 'backup_user'@'%';
FLUSH PRIVILEGES;
"

# 3. Seed akun demo (operator1, analyst1, auditor1, admin1)
sudo su - dpr_backend -c "cd /home/dpr_backend/backend && source .venv/bin/activate && python3 database/seed_users.py"
```

---

### TAHAP 5: Isolasi KMS Master Keyring (`dpr_kms`)

Kunci enkripsi master diproteksi di folder `dpr_kms` dengan hak akses read-only bagi runtime backend:

```bash
# 1. Siapkan direktori dpr_kms
sudo mkdir -p /home/dpr_kms

# 2. Pasang master keyring KMS (Versi Rotasi 2)
sudo bash -c 'cat << "EOF" > /home/dpr_kms/keyring.json
{
  "active_version": 2,
  "keys": {
    "1": {
      "wrapped_dek": "rtS5on0Ca5F8KRLj8AaVoNBmuzFMB8hZYLGHZJiWV37jZhpMPLnnQYArTIdDO6VSZS+ofgrqPvTRfXk6",
      "created_at": "2026-01-01T00:00:00Z"
    },
    "2": {
      "wrapped_dek": "yEcosW7Tvr3FU3pcULIuNhdvbKgpsDiC6anmI0uihejPHS51lzBU1pcn4wdMPaYdglP1//21mYpuUUVA",
      "created_at": "ROTATED_KEY"
    }
  }
}
EOF'

# 3. Konfigurasi hak akses (dpr_kms = RW, dpr_backend = R, lainnya = diblokir total)
sudo chown -R dpr_kms:dpr_kms /home/dpr_kms
sudo usermod -a -G dpr_kms dpr_backend
sudo chmod 750 /home/dpr_kms
sudo chmod 640 /home/dpr_kms/keyring.json

# 4. Buat symlink dari folder KMS backend
sudo ln -sf /home/dpr_kms/keyring.json /home/dpr_backend/backend/kms/keyring.json
```

---

### TAHAP 6: Pemulihan Dataset Master (734 Anggota DPR RI)

Dari **terminal laptop Anda**, kirim folder backup ke VPS:
```bash
# Jalankan di laptop lokal:
scp -r ~/Desktop/dprri/backups ubuntu@<IP_VPS>:/tmp/
```

Lalu di **terminal VPS**:
```bash
# Pindahkan file backup ke backend
sudo cp -r /tmp/backups /home/dpr_backend/backend/
sudo chown -R dpr_backend:dpr_backend /home/dpr_backend/backend/backups

# Eksekusi secure restore dengan menunjuk file master terbaru (20261025)
sudo su - dpr_backend -c "cd /home/dpr_backend/backend && source .venv/bin/activate && python3 backup_recovery/secure_restore.py backups/backup_dpr_pdp_db_20261025_162521.sql.enc"
```

---

### TAHAP 7: Konfigurasi Service Systemd Backend

```bash
# 1. Buat unit systemd dpr-backend.service
sudo bash -c 'cat << "EOF" > /etc/systemd/system/dpr-backend.service
[Unit]
Description=DPR RI PDP Secure Backend Service
After=network.target mysql.service

[Service]
Type=simple
User=dpr_backend
Group=dpr_backend
WorkingDirectory=/home/dpr_backend/backend
EnvironmentFile=/home/dpr_backend/backend/.env
ExecStart=/home/dpr_backend/backend/.venv/bin/uvicorn backend.main:app --host 127.0.0.1 --port 8000
Restart=always
RestartSec=5
PrivateTmp=true

[Install]
WantedBy=multi-user.target
EOF'

# 2. Reload daemon dan jalankan service
sudo systemctl daemon-reload
sudo systemctl enable --now dpr-backend
```

---

### TAHAP 8: Isolasi Frontend Web & Nginx Reverse Proxy (`www-data`)

```bash
# 1. Siapkan direktori web terisolasi
sudo mkdir -p /var/www/dpr_frontend
sudo cp /home/dpr_backend/backend/frontend/index.html /var/www/dpr_frontend/

# 2. Ubah API_BASE menjadi dinamis (window.location.origin)
sudo sed -i 's|const API_BASE = "http://127.0.0.1:8000";|const API_BASE = window.location.origin;|g' /var/www/dpr_frontend/index.html

# 3. Set kepemilikan khusus www-data
sudo chown -R www-data:www-data /var/www/dpr_frontend
sudo chmod -R 755 /var/www/dpr_frontend

# 4. Buat virtual host Nginx
sudo bash -c 'cat << "EOF" > /etc/nginx/sites-available/dpr_pdp
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /var/www/dpr_frontend;
    index index.html;

    location / {
        try_files $uri $uri/ /index.html;
    }

    location /demo {
        try_files /index.html =404;
    }

    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;
    }
}
EOF'

# 5. Aktifkan & restart Nginx
sudo rm -f /etc/nginx/sites-enabled/default
sudo ln -sf /etc/nginx/sites-available/dpr_pdp /etc/nginx/sites-enabled/
sudo nginx -t
sudo systemctl restart nginx
sudo systemctl enable nginx
```

### Nginx Security Hardening
```bash
# 1. Matikan pembocoran versi Nginx secara global
sudo sed -i 's/# server_tokens off;/server_tokens off;/g' /etc/nginx/nginx.conf
sudo sed -i 's/server_tokens on;/server_tokens off;/g' /etc/nginx/nginx.conf

# 2. Perbarui konfigurasi dpr_pdp dengan batasan buffer & HTTP method whitelist
sudo bash -c 'cat << "EOF" > /etc/nginx/sites-available/dpr_pdp
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;

    root /var/www/dpr_frontend;
    index index.html;

    client_body_buffer_size 128k;
    client_max_body_size 10M;
    client_header_buffer_size 1k;
    large_client_header_buffers 4 4k;
    keepalive_timeout 30;

    if ($request_method !~ ^(GET|POST|DELETE|OPTIONS|HEAD|PUT)$) {
        return 405;
    }

    add_header X-Frame-Options "DENY" always;
    add_header X-Content-Type-Options "nosniff" always;
    add_header X-XSS-Protection "1; mode=block" always;
    add_header Referrer-Policy "strict-origin-when-cross-origin" always;
    add_header Content-Security-Policy "default-src \x27self\x27 \x27unsafe-inline\x27; font-src \x27self\x27 https://fonts.gstatic.com; style-src \x27self\x27 \x27unsafe-inline\x27 https://fonts.googleapis.com;" always;


    location / {
        try_files $uri $uri/ /index.html;
    }

    location /demo {
        try_files /index.html =404;
    }


    location /api/ {
        proxy_pass http://127.0.0.1:8000;
        proxy_http_version 1.1;
        proxy_set_header Upgrade $http_upgrade;
        proxy_set_header Connection "upgrade";
        proxy_set_header Host $host;
        proxy_set_header X-Real-IP $remote_addr;
        proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
        proxy_set_header X-Forwarded-Proto $scheme;

        # Anti-Cache Headers
        add_header Cache-Control "no-store, no-cache, must-revalidate, proxy-revalidate, max-age=0" always;
        add_header Pragma "no-cache" always;
        add_header Expires "0" always;
    }
}
EOF'

# 3. Validasi & reload Nginx
sudo nginx -t
sudo systemctl reload nginx
---

```
### Install SSL
```bash
# 1. Install Certbot untuk Nginx
sudo apt update && sudo apt install certbot python3-certbot-nginx -y

# 2. Pasang sertifikat SSL otomatis untuk domain Anda
sudo certbot --nginx -d bloodyz.web.id

# 3. Izinkan HTTPS di server
sudo ufw allow 443/tcp
sudo ufw allow 'Nginx Full'
----
```

### TAHAP 9: Isolasi Auto-Backup & Disaster Recovery (`dpr_backup`)

```bash
# 1. Siapkan workspace terisolasi
sudo mkdir -p /home/dpr_backup/backups
sudo cp /home/dpr_backend/backend/backup_recovery/secure_backup.py /home/dpr_backup/

# 2. Sesuaikan path direktori backups di skrip backup dpr_backup
sudo sed -i 's|os.path.join(os.path.dirname(__file__), "..", "backups")|os.path.join(os.path.dirname(__file__), "backups")|g' /home/dpr_backup/secure_backup.py
sudo sed -i 's|sys.path.append(os.path.abspath(os.path.join(os.path.dirname(__file__), "..")))|sys.path.append(os.path.abspath(os.path.dirname(__file__)))|g' /home/dpr_backup/secure_backup.py

# 3. Siapkan file .env khusus dpr_backup (hanya izin backup)
sudo bash -c 'cat << "EOF" > /home/dpr_backup/.env
DB_HOST=127.0.0.1
DB_PORT=3306
DB_NAME=dpr_pdp_db
DB_BACKUP_PASS=Backup_P@ssw0rd_2026!
BACKUP_PEPPER=dpr-backup-pepper-2026
EOF'

# 4. Setup venv dan modul dependensi
sudo -u dpr_backup python3 -m venv /home/dpr_backup/.venv
sudo -u dpr_backup /home/dpr_backup/.venv/bin/pip install pymysql cryptography python-dotenv
sudo -u dpr_backup mkdir -p /home/dpr_backup/backend
sudo cp /home/dpr_backend/backend/backend/crypto_engine.py /home/dpr_backup/backend/
sudo -u dpr_backup touch /home/dpr_backup/backend/__init__.py

# 5. Terapkan izin isolasi ketat chmod 700
sudo chown -R dpr_backup:dpr_backup /home/dpr_backup
sudo chmod 700 /home/dpr_backup
sudo chmod 600 /home/dpr_backup/.env

# 6. Uji eksekusi pencadangan manual
sudo su - dpr_backup -c "cd /home/dpr_backup && source .venv/bin/activate && python3 secure_backup.py"

# 7. Daftarkan cron job otomatis setiap pukul 02:00 WIB
sudo su - dpr_backup -c '(crontab -l 2>/dev/null; echo "0 2 * * * cd /home/dpr_backup && /home/dpr_backup/.venv/bin/python3 secure_backup.py >> /home/dpr_backup/backups/backup.log 2>&1") | crontab -'
```

---

### TAHAP 10: Pengujian Validasi Keamanan & Kepatuhan Akhir

Jalankan Master Security Test Runner:
```bash
sudo su - dpr_backend -c "cd /home/dpr_backend/backend && source .venv/bin/activate && python3 tests/run_all_security_tests.py"
```

**Ekspektasi Output **
```text
======================================================================
                    RINGKASAN HASIL EVALUASI
======================================================================
 [✓] PASS   | Autentikasi JWT & Otorisasi RBAC
 [✓] PASS   | Token Revocation & Logout
 [✓] PASS   | Pemusnahan Retensi Data (Right to be Forgotten)
 [✓] PASS   | Alur Kerja End-to-End Multi-Peran
 [✓] PASS   | Validasi Input & Rate Limiting
----------------------------------------------------------------------
 HASIL AKHIR : SELURUH MODUL KEAMANAN & KEPATUHAN DINYATAKAN LULUS!
======================================================================
```

Buka antarmuka web di browser laptop Anda:
 `http://<IP_VPS_ANDA>` (atau `http://<IP_VPS_ANDA>/demo`)

---
