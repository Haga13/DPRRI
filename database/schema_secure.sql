
CREATE DATABASE IF NOT EXISTS `dpr_pdp_db` 
  CHARACTER SET utf8mb4 
  COLLATE utf8mb4_unicode_ci;
USE `dpr_pdp_db`;

DROP TABLE IF EXISTS `audit_log`;
DROP TABLE IF EXISTS `anggota_sensitif`;
DROP TABLE IF EXISTS `anggota`;

CREATE TABLE `anggota` (
  `id` INT AUTO_INCREMENT PRIMARY KEY,
  `nama_lengkap` VARCHAR(255) NOT NULL,
  `jenis_kelamin` ENUM('L', 'P') NOT NULL,
  `tempat_lahir` VARCHAR(100) NULL,
  `tanggal_lahir` DATE NULL,
  `pekerjaan_terakhir` VARCHAR(100) NULL,
  `ruangan` VARCHAR(50) NULL,
  `nama_bank` VARCHAR(50) NULL,
  `kode_bank` VARCHAR(10) NULL,
  `nama_kppn` VARCHAR(100) NULL,
  `retention_status` VARCHAR(20) DEFAULT 'active',
  `created_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_nama_lengkap` (`nama_lengkap`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `anggota_sensitif` (
  `anggota_id` INT PRIMARY KEY,
  
  `no_ktp_enc` VARCHAR(255) NOT NULL,
  `npwp_enc` VARCHAR(255) NULL,
  `rekening_enc` VARCHAR(255) NULL,
  `nama_rekening_enc` VARCHAR(255) NULL,
  `nip_kppn_enc` VARCHAR(255) NULL,
  `handphone_enc` VARCHAR(255) NULL,
  `email_enc` VARCHAR(255) NULL,
  `agama_enc` VARCHAR(255) NULL,
  `alamat_jakarta_enc` TEXT NULL,
  `alamat_daerah_enc` TEXT NULL,

  `bidx_no_ktp` VARCHAR(64) NOT NULL,
  `bidx_email` VARCHAR(64) NULL,

  `key_version` INT NOT NULL DEFAULT 1,
  `updated_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP ON UPDATE CURRENT_TIMESTAMP,

  CONSTRAINT `fk_anggota_sensitif` FOREIGN KEY (`anggota_id`) 
    REFERENCES `anggota` (`id`) ON DELETE CASCADE,
  INDEX `idx_bidx_no_ktp` (`bidx_no_ktp`),
  INDEX `idx_bidx_email` (`bidx_email`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;

CREATE TABLE `audit_log` (
  `id` BIGINT AUTO_INCREMENT PRIMARY KEY,
  `user_id` VARCHAR(100) NOT NULL,
  `role` VARCHAR(50) NOT NULL,
  `action` VARCHAR(50) NOT NULL,
  `target_anggota_id` INT NULL,
  `ip_address` VARCHAR(45) NULL,
  `user_agent` VARCHAR(255) NULL,
  `accessed_at` TIMESTAMP DEFAULT CURRENT_TIMESTAMP,
  INDEX `idx_audit_user` (`user_id`),
  INDEX `idx_audit_timestamp` (`accessed_at`)
) ENGINE=InnoDB DEFAULT CHARSET=utf8mb4 COLLATE=utf8mb4_unicode_ci;


CREATE ROLE IF NOT EXISTS 'role_app', 'role_analyst', 'role_auditor', 'role_backup', 'role_admin';

GRANT SELECT, INSERT, UPDATE, DELETE ON `dpr_pdp_db`.`anggota` TO 'role_app';
GRANT SELECT, INSERT, UPDATE, DELETE ON `dpr_pdp_db`.`anggota_sensitif` TO 'role_app';
GRANT INSERT ON `dpr_pdp_db`.`audit_log` TO 'role_app';

GRANT SELECT ON `dpr_pdp_db`.`anggota` TO 'role_analyst';

GRANT SELECT ON `dpr_pdp_db`.`audit_log` TO 'role_auditor';

GRANT SELECT, LOCK TABLES, SHOW VIEW, EVENT, TRIGGER ON `dpr_pdp_db`.* TO 'role_backup';

GRANT ALL PRIVILEGES ON `dpr_pdp_db`.* TO 'role_admin';

CREATE USER IF NOT EXISTS 'app_user'@'%' IDENTIFIED BY 'App_P@ssw0rd_2026!';
CREATE USER IF NOT EXISTS 'analyst_user'@'%' IDENTIFIED BY 'Analyst_P@ssw0rd_2026!';
CREATE USER IF NOT EXISTS 'auditor_user'@'%' IDENTIFIED BY 'Auditor_P@ssw0rd_2026!';
CREATE USER IF NOT EXISTS 'backup_user'@'%' IDENTIFIED BY 'Backup_P@ssw0rd_2026!';
CREATE USER IF NOT EXISTS 'admin_user'@'%' IDENTIFIED BY 'Admin_P@ssw0rd_2026!';

GRANT 'role_app' TO 'app_user'@'%';
GRANT 'role_analyst' TO 'analyst_user'@'%';
GRANT 'role_auditor' TO 'auditor_user'@'%';
GRANT 'role_backup' TO 'backup_user'@'%';
GRANT 'role_admin' TO 'admin_user'@'%';

SET DEFAULT ROLE 'role_app' TO 'app_user'@'%';
SET DEFAULT ROLE 'role_analyst' TO 'analyst_user'@'%';
SET DEFAULT ROLE 'role_auditor' TO 'auditor_user'@'%';
SET DEFAULT ROLE 'role_backup' TO 'backup_user'@'%';
SET DEFAULT ROLE 'role_admin' TO 'admin_user'@'%';

FLUSH PRIVILEGES;