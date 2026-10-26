USE `dpr_pdp_db`;

CREATE USER IF NOT EXISTS 'app_user'@'%' IDENTIFIED BY 'App_P@ssw0rd_2026!';
CREATE USER IF NOT EXISTS 'analyst_user'@'%' IDENTIFIED BY 'Analyst_P@ssw0rd_2026!';
CREATE USER IF NOT EXISTS 'auditor_user'@'%' IDENTIFIED BY 'Auditor_P@ssw0rd_2026!';
CREATE USER IF NOT EXISTS 'backup_user'@'%' IDENTIFIED BY 'Backup_P@ssw0rd_2026!';

ALTER USER 'app_user'@'%' IDENTIFIED BY 'App_P@ssw0rd_2026!';
ALTER USER 'analyst_user'@'%' IDENTIFIED BY 'Analyst_P@ssw0rd_2026!';
ALTER USER 'auditor_user'@'%' IDENTIFIED BY 'Auditor_P@ssw0rd_2026!';
ALTER USER 'backup_user'@'%' IDENTIFIED BY 'Backup_P@ssw0rd_2026!';

CREATE OR REPLACE VIEW `v_analyst_anggota` AS
SELECT 
    a.id AS `pseudo_id`,
    CONCAT(LEFT(a.nama_lengkap, 2), '***') AS `nama_samaran`,
    a.jenis_kelamin,
    a.tempat_lahir,
    TIMESTAMPDIFF(YEAR, a.tanggal_lahir, CURDATE()) AS `usia`,
    a.pekerjaan_terakhir,
    a.ruangan,
    a.nama_bank,
    a.nama_kppn
FROM `anggota` a;

REVOKE ALL PRIVILEGES, GRANT OPTION FROM 
    'app_user'@'%', 
    'analyst_user'@'%', 
    'auditor_user'@'%', 
    'backup_user'@'%';

GRANT SELECT, INSERT, UPDATE ON `dpr_pdp_db`.`anggota` TO 'app_user'@'%';
GRANT SELECT, INSERT, UPDATE ON `dpr_pdp_db`.`anggota_sensitif` TO 'app_user'@'%';
GRANT INSERT, SELECT ON `dpr_pdp_db`.`audit_log` TO 'app_user'@'%';
GRANT SELECT, INSERT, UPDATE, DELETE ON `dpr_pdp_db`.`revoked_tokens` TO 'app_user'@'%';

GRANT SELECT ON `dpr_pdp_db`.`v_analyst_anggota` TO 'analyst_user'@'%';

GRANT SELECT ON `dpr_pdp_db`.`audit_log` TO 'auditor_user'@'%';

GRANT SELECT, LOCK TABLES, SHOW VIEW, TRIGGER ON `dpr_pdp_db`.* TO 'backup_user'@'%';
GRANT RELOAD, PROCESS ON *.* TO 'backup_user'@'%';

FLUSH PRIVILEGES;