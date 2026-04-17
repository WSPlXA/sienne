-- Execute on the replica instance as an administrative user.
-- This script enforces replica read-only mode and provisions an application read-only account.

-- 1) Enforce runtime + persisted read-only mode.
SET GLOBAL read_only = ON;
SET GLOBAL super_read_only = ON;
SET PERSIST read_only = ON;
SET PERSIST super_read_only = ON;

-- 2) Replace host/password to your real network boundary before running.
CREATE USER IF NOT EXISTS 'idp_ro'@'10.%' IDENTIFIED BY 'ChangeThisReplicaReadPassword_32CharsMin';
ALTER USER 'idp_ro'@'10.%' IDENTIFIED BY 'ChangeThisReplicaReadPassword_32CharsMin';

-- 3) Grant only SELECT permissions to application schema.
REVOKE ALL PRIVILEGES, GRANT OPTION FROM 'idp_ro'@'10.%';
GRANT SELECT ON app.* TO 'idp_ro'@'10.%';
FLUSH PRIVILEGES;

-- 4) Quick verification.
SELECT @@global.read_only AS read_only, @@global.super_read_only AS super_read_only;
SHOW GRANTS FOR 'idp_ro'@'10.%';
