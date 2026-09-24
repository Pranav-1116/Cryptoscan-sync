"""Wave 9 — database and mainframe crypto: Oracle PL/SQL, SQL Server T-SQL,
PostgreSQL pgcrypto, MySQL, DB2, and COBOL/ICSF callable services. NOT blind:
the two parsers were written in the same session — but labels were written from
the code before the first run and were not edited afterwards.

Conventions: HASHBYTES/DBMS_CRYPTO.HASH_* -> digest family; ENCRYPTBYKEY without
the CREATE SYMMETRIC KEY in the same file -> UNKNOWN (not counted); ICSF PIN/CVV/
MAC verbs -> 3DES, CSNBSYE -> AES, CSNBOWH -> digest from the rule-array literal,
CSND* -> RSA (ECDSA when the rule array says ECC); VSAM RECORD KEY / table
lookups / Base64 / ORA_HASH / CHECKSUM / hash partitioning -> nothing.
"""
from __future__ import annotations


def register(_c) -> None:  # noqa: C901
    # ---------------------------------------------------------------- Oracle
    _c("sql", "w9_ora_card_pkg.pkb", """
CREATE OR REPLACE PACKAGE BODY card_sec AS
  g_key RAW(32) := HEXTORAW('0011223344556677889900AABBCCDDEEFF00112233445566778899AABBCCDDEE');
  FUNCTION enc_pan(p_pan IN VARCHAR2) RETURN RAW IS
    l_mode PLS_INTEGER := DBMS_CRYPTO.ENCRYPT_AES256 + DBMS_CRYPTO.CHAIN_CBC + DBMS_CRYPTO.PAD_PKCS5;
  BEGIN
    RETURN DBMS_CRYPTO.ENCRYPT(UTL_I18N.STRING_TO_RAW(p_pan, 'AL32UTF8'), l_mode, g_key);
  END;
  FUNCTION pan_hash(p_pan IN VARCHAR2) RETURN RAW IS
  BEGIN
    RETURN DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(p_pan), DBMS_CRYPTO.HASH_SH256);
  END;
END card_sec;
""", {"AES", "SHA-256"})
    _c("sql", "w9_ora_legacy_des.sql", """
DECLARE
  l_out VARCHAR2(2000);
BEGIN
  DBMS_OBFUSCATION_TOOLKIT.DESEncrypt(input_string => :pin, key_string => :k, encrypted_string => l_out);
  DBMS_OBFUSCATION_TOOLKIT.DES3Encrypt(input_string => :pan, key_string => :k3, encrypted_string => l_out);
END;
""", {"DES", "3DES"})
    _c("sql", "w9_ora_hmac_audit.prc", """
CREATE OR REPLACE PROCEDURE audit_sign(p_row IN VARCHAR2, p_sig OUT RAW) IS
BEGIN
  p_sig := DBMS_CRYPTO.MAC(UTL_RAW.CAST_TO_RAW(p_row), DBMS_CRYPTO.HMAC_SH512, g_mac_key);
END;
""", {"HMAC", "SHA-512"})
    _c("sql", "w9_ora_tde.ddl", """
CREATE TABLE customer (
  id NUMBER PRIMARY KEY,
  pan VARCHAR2(19) ENCRYPT USING 'AES256' NO SALT,
  ssn VARCHAR2(11) ENCRYPT
);
ADMINISTER KEY MANAGEMENT SET KEYSTORE OPEN IDENTIFIED BY "w4ll3t";
""", {"AES"})
    _c("sql", "w9_ora_md5_password.pls", """
CREATE OR REPLACE FUNCTION check_pwd(p_user VARCHAR2, p_pwd VARCHAR2) RETURN BOOLEAN IS
  l_hash VARCHAR2(32);
BEGIN
  l_hash := RAWTOHEX(DBMS_CRYPTO.HASH(UTL_RAW.CAST_TO_RAW(p_pwd || p_user), DBMS_CRYPTO.HASH_MD5));
  RETURN l_hash = get_stored_hash(p_user);
END;
""", {"MD5"})
    _c("sql", "w9_ora_random_otp.sql", """
CREATE OR REPLACE FUNCTION gen_otp RETURN VARCHAR2 IS
BEGIN
  RETURN LPAD(TRUNC(DBMS_RANDOM.VALUE(0, 999999)), 6, '0'); -- otp for sms
END;
""", {"RNG"})
    _c("sql", "w9_ora_random_bytes.sql", """
DECLARE l_salt RAW(16);
BEGIN
  l_salt := DBMS_CRYPTO.RANDOMBYTES(16);
  l_hash := STANDARD_HASH(:pwd || l_salt, 'SHA512');
END;
""", {"RNG", "SHA-512"})
    _c("sql", "w9_ora_rsa_sign.pkb", """
BEGIN
  l_sig := DBMS_CRYPTO.SIGN(src => l_data, prv_key => l_key, pubkey_alg => DBMS_CRYPTO.KEY_TYPE_RSA, sign_alg => DBMS_CRYPTO.SIGN_SHA256_RSA);
END;
""", {"RSA"})
    # ------------------------------------------------------------ SQL Server
    _c("sql", "w9_tsql_symmetric.sql", """
CREATE MASTER KEY ENCRYPTION BY PASSWORD = 'Str0ng!Pass';
CREATE CERTIFICATE CardCert WITH SUBJECT = 'Card data';
CREATE SYMMETRIC KEY CardKey WITH ALGORITHM = AES_256 ENCRYPTION BY CERTIFICATE CardCert;
GO
OPEN SYMMETRIC KEY CardKey DECRYPTION BY CERTIFICATE CardCert;
UPDATE dbo.Cards SET PanEnc = ENCRYPTBYKEY(KEY_GUID('CardKey'), Pan);
CLOSE SYMMETRIC KEY CardKey;
""", {"AES", "X509"})
    _c("sql", "w9_tsql_hashbytes.sql", """
CREATE PROCEDURE dbo.VerifyLogin @user NVARCHAR(64), @pwd NVARCHAR(128) AS
BEGIN
  DECLARE @salt VARBINARY(16) = (SELECT Salt FROM dbo.Users WHERE UserName = @user);
  IF EXISTS (SELECT 1 FROM dbo.Users WHERE UserName = @user AND PwdHash = HASHBYTES('SHA2_512', @salt + CONVERT(VARBINARY(256), @pwd)))
    SELECT 1 ELSE SELECT 0;
END
""", {"SHA-512"})
    _c("sql", "w9_tsql_legacy_md5.sql", """
SELECT UserId, HASHBYTES('MD5', Password) AS PwdHash FROM dbo.LegacyUsers;
SELECT CHECKSUM(*) FROM dbo.Ledger;
""", {"MD5"})
    _c("sql", "w9_tsql_passphrase.sql", """
INSERT INTO dbo.Notes (Body) VALUES (ENCRYPTBYPASSPHRASE(@passphrase, @plain));
SELECT CONVERT(NVARCHAR(MAX), DECRYPTBYPASSPHRASE(@passphrase, Body)) FROM dbo.Notes;
""", {"3DES"})
    _c("sql", "w9_tsql_tde.sql", """
USE CoreBanking;
CREATE DATABASE ENCRYPTION KEY WITH ALGORITHM = AES_256 ENCRYPTION BY SERVER CERTIFICATE TDECert;
ALTER DATABASE CoreBanking SET ENCRYPTION ON;
""", {"AES", "X509"})
    _c("sql", "w9_tsql_always_encrypted.sql", """
CREATE TABLE dbo.Customers (
  CustomerId INT PRIMARY KEY,
  SSN CHAR(11) COLLATE Latin1_General_BIN2
    ENCRYPTED WITH (COLUMN_ENCRYPTION_KEY = CEK_Auto1, ENCRYPTION_TYPE = DETERMINISTIC, ALGORITHM = 'AEAD_AES_256_CBC_HMAC_SHA_256')
);
""", {"AES", "HMAC", "SHA-256"})
    _c("sql", "w9_tsql_asym.sql", """
CREATE ASYMMETRIC KEY SignKey WITH ALGORITHM = RSA_2048;
SELECT SIGNBYASYMKEY(ASYMKEY_ID('SignKey'), @payload);
""", {"RSA"})
    _c("sql", "w9_tsql_triple_des.sql", """
CREATE SYMMETRIC KEY OldKey WITH ALGORITHM = TRIPLE_DES ENCRYPTION BY PASSWORD = 'p';
CREATE SYMMETRIC KEY OlderKey WITH ALGORITHM = RC4 ENCRYPTION BY PASSWORD = 'p';
""", {"3DES", "RC4"})
    _c("sql", "w9_tsql_rand_token.sql", """
DECLARE @token VARCHAR(8) = RIGHT('00000000' + CAST(CAST(RAND() * 100000000 AS INT) AS VARCHAR(8)), 8); -- session token
SELECT CRYPT_GEN_RANDOM(32) AS Nonce;
""", {"RNG"})
    # ------------------------------------------------------------ PostgreSQL
    _c("sql", "w9_pg_bcrypt.sql", """
CREATE EXTENSION IF NOT EXISTS pgcrypto;
INSERT INTO users (email, pw_hash) VALUES ($1, crypt($2, gen_salt('bf', 12)));
SELECT id FROM users WHERE email = $1 AND pw_hash = crypt($2, pw_hash);
""", {"BCRYPT"})
    _c("sql", "w9_pg_digest_hmac.sql", """
SELECT encode(digest(payload, 'sha256'), 'hex') AS body_hash,
       encode(hmac(payload, current_setting('app.webhook_secret'), 'sha256'), 'hex') AS sig
FROM webhooks;
""", {"SHA-256", "HMAC"})
    _c("sql", "w9_pg_pgp.sql", """
UPDATE accounts SET iban_enc = pgp_sym_encrypt(iban, :key, 'cipher-algo=aes256, compress-algo=1');
SELECT pgp_sym_decrypt(iban_enc, :key) FROM accounts WHERE id = 1;
""", {"PGP", "AES"})
    _c("sql", "w9_pg_raw_cipher.sql", """
SELECT encrypt(convert_to(card_no, 'utf8'), :k, 'aes-cbc/pad:pkcs') FROM cards;
SELECT encrypt(data, :k, 'bf') FROM legacy_blobs;
SELECT gen_random_bytes(32);
""", {"AES", "BLOWFISH", "RNG"})
    _c("sql", "w9_pg_md5_legacy.sql", """
SELECT md5(password || salt) = stored FROM legacy_login WHERE username = $1;
ALTER SYSTEM SET password_encryption = 'scram-sha-256';
""", {"MD5", "SHA-256"})  # convention: scram-sha-256 -> SHA-256 (as in wave 5 pg_hba)
    _c("sql", "w9_pg_random_token.sql", """
INSERT INTO reset_tokens (user_id, token) VALUES ($1, substr(md5(random()::text), 1, 20));
""", {"MD5", "RNG"})
    # -------------------------------------------------------------- MySQL
    _c("sql", "w9_mysql_aes.sql", """
SET block_encryption_mode = 'aes-256-cbc';
SET @iv = RANDOM_BYTES(16);
INSERT INTO card (pan_enc) VALUES (AES_ENCRYPT(@pan, UNHEX(SHA2(@key, 512)), @iv));
""", {"AES", "SHA-512"})
    _c("sql", "w9_mysql_legacy.sql", """
SELECT user FROM app_user WHERE pwd = SHA1(CONCAT(salt, ?));
UPDATE app_user SET pwd = MD5(?) WHERE id = ?;
ALTER USER 'svc'@'%' IDENTIFIED WITH mysql_native_password BY 'x' REQUIRE SSL;
""", {"SHA-1", "MD5", "TLS"})
    _c("sql", "w9_mysql_des.sql", """
SELECT DES_DECRYPT(secret_blob, 'k') FROM vault;
""", {"DES"})
    # ---------------------------------------------------------------- DB2
    _c("sql", "w9_db2_encrypt.sql", """
SET ENCRYPTION PASSWORD = :hv_pw;
INSERT INTO EMP (SSN) VALUES (ENCRYPT_TDES(:ssn));
SELECT DECRYPT_CHAR(SSN), HASH(NAME, 2) FROM EMP;
""", {"3DES", "AES", "SHA-256"})
    # ------------------------------------------------------ SQL negatives
    _c("sql", "w9_neg_schema.sql", """
CREATE TABLE account (
  id BIGINT PRIMARY KEY,
  customer_id BIGINT NOT NULL,
  api_key_hash VARCHAR(64),
  md5_checksum CHAR(32),
  CONSTRAINT fk_cust FOREIGN KEY (customer_id) REFERENCES customer(id)
) PARTITION BY HASH (id) PARTITIONS 8;
CREATE INDEX ix_acc USING HASH ON account(customer_id);
SELECT ORA_HASH(id, 1024) FROM account;
SELECT BINARY_CHECKSUM(*) FROM account;
""", set())
    _c("sql", "w9_neg_comments.sql", """
-- TODO: migrate from HASHBYTES('MD5', ...) to SHA2_256 next quarter
/* legacy: AES_ENCRYPT was used here before tokenisation */
SELECT id, encode(payload, 'base64') FROM outbox;
SELECT gen_random_uuid(), NEWID();
""", set())
    _c("sql", "w9_neg_random_paging.sql", """
SELECT * FROM products ORDER BY random() LIMIT 10;
SELECT TOP 5 * FROM Ads ORDER BY RAND();
""", set())

    # ------------------------------------------------------------ COBOL / ICSF
    _c("cobol", "w9_cbl_pin_verify.cbl", """
       IDENTIFICATION DIVISION.
       PROGRAM-ID. PINVERF.
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  RULE-ARRAY-COUNT        PIC S9(9) COMP VALUE 1.
       01  RULE-ARRAY              PIC X(8)  VALUE 'IBM-PINO'.
       01  PIN-ENC-KEY-ID          PIC X(64).
       01  PIN-BLOCK               PIC X(8).
       PROCEDURE DIVISION.
           CALL 'CSNBPVR' USING RETURN-CODE REASON-CODE EXIT-DATA-LENGTH
                EXIT-DATA PIN-ENC-KEY-ID PIN-VER-KEY-ID PIN-PROFILE
                PAN-DATA PIN-BLOCK RULE-ARRAY-COUNT RULE-ARRAY
                PIN-CHECK-LENGTH DATA-ARRAY.
           IF RETURN-CODE NOT = 0 PERFORM PIN-FAIL.
""", {"3DES"})
    _c("cobol", "w9_cbl_cvv.cbl", """
       PROCEDURE DIVISION.
           MOVE 'CVV-1   ' TO RULE-ARRAY(1).
           CALL 'CSNBCVV' USING RC RS EXIT-LEN EXIT-DATA CVK-A CVK-B
                PAN-DATA EXPIRY SERVICE-CODE RULE-COUNT RULE-ARRAY CVV-IN.
""", {"3DES"})
    _c("cobol", "w9_cbl_aes_encipher.cbl", """
       WORKING-STORAGE SECTION.
       01  RULE-ARRAY.
           05  FILLER              PIC X(8) VALUE 'AES     '.
           05  FILLER              PIC X(8) VALUE 'CBC     '.
           05  FILLER              PIC X(8) VALUE 'KEYIDENT'.
       PROCEDURE DIVISION.
           CALL 'CSNBSYE' USING RC RS EXIT-LEN EXIT-DATA RULE-COUNT
                RULE-ARRAY KEY-ID-LEN KEY-ID KEY-PARMS-LEN KEY-PARMS
                BLOCK-SIZE IV-LEN IV CHAIN-LEN CHAIN-DATA
                CLEAR-LEN CLEAR-TEXT CIPHER-LEN CIPHER-TEXT
                OPT-DATA-LEN OPT-DATA.
""", {"AES"})
    _c("cobol", "w9_cbl_des_encipher.cbl", """
       PROCEDURE DIVISION.
           MOVE 'CUSP    ' TO RULE-ARRAY.
           CALL 'CSNBENC' USING RC RS EXIT-LEN EXIT-DATA KEY-IDENT
                TEXT-LEN CLEAR-TEXT ICV RULE-COUNT RULE-ARRAY PAD-CHAR
                CHAIN-VECTOR CIPHER-TEXT.
""", {"3DES"})
    _c("cobol", "w9_cbl_owh_sha256.cbl", """
       01  HASH-RULE-ARRAY.
           05  FILLER              PIC X(8) VALUE 'SHA-256 '.
           05  FILLER              PIC X(8) VALUE 'ONLY    '.
       PROCEDURE DIVISION.
           CALL 'CSNBOWH' USING RC RS EXIT-LEN EXIT-DATA RULE-COUNT
                HASH-RULE-ARRAY TEXT-LEN TEXT-IN CHAIN-LEN CHAIN-VECTOR
                HASH-LEN HASH-OUT.
""", {"SHA-256"})
    _c("cobol", "w9_cbl_owh_md5.cbl", """
           MOVE 'MD5     ' TO RULE-ARRAY.
           CALL 'CSNEOWH' USING RC RS EXIT-LEN EXIT-DATA RULE-COUNT
                RULE-ARRAY TEXT-LEN TEXT-IN CHAIN-LEN CHAIN HASH-LEN HASH.
""", {"MD5"})
    _c("cobol", "w9_cbl_hmac.cbl", """
           MOVE 'SHA-512 ' TO RULE-ARRAY(1).
           MOVE 'ONLY    ' TO RULE-ARRAY(2).
           CALL 'CSNBHMG' USING RC RS EXIT-LEN EXIT-DATA RULE-COUNT
                RULE-ARRAY KEY-ID-LEN KEY-ID MSG-LEN MSG CHAIN-LEN
                CHAIN-VECTOR MAC-LEN MAC-OUT.
""", {"HMAC", "SHA-512"})
    _c("cobol", "w9_cbl_mac_gen.cbl", """
           MOVE 'X9.19-1 ' TO RULE-ARRAY.
           CALL 'CSNBMGN' USING RC RS EXIT-LEN EXIT-DATA MAC-KEY-ID
                TEXT-LEN TEXT RULE-COUNT RULE-ARRAY CHAIN-VECTOR MAC.
""", {"3DES"})
    _c("cobol", "w9_cbl_key_gen.cbl", """
       01  KEY-FORM                PIC X(4)  VALUE 'OP  '.
       01  KEY-LENGTH              PIC X(8)  VALUE 'DOUBLE  '.
       01  KEY-TYPE-1              PIC X(8)  VALUE 'DATA    '.
       01  KEY-TYPE-2              PIC X(8)  VALUE 'DATA    '.
       PROCEDURE DIVISION.
           CALL 'CSNBKGN' USING RC RS EXIT-LEN EXIT-DATA KEY-FORM
                KEY-LENGTH KEY-TYPE-1 KEY-TYPE-2 KEK-ID-1 KEK-ID-2
                GEN-KEY-ID-1 GEN-KEY-ID-2.
""", {"3DES"})
    _c("cobol", "w9_cbl_rsa_sign.cbl", """
       01  SIG-RULE-ARRAY.
           05  FILLER PIC X(8) VALUE 'PKCS-1.1'.
       PROCEDURE DIVISION.
           CALL 'CSNDDSG' USING RC RS EXIT-LEN EXIT-DATA RULE-COUNT
                SIG-RULE-ARRAY PKA-KEY-LEN PKA-KEY-TOKEN HASH-LEN HASH
                SIG-FIELD-LEN SIG-BIT-LEN SIG-FIELD.
""", {"RSA"})
    _c("cobol", "w9_cbl_ecc_sign.cbl", """
           MOVE 'ECDSA   ' TO RULE-ARRAY(1).
           CALL 'CSNDDSV' USING RC RS EXIT-LEN EXIT-DATA RULE-COUNT
                RULE-ARRAY PKA-KEY-LEN PKA-KEY-TOKEN HASH-LEN HASH
                SIG-FIELD-LEN SIG-FIELD.
""", {"RSA", "ECDSA"})
    _c("cobol", "w9_cbl_rng.cbl", """
           CALL 'CSNBRNGL' USING RC RS EXIT-LEN EXIT-DATA RULE-COUNT
                RULE-ARRAY SEED-LEN SEED RANDOM-LEN RANDOM-OUT.
""", {"RNG"})
    _c("cobol", "w9_cbl_random_pin.cbl", """
           COMPUTE WS-TEMP-PIN = FUNCTION RANDOM(WS-SEED) * 10000.
""", {"RNG"})
    _c("cobol", "w9_cbl_pkcs11.cbl", """
           MOVE 'CKM-AES-CBC-PAD' TO MECHANISM.
           CALL 'CSFPSKE' USING RC RS EXIT-LEN EXIT-DATA HANDLE RULE-COUNT
                RULE-ARRAY KEY-HANDLE MECH-LEN MECHANISM IV-LEN IV
                CLEAR-LEN CLEAR CIPHER-LEN CIPHER.
""", {"AES"})
    _c("cobol", "w9_cbl_tr31_import.cbl", """
           MOVE 'TR-31   ' TO RULE-ARRAY(1).
           CALL 'CSNBT31I' USING RC RS EXIT-LEN EXIT-DATA RULE-COUNT
                RULE-ARRAY TR31-LEN TR31-BLOCK UNWRAP-KEK-ID
                WRAP-KEK-ID OUT-KEY-ID.
""", {"AES"})
    _c("cobol", "w9_cbl_racf.jcl", """
//RACFPW   JOB (ACCT),'SET PW ALG',CLASS=A
//STEP1    EXEC PGM=IKJEFT01
//SYSTSIN  DD *
  SETROPTS PASSWORD(ALGORITHM(KDFAES))
/*
""", {"AES"})
    _c("cobol", "w9_cbl_db2_tdes.sqb", """
           EXEC SQL
             INSERT INTO EMP (SSN) VALUES (ENCRYPT_TDES(:WS-SSN, :WS-PW))
           END-EXEC.
""", {"3DES"})
    # ---------------------------------------------------- COBOL negatives
    _c("cobol", "w9_neg_vsam.cbl", """
       ENVIRONMENT DIVISION.
       INPUT-OUTPUT SECTION.
       FILE-CONTROL.
           SELECT CUST-FILE ASSIGN TO CUSTVSAM
               ORGANIZATION IS INDEXED
               ACCESS MODE IS DYNAMIC
               RECORD KEY IS CUST-ID
               ALTERNATE RECORD KEY IS CUST-PAN WITH DUPLICATES
               FILE STATUS IS WS-STATUS.
       WORKING-STORAGE SECTION.
       01  WS-PASSWORD-FIELD       PIC X(8).
       01  WS-KEY-COUNT            PIC 9(4).
       PROCEDURE DIVISION.
           SEARCH ALL RATE-TABLE
               WHEN RATE-KEY (RATE-IDX) = WS-KEY-COUNT
                   MOVE RATE-VAL (RATE-IDX) TO WS-RATE
           END-SEARCH.
""", set())
    _c("cobol", "w9_neg_comment_lines.cbl", """
      * THIS PROGRAM USED TO CALL 'CSNBENC' FOR DES ENCRYPTION
      * NOW TOKENISED - SEE TOKENSVC.  RULE ARRAY WAS 'MD5     '.
       PROCEDURE DIVISION.
           MOVE WS-PAN TO WS-TOKEN-REQ.  *> CSNBOWH removed 2019
           CALL 'TOKENSVC' USING WS-TOKEN-REQ WS-TOKEN-RSP.
""", set())
    _c("cobol", "w9_neg_random_sample.cbl", """
           COMPUTE WS-SAMPLE-IDX = FUNCTION RANDOM * WS-ROW-COUNT.
           COMPUTE WS-CHECK-DIGIT = FUNCTION MOD(WS-SUM, 10).
""", set())
