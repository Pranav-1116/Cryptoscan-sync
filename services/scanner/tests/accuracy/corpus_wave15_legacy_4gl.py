"""Wave 15 — BLIND: the last uncovered bank code classes.

* HLASM (z/OS assembler) calling ICSF through the CSNB*/CSND* callable services or the
  CSFxxxx/ICSF macros (CALL, LINK, CSFPKG …), with rule arrays in DC constants.
* Informix 4GL / Genero (ENCRYPT_AES/ENCRYPT_TDES built-ins, DBMS encryption, CALL to C).
* PowerBuilder (PowerScript CrypterObject / CoderObject — SymmetricEncrypt, Hash, AsymmetricSign).
* Progress OpenEdge ABL (ENCRYPT()/DECRYPT(), SECURITY-POLICY:SYMMETRIC-ENCRYPTION-ALGORITHM,
  MESSAGE-DIGEST(), GENERATE-PBE-KEY, SSL client options).
* Tandem / HP NonStop TAL & TACL (Atalla HSM, SEEP, SAFEGUARD, TLS via SSLLIB).
* SAS (ENCRYPT=AES dataset option, PROC PWENCODE, SHA256/MD5 functions, NETENCRYPTALGORITHM).
* Thales payShield console command scripts (.hsm / console transcripts: A, GK, LK, LO, CK, EC …).

Labels come from the vendor manuals, written before any parser existed. Conventions unchanged:
rule-array literals count; comments do not; UNKNOWN never counts; PIN/CVV → 3DES; TLS floors → TLS.
"""

from __future__ import annotations


def register(_c) -> None:
    # ------------------------------------------------------------------ HLASM
    _c("hlasm", "ENCPAN.asm", """
ENCPAN   CSECT
ENCPAN   AMODE 31
ENCPAN   RMODE ANY
         STM   R14,R12,12(R13)
         LR    R12,R15
         USING ENCPAN,R12
*   Encipher the PAN under the AES DATA key (ICSF Symmetric Algorithm Encipher)
         CALL  CSNBSYE,(RETCODE,RSNCODE,EXITLEN,EXITDATA,RULECNT,       X
               RULEARR,KEYIDLEN,KEYID,KEYPARML,KEYPARM,BLKSIZE,        X
               IVLEN,IV,CHAINLEN,CHAIN,CTXTLEN,CTXT,PANLEN,PAN,        X
               OUTLEN,OUTBUF,OPTLEN,OPTDATA),VL
         LM    R14,R12,12(R13)
         BR    R14
RETCODE  DS    F
RSNCODE  DS    F
EXITLEN  DC    F'0'
EXITDATA DS    CL4
RULECNT  DC    F'3'
RULEARR  DC    CL8'AES     ',CL8'CBC     ',CL8'KEYIDENT'
KEYIDLEN DC    F'64'
KEYID    DC    CL64'CARD.PAN.AESDATA.2024'
         END   ENCPAN
""", {"AES"})
    _c("hlasm", "HASHSTMT.asm", """
HASHSTMT CSECT
*   One-way hash (SHA-256) of the statement image for the archive index
         CALL  CSNBOWH,(RC,RS,EXL,EXD,RACNT,RARR,TXTLEN,TXT,           X
               CHNLEN,CHN,HSHLEN,HSH),VL
RC       DS    F
RS       DS    F
RACNT    DC    F'2'
RARR     DC    CL8'SHA-256 ',CL8'ONLY    '
HSHLEN   DC    F'32'
HSH      DS    XL32
         END
""", {"SHA-256"})
    _c("hlasm", "PINXLAT.asm", """
PINXLAT  CSECT
*   Translate an encrypted PIN block from the ATM ZPK to the issuer ZPK
         LINK  EP=CSNBPTR,PARAM=(RC,RS,EXL,EXD,INKEY,OUTKEY,           X
               RACNT,RARR,PAN,SEQ,EPBIN,EPBOUT),VL=1
RACNT    DC    F'2'
RARR     DC    CL8'REFORMAT',CL8'ISO-0   '
INKEY    DS    XL64
OUTKEY   DS    XL64
         END
""", {"3DES"})
    _c("hlasm", "RSASIGN.asm", """
RSASIGN  CSECT
*   Digital signature generate with the PKDS RSA private key (PKCS-1.1 / SHA-256)
         CALL  CSNDDSG,(RC,RS,EXL,EXD,RACNT,RARR,KEYLEN,KEYTOK,        X
               HSHLEN,HSH,SIGLEN,SIGBITS,SIG),VL
RACNT    DC    F'2'
RARR     DC    CL8'PKCS-1.1',CL8'SHA-256 '
KEYTOK   DC    CL64'SEPA.SIGN.RSA2048'
         END
""", {"RSA", "SHA-256"})
    _c("hlasm", "COPYREC.asm", """
COPYREC  CSECT
*   Plain record copy; the old CSNBENC call was removed in 2018 (see history)
*        CALL  CSNBENC,(RC,RS,...),VL
         STM   R14,R12,12(R13)
         MVC   OUTREC(80),INREC
         LM    R14,R12,12(R13)
         BR    R14
INREC    DS    CL80
OUTREC   DS    CL80
         END
""", set(), "negative")
    _c("hlasm", "RNDKEY.asm", """
RNDKEY   CSECT
*   Random number generate for a session key seed
         CALL  CSNBRNGL,(RC,RS,EXL,EXD,RACNT,RARR,SEEDLEN,SEED,        X
               RNDLEN,RND),VL
RACNT    DC    F'1'
RARR     DC    CL8'RANDOM  '
RNDLEN   DC    F'16'
RND      DS    XL16
         END
""", {"RNG"})
    # ------------------------------------------------------------------ Informix 4GL / Genero
    _c("informix4gl", "cust_enc.4gl", """
DATABASE bankdb

FUNCTION store_card(p_cust, p_pan)
  DEFINE p_cust INTEGER, p_pan CHAR(19)
  -- column-level encryption with the Informix built-in (AES, password from the session)
  SET ENCRYPTION PASSWORD "s3cr3t-hint" WITH HINT "card"
  UPDATE card SET pan_enc = ENCRYPT_AES(p_pan) WHERE cust_id = p_cust
END FUNCTION

FUNCTION legacy_hash(p_pwd)
  DEFINE p_pwd CHAR(32)
  RETURN security.Digest.CreateDigestString(p_pwd, "SHA1")
END FUNCTION
""", {"AES", "SHA-1"})
    _c("informix4gl", "pin_tdes.4gl", """
FUNCTION encrypt_pin(p_pin)
  DEFINE p_pin CHAR(12)
  # legacy triple-DES column encryption kept for the old ATM feed
  UPDATE atm_pin SET pin_enc = ENCRYPT_TDES(p_pin, "atmkey")
END FUNCTION
""", {"3DES"})
    _c("informix4gl", "report.4gl", """
DATABASE bankdb
MAIN
  DEFINE r RECORD LIKE branch.*
  DECLARE c CURSOR FOR SELECT * FROM branch ORDER BY name
  FOREACH c INTO r.*
    DISPLAY r.name, r.balance
  END FOREACH
END MAIN
""", set(), "negative")
    # ------------------------------------------------------------------ PowerBuilder
    _c("powerbuilder", "n_crypto.sru", """
forward
global type n_crypto from nonvisualobject
end type
end forward

global type n_crypto from nonvisualobject
end type

type variables
CrypterObject inv_crypter
end variables

forward prototypes
public function blob of_encrypt (blob ablb_data, blob ablb_key)
public function string of_hash (string as_text)
end prototypes

public function blob of_encrypt (blob ablb_data, blob ablb_key);
blob lblb_iv, lblb_out
lblb_out = inv_crypter.SymmetricEncrypt(AES!, ablb_data, ablb_key, OperationModeCBC!, lblb_iv, PKCSPadding!)
return lblb_out
end function

public function string of_hash (string as_text);
blob lblb
lblb = inv_crypter.Hash(SHA256!, Blob(as_text, EncodingUTF8!))
return String(lblb, EncodingANSI!)
end function

on n_crypto.create
inv_crypter = create CrypterObject
end on
""", {"AES", "SHA-256"})
    _c("powerbuilder", "n_sign.sru", """
public function blob of_sign (blob ablb_data, blob ablb_privkey);
CrypterObject lnv
lnv = create CrypterObject
return lnv.AsymmetricSign(ablb_data, ablb_privkey, SHA1!)
end function

public function blob of_legacy (blob ablb_data, blob ablb_key);
CrypterObject lnv
lnv = create CrypterObject
return lnv.SymmetricEncrypt(TripleDES!, ablb_data, ablb_key, OperationModeECB!, lnv.GenerateIV(), PKCSPadding!)
end function
""", {"RSA", "SHA-1", "3DES"})
    _c("powerbuilder", "w_main.srw", """
forward
global type w_main from window
end type
end forward

global type w_main from window
integer width = 3000
integer height = 1800
string title = "Branch Teller"
end type

event open;
dw_accounts.SetTransObject(SQLCA)
dw_accounts.Retrieve()
end event
""", set(), "negative")
    # ------------------------------------------------------------------ Progress OpenEdge ABL
    _c("progress", "encpan.p", """
/* encpan.p - encrypt the PAN before it is written to the customer table */
DEFINE INPUT  PARAMETER pcPan AS CHARACTER NO-UNDO.
DEFINE OUTPUT PARAMETER prEnc AS RAW       NO-UNDO.
DEFINE VARIABLE rKey AS RAW NO-UNDO.

SECURITY-POLICY:SYMMETRIC-ENCRYPTION-ALGORITHM = "AES_CBC_256".
rKey = GENERATE-PBE-KEY("card-pass-phrase").
SECURITY-POLICY:SYMMETRIC-ENCRYPTION-KEY = rKey.
prEnc = ENCRYPT(pcPan).
""", {"AES", "PBKDF2"})
    _c("progress", "pwdhash.p", """
DEFINE INPUT  PARAMETER pcPwd  AS CHARACTER NO-UNDO.
DEFINE OUTPUT PARAMETER pcHash AS CHARACTER NO-UNDO.
/* legacy: MD5 without salt — flagged in the 2023 review */
pcHash = HEX-ENCODE(MESSAGE-DIGEST("MD5", pcPwd)).
""", {"MD5"})
    _c("progress", "sslclient.p", """
DEFINE VARIABLE hSocket AS HANDLE NO-UNDO.
CREATE SOCKET hSocket.
hSocket:CONNECT("-H clearing.example -S 8443 -ssl -nohostverify -sslverify 0") NO-ERROR.
""", {"TLS"})
    _c("progress", "custlist.p", """
FOR EACH customer NO-LOCK WHERE customer.balance > 1000 BY customer.name:
  DISPLAY customer.name customer.balance.
END.
""", set(), "negative")
    # ------------------------------------------------------------------ Tandem / NonStop TAL & TACL
    _c("tal", "pinver.tal", """
?SOURCE $SYSTEM.SYSTEM.EXTDECS0(FILE_OPEN_, WRITEREADX)
! PINVER - verify a PIN block through the Atalla Network Security Processor (AKB, TDES)
INT PROC verify^pin(pin^blk, akb^pek, pan);
  STRING .pin^blk, .akb^pek, .pan;
  STRING .cmd[0:255];
  BEGIN
    ! Atalla command 32: PIN verify (IBM 3624), keys under the MFK as AKBs
    cmd ':=' "<32#" & akb^pek & "#" & pin^blk & "#" & pan & "#>";
    CALL WRITEREADX(nsp^file, cmd, 128);
  END;
""", {"3DES"})
    _c("tal", "macgen.tal", """
! MACGEN - ISO 9797 retail MAC for the interchange message (Atalla command 59)
INT PROC gen^mac(msg, mak);
  STRING .msg, .mak;
  BEGIN
    cmd ':=' "<59#" & mak & "#" & msg & "#>";
    CALL WRITEREADX(nsp^file, cmd, 64);
  END;
""", {"3DES"})
    _c("tal", "TLSSETUP.tacl", """
?TACL MACRO
== Configure NonStop SSL (SSLLIB) for the FTP and Pathway listeners
PARAM SSLPROTOCOLS "TLSv1.2,TLSv1.3"
PARAM CIPHERSUITES "ECDHE-RSA-AES256-GCM-SHA384:AES128-SHA"
PARAM SERVCERT $DATA.SSLCERT.SERVER
PARAM KEYPASS "ch@nge-me"
RUN $SYSTEM.ZSSL.SSL PROXYS
""", {"TLS", "ECDH", "RSA", "AES", "SHA-384", "SHA-1"})
    _c("tal", "STARTUP.tacl", """
?TACL MACRO
== Start the pathway environment
PATHCOM $PM; START SERVER TELLER-SRV
PATHCOM $PM; START TCP TCP-TELLER
""", set(), "negative")
    # ------------------------------------------------------------------ SAS
    _c("sas", "extract.sas", """
/* nightly extract of card transactions, encrypted at rest */
libname vault "/sasdata/vault" ;
data vault.cardtx (encrypt=aes encryptkey="&vaultkey");
  set work.cardtx;
  pan_hash = put(sha256(pan), $hex64.);
  legacy_id = put(md5(cust_id), $hex32.);
run;
""", {"AES", "SHA-256", "MD5"})
    _c("sas", "connect.sas", """
options netencryptalgorithm=aes netencrypt sslcalistloc="/etc/pki/tls/certs/ca-bundle.crt";
%let db_pw = {SAS004}A34F...;
proc pwencode in='Sup3rS3cret' method=sas004;
run;
""", {"AES", "TLS", "SHA-256"})
    _c("sas", "report.sas", """
proc means data=work.branch n mean sum;
  class region;
  var balance;
run;
proc print data=work.top10; run;
""", set(), "negative")
    # ------------------------------------------------------------------ payShield console scripts
    _c("payshield-console", "keyceremony.hsm", """
; payShield 10K console session — key ceremony, LMK id 00 (variant), 3-of-3 components
A
LK
GK
3
3
N
CK
Component 1 check value: 1A2B3C
CK
Component 2 check value: 4D5E6F
CK
Component 3 check value: 7A8B9C
LO
; generate a ZMK from clear components (variant LMK, key type 000, scheme U)
GC
000
U
3
EC
""", {"3DES"})
    _c("payshield-console", "keyblock.hsm", """
; payShield console — key block LMK (AES) setup for the TR-31 migration
CS
AES
K
GK
2
2
LK
KG
key block
A
S
""", {"AES"})
    _c("payshield-console", "diag.hsm", """
; console health check only
DT
QH
NC
VR
""", set(), "negative")
