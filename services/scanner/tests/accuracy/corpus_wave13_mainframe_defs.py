"""Wave 13 — BLIND: remaining mainframe surfaces in a bank estate that are *definitions*, not programs.

Software AG Natural (Adabas shops), CICS resource definitions (DFHCSDUP / RDO), z/OS AT-TLS
(Policy Agent) policy files, IMS/DB2 z/OS glue. Labels were written from the product manuals
before any parser/rule was touched; the first-pass score is recorded in accuracy_benchmark.py.

Conventions (unchanged): suite strings decompose (TLS + cipher + hash + key exchange/auth);
SSL(NO)/kill-switches are TLS decisions and count as TLS; rule-array literals declared in a
data area count (as in COBOL); comments never count; UNKNOWN never counts.
"""

from __future__ import annotations


def register(_c) -> None:
    # ------------------------------------------------------------------ Natural (Adabas)
    _c("natural", "ENCPGM.NSP", """
* ENCPGM  - encrypt customer PAN before writing to Adabas
* Uses ICSF Symmetric Algorithm Encipher (AES-CBC, CCA AES DATA key)
DEFINE DATA LOCAL
1 #RC          (I4)
1 #REASON      (I4)
1 #EXIT-DATA-L (I4)
1 #EXIT-DATA   (A4)
1 #RULE-COUNT  (I4) INIT <3>
1 #RULE-ARRAY  (A8/3) INIT <'AES     ','CBC     ','KEYIDENT'>
1 #KEY-LABEL   (A64) INIT <'CARD.PAN.AESDATA.2024'>
1 #CLEAR-PAN   (A19)
1 #ENC-PAN     (B32)
END-DEFINE
*
CALL 'CSNBSYE' #RC #REASON #EXIT-DATA-L #EXIT-DATA
     #RULE-COUNT #RULE-ARRAY #KEY-LABEL ...
IF #RC NE 0
  WRITE 'CSNBSYE failed' #RC #REASON
  TERMINATE 8
END-IF
END
""", {"AES"})
    _c("natural", "HASHSUB.NSN", """
* HASHSUB - one-way hash of a statement image for the archive index
DEFINE DATA PARAMETER
1 #IMAGE        (A) DYNAMIC
1 #DIGEST       (B32)
LOCAL
1 #RC (I4) 1 #RS (I4) 1 #EDL (I4) 1 #ED (A4)
1 #RA-COUNT     (I4) INIT <2>
1 #RA           (A8/2) INIT <'SHA-256 ','ONLY    '>
1 #CHAIN-LEN    (I4) INIT <128>
1 #CHAIN        (B128)
END-DEFINE
CALL 'CSNBOWH' #RC #RS #EDL #ED #RA-COUNT #RA
     *LENGTH(#IMAGE) #IMAGE #CHAIN-LEN #CHAIN 32 #DIGEST
END
""", {"SHA-256"})
    _c("natural", "PINVER.NSN", """
/* PINVER - verify an encrypted PIN block against the stored PVV
DEFINE DATA PARAMETER
1 #EPB       (B8)
1 #PAN       (A19)
1 #PVV       (A4)
1 #RESULT    (A1)
LOCAL
1 #RC (I4) 1 #RS (I4)
1 #RA-COUNT  (I4) INIT <1>
1 #RA        (A8) INIT <'VISA-PVV'>
1 #PIN-KEY   (A64) INIT <'ATM.PINVER.KEY'>
END-DEFINE
CALL 'CSNBPVR' #RC #RS 0 ' ' #EPB #PIN-KEY ... #RA-COUNT #RA ...
IF #RC = 0 MOVE 'Y' TO #RESULT ELSE MOVE 'N' TO #RESULT END-IF
END
""", {"3DES"})
    _c("natural", "RSASIGN.NSP", """
* RSASIGN - sign the SEPA batch hash with the bank's PKDS private key
DEFINE DATA LOCAL
1 #RC (I4) 1 #RS (I4) 1 #EDL (I4) 1 #ED (A4)
1 #RA-COUNT   (I4) INIT <2>
1 #RA         (A8/2) INIT <'PKCS-1.1','SHA-256 '>
1 #PKDS-LABEL (A64) INIT <'SEPA.SIGN.RSA2048'>
1 #HASH       (B32)
1 #SIG-LEN    (I4) INIT <256>
1 #SIG        (B256)
END-DEFINE
CALL 'CSNDDSG' #RC #RS #EDL #ED #RA-COUNT #RA
     64 #PKDS-LABEL 32 #HASH #SIG-LEN #SIG
END
""", {"RSA", "SHA-256"})
    _c("natural", "ALGCOPY.NSC", """
* ALGCOPY - shared rule-array constants for the crypto subprograms
* (copycode; INIT values are the ICSF 8-byte keywords)
1 #ALG-HASH    (A8) INIT <'SHA-1   '>
1 #ALG-MAC     (A8) INIT <'HMAC    '>
1 #KEY-TYPE    (A8) INIT <'DATA    '>
""", {"SHA-1", "HMAC", "3DES"})  # label corrected after the blind pass: CCA key type DATA is a DES/TDES data key (AES is AESDATA) — the detector was right
    _c("natural", "CUSTLIST.NSP", """
* CUSTLIST - customer listing, no cryptography here.
* (the old ENCRYPT call via CSNBENC was removed in 2019; kept for history:)
*   CALL 'CSNBENC' #RC #RS ...
DEFINE DATA LOCAL
1 CUSTOMER VIEW OF CUSTOMER-FILE
  2 CUST-ID (N8)
  2 NAME    (A30)
  2 BALANCE (P11.2)
1 #TOTAL (P13.2)
END-DEFINE
READ CUSTOMER BY CUST-ID
  ADD BALANCE TO #TOTAL
  DISPLAY CUST-ID NAME BALANCE
END-READ
WRITE 'Total' #TOTAL
END
""", set(), "negative")
    _c("natural", "PWDCHK.NSN", """
/* PWDCHK - legacy password check: home-grown hash (MD5 via ICSF one-way hash)
DEFINE DATA PARAMETER
1 #USER (A8) 1 #PWD (A8) 1 #OK (L)
LOCAL
1 #RC (I4) 1 #RS (I4) 1 #EDL (I4) 1 #ED (A4)
1 #RA-COUNT (I4) INIT <1>
1 #RA (A8) INIT <'MD5     '>
1 #CHAIN (B128) 1 #CHAIN-LEN (I4) INIT <128>
1 #DIGEST (B16)
1 #STORED (B16)
END-DEFINE
CALL 'CSNBOWH' #RC #RS #EDL #ED #RA-COUNT #RA 8 #PWD #CHAIN-LEN #CHAIN 16 #DIGEST
IF #DIGEST = #STORED THEN #OK := TRUE END-IF
END
""", {"MD5"})
    # ------------------------------------------------------------------ CICS resource definitions (DFHCSDUP / RDO)
    _c("cics", "webssl.csd", """
* CICS TS 5.6 - WEBGRP: inbound HTTPS listener and its cipher list
DEFINE TCPIPSERVICE(HTTPSSRV) GROUP(WEBGRP)
       DESCRIPTION(Internet banking HTTPS listener)
       PORTNUMBER(8443) PROTOCOL(HTTP) TRANSACTION(CWXN)
       URM(DFHWBAAX) SSL(YES) AUTHENTICATE(CERTIFICATE)
       CERTIFICATE(IBANK.SERVER.2025) CIPHERS(3535392F2F)
       MAXDATALEN(032) SOCKETCLOSE(NO)
DEFINE TCPIPSERVICE(HTTPPLAIN) GROUP(WEBGRP)
       PORTNUMBER(8080) PROTOCOL(HTTP) TRANSACTION(CWXN) SSL(NO)
""", {"TLS", "AES"})
    _c("cics", "urimap.csd", """
DEFINE URIMAP(PAYOUT) GROUP(PAYGRP)
       USAGE(CLIENT) SCHEME(HTTPS) HOST(api.clearing.example)
       PATH(/v2/payments/*) CERTIFICATE(CLEARING.CLIENT)
       CIPHERS(strongciphers.xml)
DEFINE URIMAP(STATUS) GROUP(PAYGRP)
       USAGE(SERVER) SCHEME(HTTP) PATH(/status) PROGRAM(PAYSTAT)
""", {"TLS"})
    _c("cics", "ipconn.csd", """
DEFINE IPCONN(BRANCH01) GROUP(IPICGRP)
       APPLID(CICSBR01) HOST(cicsbr01.bank.internal) PORT(1435)
       TCPIPSERVICE(IPICLSN) SSL(YES) CIPHERS(0A2F35)
       LINKAUTH(CERTUSER) USERAUTH(IDENTIFY)
""", {"TLS", "3DES", "AES"})
    _c("cics", "batchdefs.csd", """
* Nightly batch group: programs and transactions only
DEFINE PROGRAM(PAYPOST) GROUP(BATGRP) LANGUAGE(COBOL) DATALOCATION(ANY) EXECKEY(USER)
DEFINE PROGRAM(PAYSTAT) GROUP(BATGRP) LANGUAGE(LE370) CONCURRENCY(THREADSAFE)
DEFINE TRANSACTION(PPST) GROUP(BATGRP) PROGRAM(PAYPOST) TASKDATALOC(ANY) PRIORITY(1)
DEFINE FILE(PAYFILE) GROUP(BATGRP) DSNAME(PROD.PAY.KSDS) RECORDSIZE(200) KEYLENGTH(12)
       ADD(YES) BROWSE(YES) DELETE(YES) READ(YES) UPDATE(YES)
DEFINE TDQUEUE(PAYL) GROUP(BATGRP) TYPE(INTRA) ATIFACILITY(TERMINAL)
""", set(), "negative")
    _c("cics", "cicsssl.sit", """
* CICS system initialization parameters (SIT overrides) — TLS posture
APPLID=CICSPRD1,
SEC=YES,
SSLCACHE=SYSPLEX,
ENCRYPTION=STRONG,
MINTLSLEVEL=TLS12,
KEYRING=CICS.PROD.RING,
CRLPROFILE=CICSCRL,
MAXSSLTCBS=32,
""", {"TLS"})
    # ------------------------------------------------------------------ z/OS AT-TLS policy (Policy Agent)
    _c("attls", "TTLS.policy", """
## AT-TLS policy for the MQ channel initiator and the FTP server
TTLSRule                          MQCHIN_Outbound
{
  RemotePortRange                 1414
  Direction                       Outbound
  Jobname                         MQ1*CHIN
  TTLSGroupActionRef              grpAct_Enabled
  TTLSEnvironmentActionRef        envAct_MQ
}
TTLSGroupAction                   grpAct_Enabled
{
  TTLSEnabled                     On
  Trace                           2
}
TTLSEnvironmentAction             envAct_MQ
{
  HandshakeRole                   Client
  TTLSKeyringParms
  {
    Keyring                       MQ.CHIN.RING
  }
  TTLSCipherParmsRef              cipher_Strong
  TTLSEnvironmentAdvancedParmsRef envAdv_TLS12
}
TTLSCipherParms                   cipher_Strong
{
  V3CipherSuites                  TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384
  V3CipherSuites                  TLS_RSA_WITH_AES_128_CBC_SHA
  V3CipherSuites                  TLS_RSA_WITH_3DES_EDE_CBC_SHA
}
TTLSEnvironmentAdvancedParms      envAdv_TLS12
{
  SSLv3                           Off
  TLSv1                           Off
  TLSv1.1                         Off
  TLSv1.2                         On
  ClientAuthType                  Required
}
""", {"TLS", "AES", "SHA-384", "ECDH", "RSA", "SHA-1", "3DES"})
    _c("attls", "pagent.conf", """
# Policy Agent main configuration - no TLS material here, only pointers
LogLevel              15
TcpImage              TCPIP  /etc/pagent/TCPIP.image.conf FLUSH PURGE 600
ServicesConnection    Port  16311
Codepage              IBM-1047
""", set(), "negative")
    # ------------------------------------------------------------------ IMS / DB2 for z/OS glue
    _c("ims", "DFSPBPRD.proclib", """
* IMS PROCLIB member DFSPBxxx — control region parameters for IMSPRD
IMSID=IMSP,
ARMRST=Y,
DBRC=Y,
IRLM=Y,
ISIS=R,
RCLASS=IMSP,
SGN=Z,
* IMS Connect security: RACF PassTicket verification for OTMA clients
TRN=F,
""", set(), "negative")
    _c("ims", "HWSCFGPR.proclib", """
* IMS Connect configuration member (HWSCFGxx) with an SSL-enabled port
HWS   (ID=HWSPRD,RACF=Y,XIBAREA=20)
TCPIP (HOSTNAME=TCPIP,RACFID=IMSCON,PORTID=(9999,LOCAL),
       PORT=(ID=9998,KEEPAV=1),
       SSLPORT=(ID=9443,KEEPAV=1),
       SSLENVAR=HWSCFGSSL,MAXSOC=2000,TIMEOUT=8800,EXIT=(HWSSMPL1))
DATASTORE (ID=IMSP,GROUP=XCFGRP,MEMBER=HWSPRD,TMEMBER=IMSP,DRU=HWSYDRU0)
""", {"TLS"})
    _c("cobol", "PANENC.cbl", """
       IDENTIFICATION DIVISION.
       PROGRAM-ID. PANENC.
      * DB2 for z/OS column encryption - legacy TDES built-in on the PAN column
       DATA DIVISION.
       WORKING-STORAGE SECTION.
       01  WS-PAN            PIC X(19).
       01  WS-ENC-PAN        PIC X(64).
       PROCEDURE DIVISION.
           EXEC SQL
             SET ENCRYPTION PASSWORD = :WS-PWD
           END-EXEC.
           EXEC SQL
             UPDATE CARD SET PAN_ENC = ENCRYPT_TDES(:WS-PAN)
              WHERE CARD_ID = :WS-ID
           END-EXEC.
           GOBACK.
""", {"3DES"})
