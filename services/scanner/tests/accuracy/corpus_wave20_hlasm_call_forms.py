"""Wave 20 — HLASM ICSF call forms other than ``CALL 'name'``.

NOT blind: written in the same session as the parser rules that close the
"HLASM ICSF macros other than CALL/LINK verbs, CSFxxx macro forms, ICSF ROUTINES
via SVC" gap.  Labels come from the IBM ICSF callable-service verb tables (the
same conventions as wave 15: rule-array literals count, comments do not, UNKNOWN
never counts, PIN/CVV → 3DES) and from the *statement-shape* semantics below.
They were written before the first run and were not edited afterwards.

Statement shapes under test (the label, not the scanner, is the truth here):

* macro-form invocation — the service name is the assembler mnemonic, without a
  label (``         CSNBSYE  (RC,RS,...)``) or after one (``PANPTR   CSNBPTR``).
  A service name in the *label* field followed by ``DC`` / ``DS`` / ``EQU`` is a
  definition, not a call — silence is required.
* ``LINK  EP=CSNxxx`` — the entry point named directly.
* ``LINK  EPLOC=field`` — the entry point named indirectly, resolved through
  ``field   DC   CL8'CSNxxx'`` in the same source.  Register-indirect
  ``EPLOC=(Rn)`` is deliberately NOT tracked; silence is the honest answer.
* ICSF routine via SVC — the service name in the label field of an ``SVC``
  statement (``CSNBMGN  SVC   255``).
* address-constant linkage — ``LA  R15,=V(CSNBSYG)`` with ``BALR``.  A
  ``DC  V(CSNBSYG)`` *declaration* of the same constant is not a call.
* CSFxxx macro form (PKCS#11 via ICSF, ``CSFPGKP``) with the mechanism named in
  a ``CKM_`` literal — the mechanism literal is what fixes the family.
"""


def register(_c) -> None:
    # ------------------------------------------------------------------ macro form
    _c("hlasm", "MACROPAN.asm", """
ENCPAN   CSECT
ENCPAN   AMODE 31
ENCPAN   RMODE ANY
         STM   R14,R12,12(R13)
         LR    R12,R15
         USING ENCPAN,R12
*
*000040 * macro-form call: the service name is the mnemonic, parms inline
         CSNBSYE  (RC,RSN,EXL,EXITD,RULECNT,RULEARR,KYL,KYD,KPL,KPM,  X
               BLKSZ,IVL,IV,CHL,CHN,CTL,CT,PTL,PT)
         LTR   R15,R15
         BNZ   FAIL
         LM    R14,R12,12(R13)
         BR    R14
FAIL     DS    0H
         LM    R14,R12,12(R13)
         BR    R14
RC       DS    F
RSN      DS    F
         END
""", {"AES"})

    _c("hlasm", "MACROPIN.asm", """
PINXLT   CSECT
         STM   R14,R12,12(R13)
         LR    R12,R15
*
* PIN block translate — macro-form CSNBPTR (label + mnemonic form)
*
PANPTR   CSNBPTR  (RC,RSN,FRM,PINBLK,RULECNT,RULEARR,KYL,KYD)
         LTR   R15,R15
         BNZ   FAIL2
         LM    R14,R12,12(R13)
         BR    R14
FAIL2    DS    0H
         BR    R14
         END
""", {"3DES"})

    # ------------------------------------------------------------------ LINK forms
    _c("hlasm", "LINKDSG.asm", """
SIGNIT   CSECT
         STM   R14,R12,12(R13)
         LR    R12,R15
* PKA sign — LINK with the entry point named in EP=
         LINK  EP=CSNDDSG,PARAM=(RC,RSN,EXL,EXITD,RULECNT,RULEARR,   X
               HL,HS,SKL,SKD,SGL,SG),VL
         LM    R14,R12,12(R13)
         BR    R14
RC       DS    F
RSN      DS    F
         END
""", {"RSA"})

    _c("hlasm", "EPLINK.asm", """
PINVER   CSECT
         STM   R14,R12,12(R13)
* the entry point lives in an 8-byte constant — LINK EPLOC= form
         LINK  EPLOC=SVCEP,PARAM=(RC,RSN,EXL,EXITD,PINBLK,PINCMP),VL
         LM    R14,R12,12(R13)
         BR    R14
SVCEP    DC    CL8'CSNBPVR'
         END
""", {"3DES"})

    # ------------------------------------------------------------------ ICSF routine via SVC
    _c("hlasm", "SVCMAC.asm", """
MACGEN   CSECT
         STM   R14,R12,12(R13)
* ICSF routine via SVC — the service name sits in the label field
CSNBMGN  SVC   255
         LTR   R15,R15
         LM    R14,R12,12(R13)
         BR    R14
         END
""", {"3DES"})

    # ------------------------------------------------------------------ address-constant linkage
    _c("hlasm", "BALRSYG.asm", """
KEYGNY   CSECT
         STM   R14,R12,12(R13)
* address-constant linkage to the ICSF entry point
         LA    R15,=V(CSNBSYG)
         BALR  R14,R15
         LTR   R15,R15
         LM    R14,R12,12(R13)
         BR    R14
         END
""", {"AES"})

    # ------------------------------------------------------------------ CSFxxx macro form
    _c("hlasm", "PKCSMAC.asm", """
* PKCS#11 via ICSF — macro form; the mechanism names the family
         CSFPGKP  (RC,RSN,MECH,PARML,PARM)
MECH     DC    CL16'CKM_AES_KEY_GEN'
         END
""", {"AES"})

    # ------------------------------------------------------------------ hostile negatives
    _c("hlasm", "LITDEFS.asm", """
*
* definitions, literals and comments are not calls
*
CSNBENC  DS    0H
CSNBENC  DC    CL8'CSNBENC'
KEYTOK   DC    CL8'CSNBSYE'
SERVADR  DC    V(CSNBSYG)
SYMBOL   EQU   *
LITCOPY  DC    CL32'CSNBPTR  CSNBENC   MACRO'
*        CSNBENC  (RC,RSN,EXL,EXITD)
*        LINK     EP=CSNBPTR
         BALR   R14,R15
         BR     R14
         END
""", set(), "negative")

    _c("hlasm", "SVCLABL.asm", """
* service-named entry points that are ordinary code, not calls
CSNBMGN  BR    R14
CSNBENC  STM   R14,R12,12(R13)
         B     CSNBENC
CSNBPTR  EQU   *
         LA    R3,CSNBPTR
         END
""", set(), "negative")
