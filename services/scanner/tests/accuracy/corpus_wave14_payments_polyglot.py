"""Wave 14 — BLIND: payments / HSM idioms outside Java.

Wave 8 covered jPOS + payShield + PKCS#11 in Java. Bank estates also drive HSMs from C#
(.NET switch front-ends), Python (key-ceremony tooling, test harnesses), Go (modern
acquiring services), C (legacy terminal/host code) and Node (payment gateways).
Labels written from the protocols (payShield host commands, X9.24 DUKPT, ISO 9797 MAC,
TR-31, PKCS#11 mechanisms) before any rule was touched.

Conventions: PIN block / CVV / DUKPT / retail MAC → 3DES; TR-31 key block → AES;
payShield E* RSA family → RSA; PKCS#11 CKM_* → mechanism algorithm; KCV → 3DES;
two-letter command codes count only inside an HSM client (file context); UNKNOWN never counts.
"""

from __future__ import annotations


def register(_c) -> None:
    # ------------------------------------------------------------------ C#
    _c("csharp", "w14_PayShieldClient.cs", """
using System.Net.Sockets;
using System.Text;

namespace Switch.Hsm
{
    /// <summary>Thales payShield 10K host-command client (variant LMK).</summary>
    public sealed class PayShieldClient
    {
        private readonly TcpClient _tcp;
        public PayShieldClient(TcpClient tcp) { _tcp = tcp; }

        public string GenerateZpk(string zmkUnderLmk)
        {
            // A0: generate a key (mode 1 = under ZMK), key type 001 = ZPK, scheme U
            var cmd = "HDR0" + "A0" + "1" + "001" + "U" + zmkUnderLmk;
            return Send(cmd);
        }

        public string TranslatePin(string pinBlock, string zpkSrc, string zpkDst)
        {
            var cmd = "HDR0" + "CC" + zpkSrc + zpkDst + "12" + pinBlock + "01" + "01";
            return Send(cmd);
        }

        private string Send(string command) { /* length-prefixed write */ return command; }
    }
}
""", {"3DES"})
    _c("csharp", "w14_Dukpt.cs", """
namespace Terminal.Crypto
{
    public static class DukptTdes
    {
        // ANSI X9.24-1: derive the IPEK from the BDK and the initial KSN
        public static byte[] DeriveIpek(byte[] bdk, byte[] ksn)
        {
            var ksnMasked = new byte[8];
            System.Array.Copy(ksn, ksnMasked, 8);
            ksnMasked[7] &= 0xE0;
            return EncryptTdes(bdk, ksnMasked);
        }

        public static byte[] PinKey(byte[] ipek, byte[] ksn) => DeriveWorkingKey(ipek, ksn, 0x00FF00FF00FF00FF);

        private static byte[] EncryptTdes(byte[] k, byte[] d) => d;
        private static byte[] DeriveWorkingKey(byte[] k, byte[] ksn, ulong variant) => k;
    }
}
""", {"3DES"})
    _c("csharp", "w14_Tr31.cs", """
namespace Switch.Keys
{
    public sealed class Tr31KeyBlock
    {
        public string Version { get; } = "D";   // TR-31 version D: AES key-block protection key
        public string Usage { get; } = "P0";    // PIN encryption key
        public byte[] Wrap(byte[] kbpk, byte[] key) { /* KBEK/KBMK derived from the KBPK */ return key; }
    }
}
""", {"AES"})
    _c("csharp", "w14_neg_statuscodes.cs", """
namespace Ui.Theme
{
    public static class Codes
    {
        public const string Ok = "A0";      // grid cell colour code, not an HSM command
        public const string Warn = "CC";
        public static string Blend(string a, string b) => a + b;
    }
}
""", set(), "negative")
    # ------------------------------------------------------------------ Python
    _c("python", "w14_payshield_ceremony.py", """
import socket

HEADER = b"0000"


class PayShield:
    \"\"\"Thin payShield host-command wrapper used by the key-ceremony tooling.\"\"\"

    def __init__(self, host: str, port: int = 1500):
        self.sock = socket.create_connection((host, port))

    def _send(self, body: bytes) -> bytes:
        frame = HEADER + body
        self.sock.sendall(len(frame).to_bytes(2, "big") + frame)
        return self.sock.recv(4096)

    def generate_key(self, key_type: str = "001", scheme: str = "U") -> bytes:
        return self._send(b"A0" + b"0" + key_type.encode() + scheme.encode())

    def generate_rsa_keypair(self, bits: int = 2048) -> bytes:
        return self._send(b"EI" + b"1" + str(bits).zfill(4).encode() + b"01")

    def kcv(self, key_under_lmk: bytes) -> bytes:
        return self._send(b"BU" + b"001" + b"0" + key_under_lmk)
""", {"3DES", "RSA"})
    _c("python", "w14_iso9797_mac.py", """
from Crypto.Cipher import DES3


def retail_mac(key: bytes, data: bytes) -> bytes:
    \"\"\"ISO 9797-1 MAC algorithm 3 (retail MAC): single-DES CBC over the message, TDES on the last block.\"\"\"
    padded = data + b"\\x80" + b"\\x00" * ((8 - (len(data) + 1) % 8) % 8)
    left, right = key[:8], key[8:16]
    from Crypto.Cipher import DES
    c = DES.new(left, DES.MODE_CBC, iv=b"\\x00" * 8)
    x = c.encrypt(padded)[-8:]
    d = DES.new(right, DES.MODE_ECB).decrypt(x)
    return DES.new(left, DES.MODE_ECB).encrypt(d)


def cmac_ish(key: bytes, data: bytes) -> bytes:
    return DES3.new(key, DES3.MODE_CBC, iv=b"\\x00" * 8).encrypt(data)[-8:]
""", {"DES", "3DES"})
    _c("python", "w14_pkcs11_sign.py", """
import pkcs11
from pkcs11 import Mechanism, KeyType, ObjectClass

lib = pkcs11.lib("/opt/nfast/toolkits/pkcs11/libcknfast.so")
token = lib.get_token(token_label="PAYMENTS")


def sign_batch(pin: str, payload: bytes) -> bytes:
    with token.open(user_pin=pin) as session:
        priv = session.get_key(object_class=ObjectClass.PRIVATE_KEY, label="sepa-signing")
        return priv.sign(payload, mechanism=Mechanism.SHA256_RSA_PKCS_PSS)


def wrap_zpk(pin: str, zpk) -> bytes:
    with token.open(user_pin=pin) as session:
        kek = session.get_key(key_type=KeyType.AES, label="zone-kek")
        return kek.wrap_key(zpk, mechanism=Mechanism.AES_KEY_WRAP_PAD)
""", {"RSA", "SHA-256", "AES"})
    _c("python", "w14_neg_ksn_abbrev.py", """
# Kansas (KS) / Nebraska (NE) branch routing table — 'ksn' here is a state-network code
BRANCHES = {"ksn": ["Wichita", "Topeka"], "nen": ["Omaha"]}


def route(state_code: str) -> list[str]:
    return BRANCHES.get(state_code, [])
""", set(), "negative")
    # ------------------------------------------------------------------ Go
    _c("go", "w14_dukpt.go", """
package dukpt

import "crypto/des"

// DeriveIPEK implements ANSI X9.24-1 initial PIN encryption key derivation from a BDK and KSN.
func DeriveIPEK(bdk, ksn []byte) ([]byte, error) {
	masked := make([]byte, 8)
	copy(masked, ksn[:8])
	masked[7] &= 0xE0
	block, err := des.NewTripleDESCipher(append(bdk, bdk[:8]...))
	if err != nil {
		return nil, err
	}
	out := make([]byte, 8)
	block.Encrypt(out, masked)
	return out, nil
}
""", {"3DES"})
    _c("go", "w14_payshield.go", """
package hsm

import (
	"fmt"
	"net"
)

// PayShield is a minimal Thales payShield host-command client.
type PayShield struct{ conn net.Conn }

func (p *PayShield) send(cmd string) (string, error) {
	frame := fmt.Sprintf("%04d0000%s", len(cmd)+4, cmd)
	_, err := p.conn.Write([]byte(frame))
	return "", err
}

// GenerateCVV runs the CW command (CVV generation under a CVK pair).
func (p *PayShield) GenerateCVV(cvk, pan, expiry, svc string) (string, error) {
	return p.send("CW" + cvk + pan + ";" + expiry + svc)
}

// ImportKeyBlock runs the A6 command with a TR-31 key block (scheme S, AES LMK).
func (p *PayShield) ImportKeyBlock(kb string) (string, error) {
	return p.send("A6" + "001" + kb + "S")
}
""", {"3DES", "AES"})
    _c("go", "w14_neg_grid.go", """
package grid

// cell codes for the branch floor plan renderer
const (
	Desk   = "A0"
	Teller = "CC"
	Vault  = "CW"
)

func Label(code string) string { return "cell-" + code }
""", set(), "negative")
    # ------------------------------------------------------------------ C
    _c("c", "w14_pinblock.c", """
#include <string.h>
#include <openssl/des.h>

/* ISO 9564 format 0 PIN block, encrypted under the terminal PIN key (TPK) with TDES */
int encrypt_pin_block(const unsigned char tpk[16], const unsigned char clear_pb[8], unsigned char out[8])
{
    DES_key_schedule k1, k2;
    DES_set_key_unchecked((const_DES_cblock *)tpk, &k1);
    DES_set_key_unchecked((const_DES_cblock *)(tpk + 8), &k2);
    DES_ecb2_encrypt((const_DES_cblock *)clear_pb, (DES_cblock *)out, &k1, &k2, DES_ENCRYPT);
    return 0;
}
""", {"3DES"})
    _c("c", "w14_hsm_cmd.c", """
#include <stdio.h>
#include <string.h>

/* Thales payShield host command builder (legacy acquiring host) */
static int hsm_send(int fd, const char *cmd, size_t len);

int hsm_translate_pin(int fd, const char *zpk_src, const char *zpk_dst, const char *pin_block)
{
    char cmd[512];
    int n = snprintf(cmd, sizeof cmd, "0000%s%s%s%s%s", "CC", zpk_src, zpk_dst, "12", pin_block);
    return hsm_send(fd, cmd, (size_t)n);
}

int hsm_generate_rsa(int fd)
{
    char cmd[64];
    int n = snprintf(cmd, sizeof cmd, "0000%s%s", "EI", "12048");
    return hsm_send(fd, cmd, (size_t)n);
}
""", {"3DES", "RSA"})
    # ------------------------------------------------------------------ JS / TS
    _c("typescript", "w14_payshield.ts", """
import net from "node:net";

/** Thales payShield host-command session used by the payment gateway. */
export class PayShieldSession {
  constructor(private readonly sock: net.Socket) {}

  private send(cmd: string): Promise<string> {
    const frame = Buffer.from("0000" + cmd, "ascii");
    const len = Buffer.alloc(2);
    len.writeUInt16BE(frame.length);
    this.sock.write(Buffer.concat([len, frame]));
    return Promise.resolve("");
  }

  generateKey(keyType = "001") { return this.send("A0" + "0" + keyType + "U"); }
  verifyCvv(cvk: string, pan: string, cvv: string) { return this.send("CY" + cvk + cvv + pan); }
  arqc(mkac: string, pan: string, data: string) { return this.send("KQ" + "0" + "0" + mkac + pan + data); }
}
""", {"3DES"})
    _c("javascript", "w14_kcv.js", """
const crypto = require("crypto");

// Key check value: encrypt 8 zero bytes under the TDES key, keep 3 bytes
function keyCheckValue(key) {
  const c = crypto.createCipheriv("des-ede3", key, null).setAutoPadding(false);
  return Buffer.concat([c.update(Buffer.alloc(8)), c.final()]).subarray(0, 3).toString("hex").toUpperCase();
}

module.exports = { keyCheckValue };
""", {"3DES"})
    _c("javascript", "w14_neg_seatmap.js", """
// Seat map codes for the branch appointment kiosk
const SEATS = { A0: "window", CC: "aisle", KQ: "queue" };
export function seat(code) { return SEATS[code] ?? "unknown"; }
""", set(), "negative")
