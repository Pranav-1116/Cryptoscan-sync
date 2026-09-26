"""Hard ground-truth corpus for the production source scanner.

Each case is (language, filename, code, expected_families, category).

* ``expected_families`` is the set of canonical algorithm *families* that a
  correct scanner must report for the file (see ``canonical_family``).  An
  empty set means the file contains **no** cryptography and anything reported
  is a false positive.
* ``category`` is one of ``positive`` (ordinary real-world usage),
  ``negative`` (hard look-alikes: checksums, encodings, identifiers that merely
  contain "sha"/"des"/"rsa", comments, docs), ``obfuscated`` (split strings,
  aliasing, indirection, unusual casing) and ``config`` (non-code files).

Labels are truth, not scanner echoes: when a snippet legitimately uses two
primitives (HMAC over SHA-256, RSA-OAEP with SHA-1 MGF) both are listed.
Nothing here is generated from scanner output.
"""
from __future__ import annotations

import re

# --------------------------------------------------------------------------- canonical families
_ALIASES = {
    "DESEDE": "3DES", "TRIPLEDES": "3DES", "TDEA": "3DES", "3DES": "3DES", "DES3": "3DES", "TDESEDE3": "3DES",
    "ARC4": "RC4", "RC4": "RC4", "ARCFOUR": "RC4",
    "ARC2": "RC2", "RC2": "RC2",
    "SHA1": "SHA-1",
    "SHA224": "SHA-224", "SHA256": "SHA-256", "SHA384": "SHA-384", "SHA512": "SHA-512",
    "SHA3256": "SHA3", "SHA3512": "SHA3", "SHA3": "SHA3", "KECCAK256": "SHA3", "SHAKE128": "SHA3", "SHAKE256": "SHA3",
    "MD5": "MD5", "MD4": "MD4", "MD2": "MD2", "RIPEMD160": "RIPEMD",
    "BLAKE2B": "BLAKE2", "BLAKE2S": "BLAKE2", "BLAKE2": "BLAKE2", "BLAKE3": "BLAKE3",
    "AES": "AES", "AES128": "AES", "AES192": "AES", "AES256": "AES", "RIJNDAEL": "AES", "AESGCM": "AES", "AESCBC": "AES",
    "CHACHA20POLY1305": "CHACHA20", "CHACHA20": "CHACHA20", "XCHACHA20POLY1305": "CHACHA20", "XCHACHA20": "CHACHA20",
    "XSALSA20POLY1305": "SALSA20", "SALSA20": "SALSA20", "SECRETBOX": "SALSA20",
    "DES": "DES", "BLOWFISH": "BLOWFISH", "CAST5": "CAST5", "IDEA": "IDEA", "TWOFISH": "TWOFISH", "CAMELLIA": "CAMELLIA", "SEED": "SEED",
    "RSA": "RSA", "RSAOAEP": "RSA", "RSAPSS": "RSA", "RSAPKCS1": "RSA",
    "ECDSA": "ECDSA", "ECDH": "ECDH", "ECDHE": "ECDH", "EC": "ECDSA", "ECIES": "ECIES",
    "ED25519": "ED25519", "EDDSA": "ED25519", "ED448": "ED25519",
    "X25519": "X25519", "CURVE25519": "X25519", "X448": "X25519",
    "DSA": "DSA", "DH": "DH", "DIFFIEHELLMAN": "DH",
    "HMAC": "HMAC", "HMACSHA1": "HMAC", "HMACSHA256": "HMAC", "HMACSHA512": "HMAC", "HMACSHA384": "HMAC", "HMACMD5": "HMAC",
    "CMAC": "CMAC", "AESCMAC": "CMAC", "GMAC": "GMAC",
    "PBKDF2": "PBKDF2", "PBKDF2WITHHMACSHA256": "PBKDF2", "PBKDF2WITHHMACSHA1": "PBKDF2", "PBKDF2HMAC": "PBKDF2",
    "BCRYPT": "BCRYPT", "SCRYPT": "SCRYPT", "ARGON2": "ARGON2", "ARGON2ID": "ARGON2", "ARGON2I": "ARGON2", "HKDF": "HKDF",
    "TLS": "TLS", "TLS10": "TLS", "TLS11": "TLS", "TLS12": "TLS", "TLS13": "TLS", "SSLV3": "TLS", "SSLV2": "TLS", "SSL": "TLS",
    "TLSUNVERIFIED": "TLS", "TLSCIPHERS": "TLS", "TRUSTALL": "TLS", "SSH": "SSH", "SSHHOSTKEYNONE": "SSH", "X509": "X509", "OCSP": "X509",
    "CSPRNG": "RNG", "PRNG": "RNG", "SHA1PRNG": "RNG", "SECURERANDOM": "RNG", "RNG": "RNG",
    "JWT": "JWT", "HS256": "JWT", "HS384": "JWT", "HS512": "JWT", "RS256": "JWT", "RS384": "JWT", "RS512": "JWT", "PS256": "JWT", "PS384": "JWT", "PS512": "JWT", "ES256": "JWT", "ES384": "JWT", "ES512": "JWT", "ES256K": "JWT", "JWTNONE": "JWT",
    "MLKEM": "MLKEM", "MLKEM768": "MLKEM", "KYBER": "MLKEM", "MLDSA": "MLDSA", "DILITHIUM": "MLDSA", "SLHDSA": "SLHDSA", "SPHINCS": "SLHDSA",
    "WEBCRYPTO": "WEBCRYPTO",
}


def canonical_family(name: str | None) -> str | None:
    """Map one algorithm spelling to a family (whole-name match, then safe prefixes)."""
    if not name:
        return None
    key = re.sub(r"[^A-Z0-9]", "", str(name).upper())
    if not key or key == "UNKNOWN":
        return None
    if key == "SHA":  # Java MessageDigest.getInstance("SHA") is SHA-1
        return "SHA-1"
    if key in _ALIASES:
        return _ALIASES[key]
    # prefix matches only for size/mode-suffixed spellings the scanner emits as
    # a single field (AES-256-GCM, RSA-2048, TLS1.2 ...). Short ambiguous
    # prefixes (DES, SHA, EC) are deliberately NOT here.
    for prefix in ("HMAC", "PBKDF2", "XCHACHA20", "CHACHA20", "XSALSA20", "AES", "RSA", "ECDSA", "ECDH", "SHA3", "SHA512", "SHA384", "SHA256", "SHA224", "SHA1", "MD5", "TLS", "ARGON2", "BLAKE2", "ED25519", "X25519", "3DES", "RC4", "BCRYPT", "SCRYPT", "HKDF"):
        if key.startswith(prefix):
            return _ALIASES.get(prefix, prefix)
    return key


_SPLIT = re.compile(r"WITH|AND|[^A-Z0-9]+")


def canonical_families(name: str | None) -> set[str]:
    """Decompose a composite spelling into every family it names.

    ``HmacSHA256`` -> {HMAC, SHA-256}; ``SHA256withRSA`` -> {SHA-256, RSA};
    ``RSA/ECB/OAEPWithSHA-256AndMGF1Padding`` -> {RSA, SHA-256};
    ``PBKDF2WithHmacSHA1`` -> {PBKDF2, HMAC, SHA-1}.  Component tokens must be
    *exact* alias-table entries — a token like DESCRIPTION never maps to DES.
    """
    out: set[str] = set()
    whole = canonical_family(name)
    if whole:
        out.add(whole)
    if not name:
        return out
    # glue size suffixes back on before splitting: SHA-256 -> SHA256, TLS1.2 -> TLS12
    upper = re.sub(r"(?<=[A-Z])[-_./](?=\d)", "", str(name).upper())
    upper = re.sub(r"(?<=\d)[-_./](?=\d)", "", upper)
    for tok in _SPLIT.split(upper):
        tok = re.sub(r"[^A-Z0-9]", "", tok)
        if not tok:
            continue
        if tok.startswith("HMAC") and tok[4:] in _ALIASES:        # HMACSHA256
            out.update({"HMAC", _ALIASES[tok[4:]]})
        elif tok.startswith("PBKDF2") and tok[6:] in _ALIASES:    # PBKDF2SHA256
            out.update({"PBKDF2", _ALIASES[tok[6:]]})
        elif tok.startswith("PBKDF2HMAC") and tok[10:] in _ALIASES:
            out.update({"PBKDF2", "HMAC", _ALIASES[tok[10:]]})
        elif tok in _ALIASES:
            out.add(_ALIASES[tok])
    return out


_BARE_SPEC = re.compile(r"^[A-Za-z0-9/_\-.:+]+$")


def spec_families(raw_transformation: str | None) -> set[str]:
    """Families named inside a *bare* algorithm spec string such as the JCA
    transformation ``RSA/ECB/OAEPWithSHA-256AndMGF1Padding`` or
    ``PBKDF2WithHmacSHA1``.  Anything containing spaces, parentheses or quotes
    (i.e. regex match text) is ignored so this never scores incidental words."""
    if not raw_transformation or not _BARE_SPEC.match(raw_transformation):
        return set()
    out: set[str] = set()
    upper = re.sub(r"(?<=[A-Z])[-_./](?=\d)", "", raw_transformation.upper())
    for tok in _SPLIT.split(upper):
        tok = re.sub(r"[^A-Z0-9]", "", tok)
        if not tok:
            continue
        if tok.startswith("HMAC") and tok[4:] in _ALIASES:
            out.update({"HMAC", _ALIASES[tok[4:]]})
        elif tok in _ALIASES:
            out.add(_ALIASES[tok])
    return out


# --------------------------------------------------------------------------- cases
# (language, filename, code, expected_families, category)
CASES: list[tuple[str, str, str, set[str], str]] = []


def _c(lang: str, fname: str, code: str, expected: set[str], category: str = "positive") -> None:
    CASES.append((lang, fname, code.strip("\n") + "\n", set(expected), category))


# ===================================================================== PYTHON
_c("python", "p_hashlib_md5.py", """
import hashlib

def fingerprint(payload: bytes) -> str:
    return hashlib.md5(payload).hexdigest()
""", {"MD5"})
_c("python", "p_hashlib_new.py", """
import hashlib
digest = hashlib.new("sha1")
digest.update(b"abc")
print(digest.hexdigest())
""", {"SHA-1"})
_c("python", "p_hashlib_sha256_pbkdf2.py", """
import hashlib, os
salt = os.urandom(16)
dk = hashlib.pbkdf2_hmac("sha256", password.encode(), salt, 100_000)
""", {"PBKDF2", "SHA-256", "RNG"})
_c("python", "p_cryptography_aes_gcm.py", """
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

def encrypt(key: bytes, iv: bytes, data: bytes) -> bytes:
    cipher = Cipher(algorithms.AES(key), modes.GCM(iv), backend=default_backend())
    enc = cipher.encryptor()
    return enc.update(data) + enc.finalize()
""", {"AES"})
_c("python", "p_cryptography_aesgcm_class.py", """
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
aesgcm = AESGCM(AESGCM.generate_key(bit_length=256))
chacha = ChaCha20Poly1305(ChaCha20Poly1305.generate_key())
""", {"AES", "CHACHA20"})
_c("python", "p_cryptography_rsa.py", """
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes

private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
sig = private_key.sign(b"msg", padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=32), hashes.SHA256())
""", {"RSA", "SHA-256"})
_c("python", "p_cryptography_ec.py", """
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.hazmat.primitives import hashes
key = ec.generate_private_key(ec.SECP256R1())
signature = key.sign(b"data", ec.ECDSA(hashes.SHA256()))
""", {"ECDSA", "SHA-256"})
_c("python", "p_cryptography_x25519_hkdf.py", """
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives import hashes
shared = X25519PrivateKey.generate().exchange(peer_public)
key = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=b"h").derive(shared)
""", {"X25519", "HKDF", "SHA-256"})
_c("python", "p_cryptography_ed25519.py", """
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
sk = Ed25519PrivateKey.generate()
sig = sk.sign(b"payload")
""", {"ED25519"})
_c("python", "p_cryptography_3des_legacy.py", """
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
cipher = Cipher(algorithms.TripleDES(key), modes.CBC(iv))
""", {"3DES"})
_c("python", "p_cryptography_hmac.py", """
from cryptography.hazmat.primitives import hashes, hmac
h = hmac.HMAC(key, hashes.SHA512())
h.update(b"message")
tag = h.finalize()
""", {"HMAC", "SHA-512"})
_c("python", "p_hmac_stdlib.py", """
import hmac, hashlib
mac = hmac.new(secret, msg, hashlib.sha256).hexdigest()
if not hmac.compare_digest(mac, expected):
    raise ValueError("bad mac")
""", {"HMAC", "SHA-256"})
_c("python", "p_pycryptodome_aes.py", """
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
key = get_random_bytes(32)
cipher = AES.new(key, AES.MODE_EAX)
ct, tag = cipher.encrypt_and_digest(data)
""", {"AES", "RNG"})
_c("python", "p_pycryptodome_arc4.py", """
from Crypto.Cipher import ARC4
stream = ARC4.new(b"legacy-key")
out = stream.encrypt(plaintext)
""", {"RC4"})
_c("python", "p_pycryptodome_des_blowfish.py", """
from Crypto.Cipher import DES, Blowfish
c1 = DES.new(k8, DES.MODE_ECB)
c2 = Blowfish.new(k16, Blowfish.MODE_CBC, iv)
""", {"DES", "BLOWFISH"})
_c("python", "p_pycryptodome_rsa_pkcs1.py", """
from Crypto.PublicKey import RSA
from Crypto.Cipher import PKCS1_OAEP
key = RSA.generate(3072)
enc = PKCS1_OAEP.new(key.publickey()).encrypt(secret)
""", {"RSA"})
_c("python", "p_pycryptodome_hash.py", """
from Crypto.Hash import SHA256, MD5
h = SHA256.new(data=b"x")
legacy = MD5.new(b"y").hexdigest()
""", {"SHA-256", "MD5"})
_c("python", "p_bcrypt_argon2.py", """
import bcrypt
from argon2 import PasswordHasher
hashed = bcrypt.hashpw(pw.encode(), bcrypt.gensalt(rounds=12))
ph = PasswordHasher()
h2 = ph.hash(pw)
""", {"BCRYPT", "ARGON2"})
_c("python", "p_pyjwt.py", """
import jwt
token = jwt.encode({"sub": "u1"}, SECRET, algorithm="HS256")
claims = jwt.decode(token, SECRET, algorithms=["HS256"])
""", {"JWT"})
_c("python", "p_nacl.py", """
import nacl.secret, nacl.utils
box = nacl.secret.SecretBox(nacl.utils.random(nacl.secret.SecretBox.KEY_SIZE))
ct = box.encrypt(b"hi")
""", {"SALSA20", "RNG"})
_c("python", "p_ssl_context.py", """
import ssl
ctx = ssl.SSLContext(ssl.PROTOCOL_TLSv1)
ctx.check_hostname = False
ctx.verify_mode = ssl.CERT_NONE
""", {"TLS"})
_c("python", "p_paramiko_ssh.py", """
import paramiko
key = paramiko.RSAKey.generate(2048)
client = paramiko.SSHClient()
client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
""", {"RSA", "SSH"})
_c("python", "p_secrets_random.py", """
import secrets, random
token = secrets.token_hex(32)
weak = random.random()  # not for keys
""", {"RNG"})
_c("python", "p_fernet.py", """
from cryptography.fernet import Fernet
f = Fernet(Fernet.generate_key())
ct = f.encrypt(b"secret")
""", {"AES", "HMAC", "SHA-256"})
_c("python", "p_dsa_dh.py", """
from cryptography.hazmat.primitives.asymmetric import dsa, dh
params = dh.generate_parameters(generator=2, key_size=2048)
dsa_key = dsa.generate_private_key(key_size=2048)
""", {"DSA", "DH"})

# python — hard negatives
_c("python", "n_identifiers.py", """
# The DESCRIPTOR describes the shape; nothing cryptographic here.
sha = repo.head.commit.hexsha
dorsal_rsa_index = 3
md5sum_path = "/usr/bin/md5sum"
desired_shape = (1, 2)
class Shader: pass
aesthetic = "minimal"
""", set(), "negative")
_c("python", "n_checksums_encodings.py", """
import zlib, base64, uuid, binascii
crc = zlib.crc32(payload)
b64 = base64.b64encode(payload)
u = uuid.uuid4()
hexed = binascii.hexlify(payload)
adler = zlib.adler32(payload)
""", set(), "negative")
_c("python", "n_hash_builtin.py", """
class Point:
    def __hash__(self):
        return hash((self.x, self.y))
lookup = {hash("k"): 1}
import hashlib_shim  # a local module with an unfortunate name that only wraps json
""", set(), "negative")
_c("python", "n_docstrings.py", '''
def rotate(data):
    """Rotate the list. Note: this is NOT encryption, despite what the
    old comment said about "AES" and "RSA" — see ticket SEC-1 for the
    reason SHA-256 is referenced in the design doc."""
    return data[1:] + data[:1]
''', set(), "negative")
_c("python", "n_dataclass_fields.py", """
from dataclasses import dataclass
@dataclass
class Cert:
    sha256_fingerprint: str   # a stored string, no hashing performed here
    rsa_bits: int
    des_cription: str
""", set(), "negative")
_c("python", "n_pandas.py", """
import pandas as pd
df = pd.read_csv("keys.csv")
df["hash"] = df["id"].apply(lambda v: v * 31)
df.describe()
""", set(), "negative")

# python — obfuscated / indirect
_c("python", "o_getattr_hashlib.py", """
import hashlib
algo = "md" + "5"
h = getattr(hashlib, algo)(data).hexdigest()
""", {"MD5"}, "obfuscated")
_c("python", "o_alias_import.py", """
import hashlib as hl
from Crypto.Cipher import AES as _A
d = hl.sha1(b"x").digest()
c = _A.new(k, _A.MODE_CBC, iv)
""", {"SHA-1", "AES"}, "obfuscated")
_c("python", "o_hashlib_new_var.py", """
import hashlib
name = config.get("digest", "sha512")
h = hashlib.new(name)
""", {"SHA-512"}, "obfuscated")
_c("python", "o_importlib.py", """
import importlib
mod = importlib.import_module("Crypto.Cipher.ARC4")
c = mod.new(key)
""", {"RC4"}, "obfuscated")

# ===================================================================== JAVA
_c("java", "J_CipherDesede.java", """
import javax.crypto.Cipher;
public class Legacy {
    Cipher make() throws Exception {
        return Cipher.getInstance("DESede/CBC/PKCS5Padding");
    }
}
""", {"3DES"})
_c("java", "J_CipherAesGcm.java", """
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
public class Enc {
    byte[] run(byte[] key, byte[] iv, byte[] pt) throws Exception {
        Cipher c = Cipher.getInstance("AES/GCM/NoPadding");
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(key, "AES"), new GCMParameterSpec(128, iv));
        return c.doFinal(pt);
    }
}
""", {"AES"})
_c("java", "J_CipherRsaOaep.java", """
public class Wrap {
    Cipher c = Cipher.getInstance("RSA/ECB/OAEPWithSHA-256AndMGF1Padding");
}
""", {"RSA", "SHA-256"})
_c("java", "J_MessageDigest.java", """
import java.security.MessageDigest;
class H {
    byte[] d(byte[] in) throws Exception {
        MessageDigest md = MessageDigest.getInstance("SHA-1");
        return md.digest(in);
    }
}
""", {"SHA-1"})
_c("java", "J_KeyPairRsa.java", """
import java.security.KeyPairGenerator;
class K {
    KeyPair gen() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(1024);
        return kpg.generateKeyPair();
    }
}
""", {"RSA"})
_c("java", "J_KeyPairEc.java", """
KeyPairGenerator g = KeyPairGenerator.getInstance("EC");
g.initialize(new ECGenParameterSpec("secp256r1"));
Signature s = Signature.getInstance("SHA256withECDSA");
""", {"ECDSA", "SHA-256"})
_c("java", "J_Mac.java", """
import javax.crypto.Mac;
class M {
    byte[] tag(byte[] k, byte[] m) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA256");
        mac.init(new SecretKeySpec(k, "HmacSHA256"));
        return mac.doFinal(m);
    }
}
""", {"HMAC", "SHA-256"})
_c("java", "J_Pbkdf2.java", """
SecretKeyFactory f = SecretKeyFactory.getInstance("PBKDF2WithHmacSHA1");
PBEKeySpec spec = new PBEKeySpec(pw, salt, 65536, 256);
""", {"PBKDF2", "HMAC", "SHA-1"})
_c("java", "J_SecureRandom.java", """
SecureRandom sr = SecureRandom.getInstance("SHA1PRNG");
sr.setSeed(42L);
byte[] iv = new byte[16];
sr.nextBytes(iv);
""", {"RNG"})
_c("java", "J_KeyGeneratorDes.java", """
KeyGenerator kg = KeyGenerator.getInstance("DES");
kg.init(56);
SecretKey k = kg.generateKey();
""", {"DES"})
_c("java", "J_SignatureRsa.java", """
Signature sig = Signature.getInstance("SHA1withRSA");
sig.initSign(privateKey);
sig.update(data);
""", {"RSA", "SHA-1"})
_c("java", "J_Blowfish.java", """
Cipher c = Cipher.getInstance("Blowfish");
c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(k, "Blowfish"));
""", {"BLOWFISH"})
_c("java", "J_SslContext.java", """
import javax.net.ssl.SSLContext;
SSLContext ctx = SSLContext.getInstance("TLSv1");
ctx.init(null, new TrustManager[]{ new X509TrustManager() {
    public void checkServerTrusted(X509Certificate[] c, String a) {}
    public void checkClientTrusted(X509Certificate[] c, String a) {}
    public X509Certificate[] getAcceptedIssuers() { return null; }
}}, null);
""", {"TLS"})
_c("java", "J_BouncyCastle.java", """
import org.bouncycastle.crypto.engines.AESEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
BlockCipher engine = new CBCBlockCipher(new AESEngine());
""", {"AES"})
_c("java", "J_Jwt.java", """
String jws = Jwts.builder().setSubject("u").signWith(SignatureAlgorithm.HS256, key).compact();
""", {"JWT"})
_c("java", "J_HardcodedKey.java", """
public class Cfg {
    private static final byte[] KEY = "0123456789abcdef".getBytes();
    Cipher c = Cipher.getInstance("AES/ECB/PKCS5Padding");
}
""", {"AES"})
_c("java", "J_Argon2Bcrypt.java", """
String h = BCrypt.hashpw(password, BCrypt.gensalt(12));
Argon2 argon2 = Argon2Factory.create();
""", {"BCRYPT", "ARGON2"})
_c("java", "J_ChaCha.java", """
Cipher c = Cipher.getInstance("ChaCha20-Poly1305");
""", {"CHACHA20"})
_c("java", "J_Ed25519.java", """
KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519");
Signature s = Signature.getInstance("Ed25519");
""", {"ED25519"})

# java negatives
_c("java", "N_Descriptor.java", """
public class OrderDescriptor {
    private String description;
    private int shard;   // shard, not sha
    public String getDescription() { return description; }
    public int hashCode() { return Objects.hash(description, shard); }
}
""", set(), "negative")
_c("java", "N_Crc32Base64.java", """
import java.util.zip.CRC32;
import java.util.Base64;
CRC32 crc = new CRC32();
crc.update(bytes);
String b64 = Base64.getEncoder().encodeToString(bytes);
UUID id = UUID.randomUUID();
""", set(), "negative")
_c("java", "N_Comments.java", """
/**
 * Legacy notes: we used to call Cipher.getInstance("DES") here.
 * That path was deleted in 2019; see MessageDigest migration notes.
 */
public class Notes { int value = 1; }
""", set(), "negative")
_c("java", "N_HashMap.java", """
import java.util.HashMap;
import java.util.HashSet;
HashMap<String, Integer> counts = new HashMap<>();
HashSet<String> seen = new HashSet<>();
int h = key.hashCode();
""", set(), "negative")
_c("java", "N_Strings.java", """
String label = "RSA Conference 2024 keynote";
String algoDoc = "Supported: AES, RSA";   // documentation string, never passed to a provider
System.out.println(label + algoDoc);
""", set(), "negative")

# java obfuscated
_c("java", "O_ConcatTransform.java", """
String t = "AES/" + mode + "/PKCS5Padding";
Cipher c = Cipher.getInstance(t);
""", {"AES"}, "obfuscated")
_c("java", "O_ConstantField.java", """
public class Consts {
    static final String ALG = "DESede";
    Cipher c = Cipher.getInstance(ALG + "/ECB/PKCS5Padding");
}
""", {"3DES"}, "obfuscated")
_c("java", "O_Reflection.java", """
Class<?> cls = Class.forName("javax.crypto.Cipher");
Object c = cls.getMethod("getInstance", String.class).invoke(null, "RC4");
""", {"RC4"}, "obfuscated")
_c("java", "O_Lowercase.java", """
MessageDigest md = MessageDigest.getInstance("md5");
""", {"MD5"}, "obfuscated")

# ===================================================================== KOTLIN
_c("kotlin", "K_Cipher.kt", """
val cipher = Cipher.getInstance("AES/CBC/PKCS5Padding")
cipher.init(Cipher.ENCRYPT_MODE, SecretKeySpec(key, "AES"), IvParameterSpec(iv))
""", {"AES"})
_c("kotlin", "K_Mac.kt", """
val mac = Mac.getInstance("HmacSHA256").apply { init(SecretKeySpec(k, "HmacSHA256")) }
""", {"HMAC", "SHA-256"})
_c("kotlin", "K_Digest.kt", """
fun sha1(b: ByteArray): ByteArray = MessageDigest.getInstance("SHA-1").digest(b)
""", {"SHA-1"})
_c("kotlin", "K_KeyPair.kt", """
val kpg = KeyPairGenerator.getInstance("RSA").also { it.initialize(4096) }
""", {"RSA"})
_c("kotlin", "K_Negative.kt", """
data class Desk(val shape: String, val shade: Int)
val hashed = listOf(1, 2, 3).hashCode()
val rsaConference = "RSA 2024"
""", set(), "negative")
_c("kotlin", "K_Obf.kt", """
val alg = buildString { append("DES"); append("ede") }
val c = Cipher.getInstance("$alg/CBC/PKCS5Padding")
""", {"3DES"}, "obfuscated")

# ===================================================================== JAVASCRIPT / TYPESCRIPT
_c("javascript", "js_createHash_sha1.js", """
const crypto = require("crypto");
function etag(buf) {
  return crypto.createHash("sha1").update(buf).digest("hex");
}
""", {"SHA-1"})
_c("javascript", "js_createHash_md5.js", """
import { createHash } from "node:crypto";
export const sum = (s) => createHash("md5").update(s).digest("base64");
""", {"MD5"})
_c("javascript", "js_createCipheriv.js", """
const crypto = require("crypto");
const cipher = crypto.createCipheriv("aes-256-cbc", key, iv);
let enc = cipher.update(text, "utf8", "hex");
enc += cipher.final("hex");
""", {"AES"})
_c("javascript", "js_createCipher_des.js", """
const d = crypto.createDecipheriv("des-ede3-cbc", key, iv);
""", {"3DES"})
_c("javascript", "js_hmac.js", """
const sig = crypto.createHmac("sha256", secret).update(body).digest("hex");
""", {"HMAC", "SHA-256"})
_c("javascript", "js_pbkdf2_scrypt.js", """
crypto.pbkdf2(password, salt, 100000, 64, "sha512", cb);
const key = crypto.scryptSync(password, salt, 32);
""", {"PBKDF2", "SHA-512", "SCRYPT"})
_c("javascript", "js_generateKeyPair.js", """
const { generateKeyPairSync } = require("crypto");
const { publicKey, privateKey } = generateKeyPairSync("rsa", { modulusLength: 2048 });
const ec = generateKeyPairSync("ec", { namedCurve: "P-256" });
""", {"RSA", "ECDSA"})
_c("javascript", "js_sign_verify.js", """
const signer = crypto.createSign("RSA-SHA256");
signer.update(data);
const signature = signer.sign(privateKey, "base64");
""", {"RSA", "SHA-256"})
_c("javascript", "js_randomBytes.js", """
const iv = crypto.randomBytes(16);
const n = Math.random();
""", {"RNG"})
_c("typescript", "ts_webcrypto.ts", """
const key = await crypto.subtle.generateKey({ name: "AES-GCM", length: 256 }, true, ["encrypt", "decrypt"]);
const digest = await crypto.subtle.digest("SHA-256", data);
""", {"AES", "SHA-256"})
_c("typescript", "ts_webcrypto_rsa.ts", """
const kp = await window.crypto.subtle.generateKey(
  { name: "RSA-OAEP", modulusLength: 2048, publicExponent: new Uint8Array([1, 0, 1]), hash: "SHA-1" },
  true, ["encrypt", "decrypt"]);
""", {"RSA", "SHA-1"})
_c("javascript", "js_cryptojs.js", """
const CryptoJS = require("crypto-js");
const ct = CryptoJS.AES.encrypt(message, passphrase).toString();
const h = CryptoJS.MD5(message).toString();
const t = CryptoJS.TripleDES.encrypt(message, key);
""", {"AES", "MD5", "3DES"})
_c("javascript", "js_jsonwebtoken.js", """
const jwt = require("jsonwebtoken");
const token = jwt.sign({ id }, SECRET, { algorithm: "HS256", expiresIn: "1h" });
jwt.verify(token, SECRET, { algorithms: ["HS256", "none"] });
""", {"JWT"})
_c("javascript", "js_bcrypt.js", """
const bcrypt = require("bcryptjs");
const hash = await bcrypt.hash(password, 10);
""", {"BCRYPT"})
_c("javascript", "js_forge.js", """
const forge = require("node-forge");
const keypair = forge.pki.rsa.generateKeyPair({ bits: 1024 });
const md = forge.md.sha1.create();
""", {"RSA", "SHA-1"})
_c("javascript", "js_tweetnacl.js", """
import nacl from "tweetnacl";
const box = nacl.secretbox(msg, nonce, key);
const kp = nacl.sign.keyPair();
""", {"SALSA20", "ED25519"})
_c("javascript", "js_tls.js", """
const https = require("https");
const agent = new https.Agent({ rejectUnauthorized: false, secureProtocol: "TLSv1_method" });
""", {"TLS"})

# js negatives
_c("javascript", "n_lodash_hash.js", """
const _ = require("lodash");
const grouped = _.groupBy(items, "shade");
const hashtags = text.match(/#\\w+/g);
const desc = { description: "AES conference", shard: 2 };
""", set(), "negative")
_c("javascript", "n_base64_uuid.js", """
const b = Buffer.from(str).toString("base64");
const id = require("uuid").v4();
const crc = require("crc-32").str(str);
const hexColor = "#aabbcc";
""", set(), "negative")
_c("javascript", "n_react_component.jsx", """
export default function Badge({ shaded }) {
  const [desired, setDesired] = useState(false);
  return <span className={shaded ? "dark" : "light"}>{desired ? "RSA Conf" : "AES Talk"}</span>;
}
""", set(), "negative")
_c("typescript", "n_types.ts", """
export interface Certificate { sha256: string; rsaBits: number; }
export type HashFn = (s: string) => number;   // a plain map hash, not crypto
const table = new Map<string, HashFn>();
""", set(), "negative")
_c("javascript", "n_comment_only.js", """
// TODO: replace createHash("md5") with something modern — removed in v3
module.exports = { version: "3.0.0" };
""", set(), "negative")

# js obfuscated
_c("javascript", "o_dynamic_algo.js", """
const algo = ["a", "es-128-ecb"].join("");
const c = require("crypto").createCipheriv(algo, key, null);
""", {"AES"}, "obfuscated")
_c("javascript", "o_destructure_alias.js", """
const { createHash: mk } = require("crypto");
const out = mk("sha512").update(x).digest();
""", {"SHA-512"}, "obfuscated")
_c("javascript", "o_bracket_access.js", """
const c = require("crypto");
const h = c["createHash"]("md5");
""", {"MD5"}, "obfuscated")

# ===================================================================== GO
_c("go", "g_md5.go", """
package main
import "crypto/md5"
func sum(b []byte) [16]byte { return md5.Sum(b) }
""", {"MD5"})
_c("go", "g_aes_gcm.go", """
package main
import ("crypto/aes"; "crypto/cipher")
func seal(key, nonce, pt []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil { return nil, err }
	gcm, err := cipher.NewGCM(block)
	return gcm.Seal(nil, nonce, pt, nil), err
}
""", {"AES"})
_c("go", "g_rsa.go", """
package main
import ("crypto/rand"; "crypto/rsa")
func gen() (*rsa.PrivateKey, error) { return rsa.GenerateKey(rand.Reader, 2048) }
""", {"RSA", "RNG"})
_c("go", "g_ecdsa.go", """
package main
import ("crypto/ecdsa"; "crypto/elliptic"; "crypto/rand")
var k, _ = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
""", {"ECDSA", "RNG"})
_c("go", "g_hmac.go", """
package main
import ("crypto/hmac"; "crypto/sha256")
func tag(k, m []byte) []byte { h := hmac.New(sha256.New, k); h.Write(m); return h.Sum(nil) }
""", {"HMAC", "SHA-256"})
_c("go", "g_des.go", """
package main
import "crypto/des"
var b, _ = des.NewTripleDESCipher(key)
var s, _ = des.NewCipher(key8)
""", {"3DES", "DES"})
_c("go", "g_rc4.go", """
package main
import "crypto/rc4"
var c, _ = rc4.NewCipher(key)
""", {"RC4"})
_c("go", "g_tls.go", """
package main
import "crypto/tls"
var cfg = &tls.Config{MinVersion: tls.VersionTLS10, InsecureSkipVerify: true}
""", {"TLS"})
_c("go", "g_bcrypt_argon.go", """
package main
import ("golang.org/x/crypto/bcrypt"; "golang.org/x/crypto/argon2")
var h, _ = bcrypt.GenerateFromPassword(pw, bcrypt.DefaultCost)
var k = argon2.IDKey(pw, salt, 1, 64*1024, 4, 32)
""", {"BCRYPT", "ARGON2"})
_c("go", "g_ed25519_x25519.go", """
package main
import ("crypto/ed25519"; "golang.org/x/crypto/curve25519")
var pub, priv, _ = ed25519.GenerateKey(nil)
var shared, _ = curve25519.X25519(priv[:32], pub)
""", {"ED25519", "X25519"})
_c("go", "g_chacha.go", """
package main
import "golang.org/x/crypto/chacha20poly1305"
var aead, _ = chacha20poly1305.NewX(key)
""", {"CHACHA20"})
_c("go", "g_sha1_sha512.go", """
package main
import ("crypto/sha1"; "crypto/sha512")
var a = sha1.Sum(b)
var c = sha512.Sum384(b)
""", {"SHA-1", "SHA-384"})
_c("go", "n_hash_fnv.go", """
package main
import ("hash/fnv"; "hash/crc32"; "encoding/base64")
var h = fnv.New32a()
var c = crc32.ChecksumIEEE(b)
var s = base64.StdEncoding.EncodeToString(b)
""", set(), "negative")
_c("go", "n_struct_names.go", """
package main
type Shader struct{ Desc string; RsaConference bool }
func (s Shader) Describe() string { return s.Desc }
var md5sumBinary = "/usr/bin/md5sum"
""", set(), "negative")
_c("go", "n_comments.go", """
package main
// We considered aes.NewCipher here but chose an HTTP signature header instead.
// sha256.Sum256 is used by the upstream service, not by us.
var version = "1.2.3"
""", set(), "negative")
_c("go", "o_alias_import.go", """
package main
import m "crypto/md5"
var d = m.Sum(data)
""", {"MD5"}, "obfuscated")

# ===================================================================== C#
_c("csharp", "cs_sha256_rsa.cs", """
using System.Security.Cryptography;
class C {
    void F() {
        using var sha = SHA256.Create();
        var rsa = new RSACryptoServiceProvider(2048);
    }
}
""", {"SHA-256", "RSA"})
_c("csharp", "cs_aes.cs", """
using System.Security.Cryptography;
using (Aes aes = Aes.Create()) {
    aes.Mode = CipherMode.CBC;
    aes.Key = key; aes.IV = iv;
    var enc = aes.CreateEncryptor();
}
""", {"AES"})
_c("csharp", "cs_tripledes_des.cs", """
var tdes = new TripleDESCryptoServiceProvider();
var des = DES.Create();
""", {"3DES", "DES"})
_c("csharp", "cs_md5.cs", """
using (var md5 = MD5.Create()) { var h = md5.ComputeHash(bytes); }
var legacy = new MD5CryptoServiceProvider();
""", {"MD5"})
_c("csharp", "cs_hmac.cs", """
using var h = new HMACSHA256(key);
var tag = h.ComputeHash(data);
""", {"HMAC", "SHA-256"})
_c("csharp", "cs_pbkdf2.cs", """
var kdf = new Rfc2898DeriveBytes(password, salt, 10000, HashAlgorithmName.SHA1);
byte[] key = kdf.GetBytes(32);
""", {"PBKDF2", "SHA-1"})
_c("csharp", "cs_ecdsa.cs", """
using var ecdsa = ECDsa.Create(ECCurve.NamedCurves.nistP256);
var sig = ecdsa.SignData(data, HashAlgorithmName.SHA256);
""", {"ECDSA", "SHA-256"})
_c("csharp", "cs_rsa_create.cs", """
using var rsa = RSA.Create(3072);
var ct = rsa.Encrypt(pt, RSAEncryptionPadding.OaepSHA256);
""", {"RSA", "SHA-256"})
_c("csharp", "cs_rng.cs", """
var bytes = RandomNumberGenerator.GetBytes(32);
var weak = new Random().Next();
""", {"RNG"})
_c("csharp", "cs_bouncycastle.cs", """
using Org.BouncyCastle.Crypto.Engines;
var engine = new RijndaelEngine();
var blowfish = new BlowfishEngine();
""", {"AES", "BLOWFISH"})
_c("csharp", "cs_tls.cs", """
ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Ssl3;
ServicePointManager.ServerCertificateValidationCallback = (s, c, ch, e) => true;
""", {"TLS"})
_c("csharp", "cs_dsa.cs", """
using var dsa = DSA.Create(2048);
""", {"DSA"})
_c("csharp", "n_linq_hash.cs", """
var set = new HashSet<string>();
var dict = new Dictionary<int, string>();
int code = value.GetHashCode();
string desc = order.Description;
""", set(), "negative")
_c("csharp", "n_crc_base64.cs", """
string b64 = Convert.ToBase64String(bytes);
var id = Guid.NewGuid();
uint crc = Crc32.Compute(bytes);
""", set(), "negative")
_c("csharp", "n_comments.cs", """
// Historically: new RSACryptoServiceProvider(1024) — removed, see ADR-7.
/* MD5.Create() was here */
public class Version { public const string Value = "2.0"; }
""", set(), "negative")
_c("csharp", "o_hashalgorithm_create.cs", """
var name = "SHA1";
using var h = HashAlgorithm.Create(name);
""", {"SHA-1"}, "obfuscated")
_c("csharp", "o_symmetric_create.cs", """
var alg = SymmetricAlgorithm.Create("TripleDES");
""", {"3DES"}, "obfuscated")

# ===================================================================== RUST
_c("rust", "r_ring_aead.rs", """
use ring::aead::{AES_256_GCM, LessSafeKey, UnboundKey};
let key = LessSafeKey::new(UnboundKey::new(&AES_256_GCM, &raw).unwrap());
""", {"AES"})
_c("rust", "r_ring_chacha.rs", """
use ring::aead::CHACHA20_POLY1305;
let k = UnboundKey::new(&CHACHA20_POLY1305, &raw)?;
""", {"CHACHA20"})
_c("rust", "r_ring_signature.rs", """
use ring::signature::{Ed25519KeyPair, ECDSA_P256_SHA256_ASN1_SIGNING, RSA_PKCS1_SHA256};
let kp = Ed25519KeyPair::from_pkcs8(&pkcs8)?;
""", {"ED25519", "ECDSA", "RSA", "SHA-256"})
_c("rust", "r_ring_digest.rs", """
use ring::digest::{digest, SHA256};
let d = digest(&SHA256, b"hello");
""", {"SHA-256"})
_c("rust", "r_rustcrypto_aes_gcm.rs", """
use aes_gcm::{Aes256Gcm, Key, Nonce};
use aes_gcm::aead::{Aead, KeyInit};
let cipher = Aes256Gcm::new(Key::<Aes256Gcm>::from_slice(&key));
""", {"AES"})
_c("rust", "r_sha2_md5.rs", """
use sha2::{Sha256, Digest};
use md5::Md5;
let h = Sha256::digest(b"x");
let m = Md5::digest(b"y");
""", {"SHA-256", "MD5"})
_c("rust", "r_rsa_crate.rs", """
use rsa::{RsaPrivateKey, Pkcs1v15Encrypt};
let sk = RsaPrivateKey::new(&mut rng, 2048)?;
""", {"RSA"})
_c("rust", "r_hmac.rs", """
use hmac::{Hmac, Mac};
use sha2::Sha256;
type HmacSha256 = Hmac<Sha256>;
let mut mac = HmacSha256::new_from_slice(key)?;
""", {"HMAC", "SHA-256"})
_c("rust", "r_openssl_symm.rs", """
use openssl::symm::{Cipher, encrypt};
let ct = encrypt(Cipher::aes_128_cbc(), key, Some(iv), data)?;
let legacy = Cipher::des_ede3_cbc();
""", {"AES", "3DES"})
_c("rust", "r_openssl_hash.rs", """
use openssl::hash::{hash, MessageDigest};
let d = hash(MessageDigest::sha1(), data)?;
""", {"SHA-1"})
_c("rust", "r_argon2_bcrypt.rs", """
use argon2::{Argon2, PasswordHasher};
let h = bcrypt::hash(pw, bcrypt::DEFAULT_COST)?;
""", {"ARGON2", "BCRYPT"})
_c("rust", "r_rustls.rs", """
use rustls::{ClientConfig, RootCertStore};
let cfg = ClientConfig::builder().with_root_certificates(RootCertStore::empty()).with_no_client_auth();
""", {"TLS"})
_c("rust", "r_x25519_dalek.rs", """
use x25519_dalek::{EphemeralSecret, PublicKey};
let secret = EphemeralSecret::random_from_rng(OsRng);
""", {"X25519", "RNG"})
_c("rust", "n_hash_std.rs", """
use std::collections::HashMap;
use std::hash::{Hash, Hasher};
let mut m: HashMap<String, u32> = HashMap::new();
struct Shade { desc: String }
""", set(), "negative")
_c("rust", "n_crc_base64.rs", """
let c = crc32fast::hash(data);
let b = base64::encode(data);
let id = uuid::Uuid::new_v4();
""", set(), "negative")
_c("rust", "n_comments.rs", """
// previously used aes_gcm::Aes256Gcm here — moved to the vault service
fn version() -> &'static str { "0.9" }
""", set(), "negative")

# ===================================================================== PHP
_c("php", "ph_md5_openssl.php", """
<?php
$h = md5($password);
$ct = openssl_encrypt($data, "aes-128-ecb", $key);
""", {"MD5", "AES"})
_c("php", "ph_sha1_hash.php", """
<?php
$a = sha1($x);
$b = hash("sha256", $x);
$c = hash_hmac("sha512", $x, $k);
""", {"SHA-1", "SHA-256", "HMAC", "SHA-512"})
_c("php", "ph_password_hash.php", """
<?php
$h = password_hash($pw, PASSWORD_BCRYPT, ["cost" => 12]);
$a = password_hash($pw, PASSWORD_ARGON2ID);
""", {"BCRYPT", "ARGON2"})
_c("php", "ph_openssl_rsa.php", """
<?php
$res = openssl_pkey_new(["private_key_bits" => 1024, "private_key_type" => OPENSSL_KEYTYPE_RSA]);
openssl_sign($data, $sig, $res, OPENSSL_ALGO_SHA1);
""", {"RSA", "SHA-1"})
_c("php", "ph_mcrypt.php", """
<?php
$ct = mcrypt_encrypt(MCRYPT_RIJNDAEL_128, $key, $data, MCRYPT_MODE_ECB);
$old = mcrypt_encrypt(MCRYPT_3DES, $key, $data, MCRYPT_MODE_CBC, $iv);
""", {"AES", "3DES"})
_c("php", "ph_sodium.php", """
<?php
$ct = sodium_crypto_secretbox($msg, $nonce, $key);
$kp = sodium_crypto_sign_keypair();
""", {"SALSA20", "ED25519"})
_c("php", "ph_random.php", """
<?php
$iv = random_bytes(16);
$weak = rand(0, 100);
$r = mt_rand();
""", {"RNG"})
_c("php", "ph_openssl_3des.php", """
<?php
$c = openssl_decrypt($ct, "des-ede3-cbc", $k, 0, $iv);
$r = openssl_encrypt($p, "rc4", $k);
""", {"3DES", "RC4"})
_c("php", "ph_jwt.php", """
<?php
use Firebase\\JWT\\JWT;
$jwt = JWT::encode($payload, $key, "HS256");
""", {"JWT"})
_c("php", "ph_curl_tls.php", """
<?php
curl_setopt($ch, CURLOPT_SSL_VERIFYPEER, false);
curl_setopt($ch, CURLOPT_SSLVERSION, CURL_SSLVERSION_TLSv1_0);
""", {"TLS"})
_c("php", "n_php_negative.php", """
<?php
$desc = $order->description;
$hashtags = explode("#", $text);
$crc = crc32($data);
$b = base64_encode($data);
$id = uniqid();
""", set(), "negative")
_c("php", "n_php_comment.php", """
<?php
// legacy: md5($pw) — removed 2018, now handled by the identity provider
return ["version" => "4"];
""", set(), "negative")
_c("php", "o_php_variable_func.php", """
<?php
$fn = "md" . "5";
$h = $fn($data);
$cipher = "aes-256-" . $mode;
$ct = openssl_encrypt($data, $cipher, $key);
""", {"MD5", "AES"}, "obfuscated")

# ===================================================================== RUBY
_c("ruby", "rb_digest.rb", """
require "digest"
etag = Digest::SHA1.hexdigest(body)
legacy = Digest::MD5.base64digest(body)
""", {"SHA-1", "MD5"})
_c("ruby", "rb_openssl_cipher.rb", """
require "openssl"
cipher = OpenSSL::Cipher.new("aes-256-gcm")
cipher.encrypt
cipher.key = key
""", {"AES"})
_c("ruby", "rb_openssl_legacy.rb", """
c = OpenSSL::Cipher::Cipher.new("des-ede3-cbc")
d = OpenSSL::Cipher.new("rc4")
""", {"3DES", "RC4"})
_c("ruby", "rb_hmac.rb", """
sig = OpenSSL::HMAC.hexdigest("SHA256", secret, payload)
""", {"HMAC", "SHA-256"})
_c("ruby", "rb_rsa.rb", """
key = OpenSSL::PKey::RSA.new(2048)
sig = key.sign(OpenSSL::Digest::SHA1.new, data)
""", {"RSA", "SHA-1"})
_c("ruby", "rb_ec.rb", """
ec = OpenSSL::PKey::EC.generate("prime256v1")
""", {"ECDSA"})
_c("ruby", "rb_bcrypt.rb", """
require "bcrypt"
h = BCrypt::Password.create(password, cost: 12)
""", {"BCRYPT"})
_c("ruby", "rb_pbkdf2.rb", """
key = OpenSSL::PKCS5.pbkdf2_hmac(pw, salt, 20_000, 32, "sha256")
""", {"PBKDF2", "SHA-256"})
_c("ruby", "rb_jwt.rb", """
token = JWT.encode(payload, secret, "HS256")
""", {"JWT"})
_c("ruby", "rb_ssl.rb", """
http.verify_mode = OpenSSL::SSL::VERIFY_NONE
ctx = OpenSSL::SSL::SSLContext.new(:TLSv1)
""", {"TLS"})
_c("ruby", "rb_securerandom.rb", """
token = SecureRandom.hex(32)
w = rand(100)
""", {"RNG"})
_c("ruby", "n_ruby_negative.rb", """
class Shader
  attr_reader :description, :shade
  def hash; [description, shade].hash; end
end
crc = Zlib.crc32(data)
b = Base64.strict_encode64(data)
""", set(), "negative")
_c("ruby", "n_ruby_comment.rb", """
# Digest::MD5 used to live here; see CHANGELOG 2.1
VERSION = "2.1"
""", set(), "negative")
_c("ruby", "o_ruby_const_get.rb", """
klass = Digest.const_get(:SHA1)
h = klass.hexdigest(x)
""", {"SHA-1"}, "obfuscated")

# ===================================================================== C / C++
_c("c", "c_openssl_evp.c", """
#include <openssl/evp.h>
int enc(unsigned char *key, unsigned char *iv) {
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    EVP_EncryptInit_ex(ctx, EVP_aes_256_cbc(), NULL, key, iv);
    return 0;
}
""", {"AES"})
_c("c", "c_openssl_legacy_hash.c", """
#include <openssl/md5.h>
#include <openssl/sha.h>
void h(const unsigned char *d, size_t n, unsigned char *out) {
    MD5_CTX c; MD5_Init(&c); MD5_Update(&c, d, n); MD5_Final(out, &c);
    SHA1(d, n, out);
}
""", {"MD5", "SHA-1"})
_c("c", "c_openssl_des_rc4.c", """
#include <openssl/des.h>
#include <openssl/rc4.h>
DES_key_schedule ks;
DES_set_key_unchecked(&key, &ks);
DES_ecb_encrypt(&in, &out, &ks, DES_ENCRYPT);
RC4_KEY rk; RC4_set_key(&rk, 16, k); RC4(&rk, n, in, out);
""", {"DES", "RC4"})
_c("c", "c_openssl_rsa.c", """
#include <openssl/rsa.h>
RSA *r = RSA_new();
BIGNUM *e = BN_new(); BN_set_word(e, RSA_F4);
RSA_generate_key_ex(r, 1024, e, NULL);
int n = RSA_public_encrypt(len, in, out, r, RSA_PKCS1_PADDING);
""", {"RSA"})
_c("c", "c_openssl_evp_digest.c", """
EVP_MD_CTX *m = EVP_MD_CTX_new();
EVP_DigestInit_ex(m, EVP_sha256(), NULL);
const EVP_MD *legacy = EVP_md5();
""", {"SHA-256", "MD5"})
_c("c", "c_openssl_hmac_pkcs5.c", """
#include <openssl/hmac.h>
unsigned char *t = HMAC(EVP_sha1(), key, klen, data, dlen, out, &outlen);
PKCS5_PBKDF2_HMAC(pw, pwlen, salt, slen, 10000, EVP_sha256(), 32, key);
""", {"HMAC", "SHA-1", "PBKDF2", "SHA-256"})
_c("c", "c_openssl_ec.c", """
#include <openssl/ec.h>
EC_KEY *k = EC_KEY_new_by_curve_name(NID_X9_62_prime256v1);
EC_KEY_generate_key(k);
ECDSA_SIG *s = ECDSA_do_sign(dgst, 32, k);
""", {"ECDSA"})
_c("c", "c_openssl_ssl.c", """
#include <openssl/ssl.h>
SSL_CTX *ctx = SSL_CTX_new(SSLv23_method());
SSL_CTX_set_verify(ctx, SSL_VERIFY_NONE, NULL);
SSL_CTX_set_cipher_list(ctx, "RC4-SHA:DES-CBC3-SHA");
""", {"TLS", "RC4", "3DES", "SHA-1"})
_c("c", "c_openssl_rand.c", """
#include <openssl/rand.h>
unsigned char buf[32];
RAND_bytes(buf, sizeof buf);
int weak = rand() % 256;
""", {"RNG"})
_c("cpp", "cpp_mbedtls.cpp", """
#include "mbedtls/aes.h"
#include "mbedtls/md.h"
mbedtls_aes_context aes;
mbedtls_aes_setkey_enc(&aes, key, 128);
mbedtls_aes_crypt_cbc(&aes, MBEDTLS_AES_ENCRYPT, len, iv, in, out);
const mbedtls_md_info_t *md = mbedtls_md_info_from_type(MBEDTLS_MD_SHA1);
""", {"AES", "SHA-1"})
_c("c", "c_mbedtls_rsa_ecdh.c", """
mbedtls_rsa_context rsa;
mbedtls_rsa_gen_key(&rsa, mbedtls_ctr_drbg_random, &ctr, 2048, 65537);
mbedtls_ecdh_context ecdh;
mbedtls_ecdh_gen_public(&grp, &d, &Q, mbedtls_ctr_drbg_random, &ctr);
""", {"RSA", "ECDH", "RNG"})
_c("c", "c_wolfssl.c", """
#include <wolfssl/wolfcrypt/aes.h>
Aes aes;
wc_AesSetKey(&aes, key, 16, iv, AES_ENCRYPTION);
wc_Sha256Hash(in, len, out);
wc_Md5Hash(in, len, out);
""", {"AES", "SHA-256", "MD5"})
_c("c", "c_libsodium.c", """
#include <sodium.h>
crypto_secretbox_easy(c, m, mlen, nonce, key);
crypto_sign_keypair(pk, sk);
crypto_aead_chacha20poly1305_ietf_encrypt(c, &clen, m, mlen, ad, adlen, NULL, npub, k);
crypto_pwhash_str(out, pw, pwlen, crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE);
""", {"SALSA20", "ED25519", "CHACHA20", "ARGON2"})
_c("cpp", "cpp_cryptopp.cpp", """
#include <cryptopp/aes.h>
#include <cryptopp/modes.h>
#include <cryptopp/sha.h>
CryptoPP::CBC_Mode<CryptoPP::AES>::Encryption e;
CryptoPP::SHA1 sha;
CryptoPP::RSA::PrivateKey priv;
""", {"AES", "SHA-1", "RSA"})
_c("c", "c_windows_cng.c", """
#include <bcrypt.h>
BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_AES_ALGORITHM, NULL, 0);
BCryptOpenAlgorithmProvider(&hHash, BCRYPT_MD5_ALGORITHM, NULL, 0);
CryptCreateHash(hProv, CALG_SHA1, 0, 0, &hHash);
""", {"AES", "MD5", "SHA-1"})
_c("c", "c_openssl_blowfish_cast.c", """
#include <openssl/blowfish.h>
BF_KEY bk; BF_set_key(&bk, 16, k);
BF_ecb_encrypt(in, out, &bk, BF_ENCRYPT);
const EVP_CIPHER *c2 = EVP_cast5_cbc();
""", {"BLOWFISH", "CAST5"})
_c("c", "c_openssl_chacha_ed.c", """
const EVP_CIPHER *c = EVP_chacha20_poly1305();
EVP_PKEY *pk = EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, NULL, raw, 32);
EVP_PKEY_CTX *x = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
""", {"CHACHA20", "ED25519", "X25519"})
_c("c", "n_c_negative.c", """
#include <stdio.h>
#include <zlib.h>
struct shader { int shade; char description[64]; };
uLong c = crc32(0L, buf, len);
static const char *md5sum_path = "/usr/bin/md5sum";
int desired = 1;
""", set(), "negative")
_c("c", "n_c_comments.c", """
/* We used to call EVP_aes_128_ecb() here. Do not reintroduce; see SEC-42. */
// RSA_generate_key is deprecated upstream — irrelevant, we do not link libcrypto.
int main(void) { return 0; }
""", set(), "negative")
_c("cpp", "n_cpp_stdhash.cpp", """
#include <unordered_map>
#include <functional>
std::unordered_map<std::string, int> counts;
std::hash<std::string> hasher;
size_t h = hasher("key");
""", set(), "negative")
_c("c", "o_c_macro.c", """
#define CIPHER() EVP_des_ede3_cbc()
EVP_EncryptInit_ex(ctx, CIPHER(), NULL, key, iv);
""", {"3DES"}, "obfuscated")

# ===================================================================== CONFIG / IaC
_c("config", "nginx.conf", """
server {
    listen 443 ssl;
    ssl_protocols SSLv3 TLSv1 TLSv1.1;
    ssl_ciphers 'RC4-SHA:DES-CBC3-SHA:AES128-SHA';
}
""", {"TLS", "RC4", "3DES", "AES", "SHA-1"}, "config")
_c("config", "application.properties", """
server.ssl.enabled-protocols=TLSv1.2,TLSv1.3
server.ssl.ciphers=TLS_AES_256_GCM_SHA384
app.crypto.algorithm=AES/GCM/NoPadding
""", {"TLS", "AES", "SHA-384"}, "config")
_c("config", "sshd_config.conf", """
Ciphers 3des-cbc,aes128-ctr
MACs hmac-md5,hmac-sha1
KexAlgorithms diffie-hellman-group1-sha1
HostKey /etc/ssh/ssh_host_rsa_key
""", {"3DES", "AES", "HMAC", "MD5", "SHA-1", "DH", "RSA"}, "config")
_c("config", "main.tf", """
resource "aws_kms_key" "app" {
  description              = "app key"
  customer_master_key_spec = "RSA_2048"
  key_usage                = "ENCRYPT_DECRYPT"
}
resource "aws_lb_listener" "https" {
  ssl_policy = "ELBSecurityPolicy-TLS-1-0-2015-04"
}
""", {"RSA", "TLS"}, "config")
_c("config", "docker-compose.yml", """
services:
  api:
    image: app:1.0
    environment:
      - JWT_ALGORITHM=HS256
      - TLS_MIN_VERSION=1.0
""", {"JWT", "TLS"}, "config")
_c("config", "n_settings.ini", """
[app]
name = shaded-desk
description = RSA conference attendee list
theme = aesthetic
""", set(), "negative")
_c("config", "n_values.yaml", """
replicaCount: 3
image:
  repository: registry/app
  tag: "sha-abc123"   # image tag from git sha, not a hash operation
resources:
  limits: {cpu: 500m}
""", set(), "negative")
_c("config", "n_env.env", """
DATABASE_URL=postgres://u:p@db/app
LOG_LEVEL=info
FEATURE_DESIGN_V2=true
""", set(), "negative")


try:  # wave 2: harder real-world idioms (same _c registrar)
    from .corpus_wave2 import register as _register_wave2
except ImportError:  # imported as a top-level module
    from corpus_wave2 import register as _register_wave2  # type: ignore[no-redef]
_register_wave2(_c)
try:
    from .corpus_wave3 import register as _register_wave3
except ImportError:
    from corpus_wave3 import register as _register_wave3  # type: ignore[no-redef]
_register_wave3(_c)
try:
    from .corpus_wave4_wild import register as _register_wave4
except ImportError:  # pragma: no cover - script execution
    from corpus_wave4_wild import register as _register_wave4  # type: ignore[no-redef]
_register_wave4(_c)
try:
    from .corpus_wave5 import register as _register_wave5
except ImportError:  # pragma: no cover - script execution
    from corpus_wave5 import register as _register_wave5  # type: ignore[no-redef]
_register_wave5(_c)
try:
    from .corpus_wave6_xml import register as _register_wave6
except ImportError:  # pragma: no cover - script execution
    from corpus_wave6_xml import register as _register_wave6  # type: ignore[no-redef]
_register_wave6(_c)
try:
    from .corpus_wave7_blind import register as _register_wave7
except ImportError:  # pragma: no cover - script execution
    from corpus_wave7_blind import register as _register_wave7  # type: ignore[no-redef]
_register_wave7(_c)


def summary() -> dict[str, int]:
    out: dict[str, int] = {}
    for lang, _, _, _, cat in CASES:
        out[lang] = out.get(lang, 0) + 1
        out[cat] = out.get(cat, 0) + 1
    out["total"] = len(CASES)
    return out
try:
    from .corpus_wave8_payments import register as _register_wave8
except ImportError:  # pragma: no cover
    from corpus_wave8_payments import register as _register_wave8  # type: ignore[no-redef]
_register_wave8(_c)
try:
    from .corpus_wave9_sql_cobol import register as _register_wave9
except ImportError:  # pragma: no cover
    from corpus_wave9_sql_cobol import register as _register_wave9  # type: ignore[no-redef]
_register_wave9(_c)
try:
    from .corpus_wave10_middleware import register as _register_wave10
except ImportError:  # pragma: no cover
    from corpus_wave10_middleware import register as _register_wave10  # type: ignore[no-redef]
_register_wave10(_c)
try:
    from .corpus_wave11_ibmi import register as _register_wave11
except ImportError:  # pragma: no cover
    from corpus_wave11_ibmi import register as _register_wave11  # type: ignore[no-redef]
_register_wave11(_c)
try:
    from .corpus_wave12_evasion import register as _register_wave12
except ImportError:  # pragma: no cover
    from corpus_wave12_evasion import register as _register_wave12  # type: ignore[no-redef]
_register_wave12(_c)
try:
    from .corpus_wave13_mainframe_defs import register as _register_wave13
except ImportError:  # pragma: no cover
    from corpus_wave13_mainframe_defs import register as _register_wave13  # type: ignore[no-redef]
_register_wave13(_c)
try:
    from .corpus_wave14_payments_polyglot import register as _register_wave14
except ImportError:  # pragma: no cover
    from corpus_wave14_payments_polyglot import register as _register_wave14  # type: ignore[no-redef]
_register_wave14(_c)
try:
    from .corpus_wave15_legacy_4gl import register as _register_wave15
except ImportError:  # pragma: no cover
    from corpus_wave15_legacy_4gl import register as _register_wave15  # type: ignore[no-redef]
_register_wave15(_c)

try:
    from .corpus_wave16_saudi_bank import register as _register_wave16
except ImportError:  # pragma: no cover
    from corpus_wave16_saudi_bank import register as _register_wave16  # type: ignore[no-redef]
_register_wave16(_c)
