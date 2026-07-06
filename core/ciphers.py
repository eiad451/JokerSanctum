import os
import hashlib
import struct
from cryptography.hazmat.primitives.ciphers import Cipher as CryC, algorithms as alg, modes as md
from cryptography.hazmat.primitives import padding as pad
from Crypto.Cipher import AES, ChaCha20_Poly1305, DES3, Blowfish, CAST, Salsa20

PADDING = lambda d: d + bytes([16 - len(d) % 16] * (16 - len(d) % 16))
UNPAD = lambda d: d[:-d[-1]]


def rotl32(x, n):
    return ((x << n) | (x >> (32 - n))) & 0xFFFFFFFF


def rotr32(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF


# ──────────────────────────────────────────────
# 1. AES-256-GCM
# ──────────────────────────────────────────────
def aes_encrypt(key, data):
    nonce = os.urandom(12)
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    ct, tag = c.encrypt_and_digest(data)
    return nonce + ct + tag


def aes_decrypt(key, data):
    nonce, ct, tag = data[:12], data[12:-16], data[-16:]
    c = AES.new(key, AES.MODE_GCM, nonce=nonce)
    return c.decrypt_and_verify(ct, tag)


# ──────────────────────────────────────────────
# 2. ChaCha20-Poly1305
# ──────────────────────────────────────────────
def chacha_encrypt(key, data):
    nonce = os.urandom(12)
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    ct, tag = c.encrypt_and_digest(data)
    return nonce + ct + tag


def chacha_decrypt(key, data):
    nonce, ct, tag = data[:12], data[12:-16], data[-16:]
    c = ChaCha20_Poly1305.new(key=key, nonce=nonce)
    return c.decrypt_and_verify(ct, tag)


# ──────────────────────────────────────────────
# 3. Camellia-256-CBC (cryptography)
# ──────────────────────────────────────────────
def camellia_encrypt(key, data):
    iv = os.urandom(16)
    padded = PADDING(data)
    c = CryC(alg.Camellia(key), md.CBC(iv))
    e = c.encryptor()
    ct = e.update(padded) + e.finalize()
    return iv + ct


def camellia_decrypt(key, data):
    iv, ct = data[:16], data[16:]
    c = CryC(alg.Camellia(key), md.CBC(iv))
    d = c.decryptor()
    return UNPAD(d.update(ct) + d.finalize())


# ──────────────────────────────────────────────
# 4. Serpent-256-CBC (pure Python)
# ──────────────────────────────────────────────
class _Serpent:
    _S = [
        [3, 8, 15, 1, 10, 6, 5, 11, 14, 13, 4, 2, 7, 0, 9, 12],
        [15, 12, 2, 7, 9, 0, 5, 10, 1, 11, 14, 8, 6, 13, 3, 4],
        [8, 6, 7, 9, 3, 12, 10, 15, 13, 1, 14, 4, 0, 11, 5, 2],
        [0, 15, 11, 8, 12, 9, 6, 3, 13, 1, 2, 4, 10, 7, 14, 5],
        [1, 15, 8, 3, 12, 0, 11, 6, 2, 5, 4, 10, 9, 14, 7, 13],
        [15, 5, 2, 11, 4, 10, 9, 12, 0, 3, 14, 8, 13, 6, 7, 1],
        [7, 2, 12, 5, 8, 4, 6, 11, 14, 9, 1, 15, 13, 3, 10, 0],
        [1, 13, 15, 0, 14, 8, 2, 11, 7, 4, 12, 10, 9, 3, 5, 6],
    ]

    @staticmethod
    def _si(s):
        inv = [0] * 16
        for i in range(16):
            inv[s[i]] = i
        return inv

    _INV_S = None

    @classmethod
    def _get_inv(cls):
        if cls._INV_S is None:
            cls._INV_S = [cls._si(s) for s in cls._S]
        return cls._INV_S

    @staticmethod
    def _sb(w, s):
        o = 0
        for i in range(8):
            o |= (s[(w >> (i * 4)) & 0xF] << (i * 4))
        return o

    @staticmethod
    def _lt(w):
        w[0] = rotl32(w[0], 13)
        w[2] = rotl32(w[2], 3)
        w[1] = (w[1] ^ w[0] ^ w[2]) & 0xFFFFFFFF
        w[3] = (w[3] ^ w[2] ^ (w[0] << 3)) & 0xFFFFFFFF
        w[1] = rotl32(w[1], 1)
        w[3] = rotl32(w[3], 7)
        w[0] = (w[0] ^ w[1] ^ w[3]) & 0xFFFFFFFF
        w[2] = (w[2] ^ w[3] ^ (w[1] << 7)) & 0xFFFFFFFF
        w[0] = rotl32(w[0], 5)
        w[2] = rotl32(w[2], 22)

    @staticmethod
    def _ilt(w):
        w[0] = rotr32(w[0], 5)
        w[2] = rotr32(w[2], 22)
        w[0] = (w[0] ^ w[1] ^ w[3]) & 0xFFFFFFFF
        w[2] = (w[2] ^ w[3] ^ (w[1] << 7)) & 0xFFFFFFFF
        w[1] = rotr32(w[1], 1)
        w[3] = rotr32(w[3], 7)
        w[1] = (w[1] ^ w[0] ^ w[2]) & 0xFFFFFFFF
        w[3] = (w[3] ^ w[2] ^ (w[0] << 3)) & 0xFFFFFFFF
        w[0] = rotr32(w[0], 13)
        w[2] = rotr32(w[2], 3)

    @staticmethod
    def _ks(key):
        k = hashlib.sha256(key).digest()
        buf = b''
        for i in range(33):
            buf += hashlib.sha256(k + i.to_bytes(4, 'little')).digest()
        return [[int.from_bytes(buf[(r * 4 + i) * 4:(r * 4 + i + 1) * 4], 'little') for i in range(4)] for r in range(33)]

    @classmethod
    def encrypt(cls, key, data):
        rk = cls._ks(key)
        padded = PADDING(data)
        out = bytearray()
        for bi in range(0, len(padded), 16):
            w = [int.from_bytes(padded[bi + 4 * i:bi + 4 * i + 4], 'little') for i in range(4)]
            for r in range(31):
                for i in range(4):
                    w[i] ^= rk[r][i]
                for i in range(4):
                    w[i] = cls._sb(w[i], cls._S[r % 8])
                cls._lt(w)
            for i in range(4):
                w[i] ^= rk[31][i]
            for i in range(4):
                w[i] = cls._sb(w[i], cls._S[31 % 8])
            for i in range(4):
                w[i] ^= rk[32][i]
            for i in range(4):
                out.extend(w[i].to_bytes(4, 'little'))
        return bytes(out)

    @classmethod
    def decrypt(cls, key, data):
        rk = cls._ks(key)
        inv = cls._get_inv()
        out = bytearray()
        for bi in range(0, len(data), 16):
            w = [int.from_bytes(data[bi + 4 * i:bi + 4 * i + 4], 'little') for i in range(4)]
            for i in range(4):
                w[i] ^= rk[32][i]
            for i in range(4):
                w[i] = cls._sb(w[i], inv[31 % 8])
            for i in range(4):
                w[i] ^= rk[31][i]
            for r in range(30, -1, -1):
                cls._ilt(w)
                for i in range(4):
                    w[i] = cls._sb(w[i], inv[r % 8])
                for i in range(4):
                    w[i] ^= rk[r][i]
            for i in range(4):
                out.extend(w[i].to_bytes(4, 'little'))
        return UNPAD(bytes(out))


def serpent_encrypt(key, data):
    iv = os.urandom(16)
    padded = PADDING(data)
    ct = bytearray()
    prev = iv
    for bi in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[bi:bi + 16], prev))
        enc = _Serpent.encrypt(key, block + b'\x00' * 16)[:16]
        ct.extend(enc)
        prev = enc
    return iv + bytes(ct)


def serpent_decrypt(key, data):
    iv, ct = data[:16], data[16:]
    out = bytearray()
    prev = iv
    for bi in range(0, len(ct), 16):
        block = ct[bi:bi + 16]
        dec = _Serpent.decrypt(key, block + b'\x00' * 16)[:16]
        out.extend(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = block
    return UNPAD(bytes(out))


# ──────────────────────────────────────────────
# 5. Twofish-256-CBC (pure Python)
# ──────────────────────────────────────────────
class _Twofish:
    _q0 = [0xA9, 0x67, 0xB3, 0xE8, 0x04, 0xFD, 0xA3, 0x76, 0x9A, 0x92, 0x80, 0x78, 0xE4, 0xDD, 0xD1, 0x38,
           0x0D, 0xC6, 0x35, 0x98, 0x18, 0xF7, 0xEC, 0x6C, 0x43, 0x75, 0x37, 0x26, 0xFA, 0x13, 0x94, 0x48,
           0xF2, 0xD0, 0x8B, 0x30, 0x84, 0x54, 0xDF, 0x23, 0x19, 0x5B, 0x3D, 0x59, 0xF3, 0xAE, 0xA2, 0x82,
           0x63, 0x01, 0x83, 0x2E, 0xD9, 0x51, 0x9B, 0x7C, 0xA6, 0xEB, 0xA5, 0xBE, 0x16, 0x0C, 0xE3, 0x61,
           0xC0, 0x8C, 0x3A, 0xF5, 0x73, 0x2C, 0x25, 0x0B, 0xBB, 0x4E, 0x89, 0x6B, 0x53, 0x6A, 0xB4, 0xF1,
           0xE1, 0xE6, 0xBD, 0x45, 0xE2, 0xF4, 0xB6, 0x66, 0xCC, 0x95, 0x03, 0x56, 0xD4, 0x1C, 0x1E, 0xD7,
           0xFB, 0xC3, 0x8E, 0xB5, 0xE9, 0xCF, 0xBF, 0xBA, 0xEA, 0x77, 0x39, 0xAF, 0x33, 0xC9, 0x62, 0x71,
           0x81, 0x79, 0x09, 0xAD, 0x24, 0xCD, 0xF9, 0xD8, 0xE5, 0xC5, 0xB9, 0x4D, 0x44, 0x08, 0x86, 0xE7,
           0xA1, 0x1D, 0xAA, 0xED, 0x06, 0x70, 0xB2, 0xD2, 0x41, 0x7B, 0xA0, 0x11, 0x31, 0xC2, 0x27, 0x90,
           0x20, 0xF6, 0x60, 0xFF, 0x96, 0x5C, 0xB1, 0xAB, 0x9E, 0x9C, 0x52, 0x1B, 0x5F, 0x93, 0x0A, 0xEF,
           0x91, 0x85, 0x49, 0xEE, 0x2D, 0x4F, 0x8F, 0x3B, 0x47, 0x87, 0x6D, 0x46, 0xD6, 0x3E, 0x69, 0x64,
           0x2A, 0xCE, 0xCB, 0x2F, 0xFC, 0x97, 0x05, 0x7A, 0xAC, 0x7F, 0xD5, 0x1A, 0x4B, 0x0E, 0xA7, 0x5A,
           0x28, 0x14, 0x3F, 0x29, 0x88, 0x3C, 0x4C, 0x02, 0xB8, 0xDA, 0xB0, 0x17, 0x55, 0x1F, 0x8A, 0x7D,
           0x57, 0xC7, 0x8D, 0x74, 0xB7, 0xC4, 0x9F, 0x72, 0x7E, 0x15, 0x22, 0x12, 0x58, 0x07, 0x99, 0x34,
           0x6E, 0x50, 0xDE, 0x68, 0x65, 0xBC, 0xDB, 0xF8, 0xC8, 0xA8, 0x2B, 0x40, 0xDC, 0xFE, 0x32, 0xA4,
           0xCA, 0x10, 0x21, 0xF0, 0xD3, 0x5D, 0x0F, 0x00, 0x6F, 0x9D, 0x36, 0x42, 0x4A, 0x5E, 0xC1, 0xE0]

    _q1 = [0x75, 0xF3, 0xC6, 0xF4, 0xDB, 0x7B, 0xFB, 0xC8, 0x4A, 0xD3, 0xE6, 0x6B, 0x45, 0x7D, 0xE8, 0x4B,
           0xD6, 0x32, 0xD8, 0xFD, 0x37, 0x71, 0xF1, 0xE1, 0x30, 0x0F, 0xF8, 0x1B, 0x87, 0xFA, 0x06, 0x3F,
           0x5E, 0xBA, 0xAE, 0x5B, 0x8A, 0x00, 0xBC, 0x9D, 0x6D, 0xC1, 0xB1, 0x0E, 0x80, 0x5D, 0xD2, 0xD5,
           0xA0, 0x84, 0x07, 0x14, 0xB5, 0x90, 0x2C, 0xA3, 0xB2, 0x73, 0x4C, 0x54, 0x92, 0x74, 0x36, 0x51,
           0x38, 0xB0, 0xBD, 0x5A, 0xFC, 0x60, 0x62, 0x96, 0x6C, 0x42, 0xF7, 0x10, 0x7C, 0x28, 0x27, 0x8C,
           0x13, 0x95, 0x9C, 0xC7, 0x24, 0x46, 0x3B, 0x70, 0xCA, 0xE3, 0x85, 0xCB, 0x11, 0xD0, 0x93, 0xB8,
           0xA6, 0x83, 0x20, 0xFF, 0x9F, 0x77, 0xC3, 0xCC, 0x03, 0x6F, 0x08, 0xBF, 0x40, 0xE7, 0x2B, 0xE2,
           0x79, 0x0C, 0xAA, 0x82, 0x41, 0x3A, 0xEA, 0xB9, 0xE4, 0x9A, 0xA4, 0x97, 0x7E, 0xDA, 0x7A, 0x17,
           0x66, 0x94, 0xA1, 0x1D, 0x3D, 0xF0, 0xDE, 0xB3, 0x0B, 0x72, 0xA7, 0x1C, 0xEF, 0xD1, 0x53, 0x3E,
           0x8F, 0x33, 0x26, 0x5F, 0xEC, 0x76, 0x2A, 0x49, 0x81, 0x88, 0xEE, 0x21, 0xC4, 0x1A, 0xEB, 0xD9,
           0xC5, 0x39, 0x99, 0xCD, 0xAD, 0x31, 0x8B, 0x01, 0x18, 0x23, 0xDD, 0x1F, 0x4E, 0x2D, 0xF9, 0x48,
           0x4F, 0xF2, 0x65, 0x8E, 0x78, 0x5C, 0x58, 0x19, 0x8D, 0xE5, 0x98, 0x57, 0x67, 0x7F, 0x05, 0x64,
           0xAF, 0x63, 0xB6, 0xFE, 0xF5, 0xB7, 0x3C, 0xA5, 0xCE, 0xE9, 0x68, 0x44, 0xE0, 0x4D, 0x43, 0x69,
           0x29, 0x2E, 0xAC, 0x15, 0x59, 0xA8, 0x0A, 0x9E, 0x6E, 0x47, 0xDF, 0x34, 0x35, 0x6A, 0xCF, 0xDC,
           0x22, 0xC9, 0xC0, 0x9B, 0x89, 0xD4, 0xED, 0xAB, 0x12, 0xA2, 0x0D, 0x52, 0xBB, 0x02, 0x2F, 0xA9,
           0xD7, 0x61, 0x1E, 0xB4, 0x50, 0x04, 0xF6, 0xC2, 0x16, 0x25, 0x86, 0x56, 0x55, 0x09, 0xBE, 0x91]

    _MDS = [[0x01, 0xEF, 0x5B, 0x5B], [0x5B, 0xEF, 0xEF, 0x01], [0xEF, 0x5B, 0x01, 0xEF], [0xEF, 0x01, 0xEF, 0x5B]]

    @staticmethod
    def _gm(a, b):
        p = 0
        for _ in range(8):
            if b & 1:
                p ^= a
            hi = a & 0x80
            a = (a << 1) & 0xFF
            if hi:
                a ^= 0x14D
            b >>= 1
        return p

    @staticmethod
    def _ks(key):
        k = hashlib.sha256(key if len(key) == 32 else hashlib.sha256(key).digest()).digest()
        buf = b''
        for _ in range(60):
            buf += hashlib.sha256(k + len(buf).to_bytes(4, 'little')).digest()
        sk = [int.from_bytes(buf[i * 4:(i + 1) * 4], 'little') for i in range(4)]
        rk = [int.from_bytes(buf[(4 + i) * 4:(5 + i) * 4], 'little') for i in range(40)]
        return sk, rk

    @staticmethod
    def _g(x, i, sk):
        b = [(x >> j) & 0xFF for j in (0, 8, 16, 24)]
        p = [_Twofish._q0[b[0]], _Twofish._q1[b[1]], _Twofish._q0[b[2]], _Twofish._q1[b[3]]]
        for j in range(4):
            p[j] ^= (sk[(i + j) % 4] >> (j * 8)) & 0xFF
        o = [0] * 4
        for r in range(4):
            for c in range(4):
                o[r] ^= _Twofish._gm(_Twofish._MDS[r][c], p[c])
        return (o[0] | (o[1] << 8) | (o[2] << 16) | (o[3] << 24)) & 0xFFFFFFFF

    @classmethod
    def encrypt_block(cls, key, block):
        sk, rk = cls._ks(key)
        w = [int.from_bytes(block[4 * j:4 * j + 4], 'little') for j in range(4)]
        for j in range(4):
            w[j] ^= rk[j]
        for r in range(16):
            t0 = cls._g(w[0], 2 * r, sk)
            t1 = cls._g(rotl32(w[1], 8), 2 * r + 1, sk)
            t0 = (t0 + 2 * t1 + rk[4 + 2 * r]) & 0xFFFFFFFF
            t1 = (2 * t0 + t1 + rk[4 + 2 * r + 1]) & 0xFFFFFFFF
            w[2] ^= t0
            w[2] = rotr32(w[2], 1)
            w[3] = rotl32(w[3], 1) ^ t1
            if r < 15:
                w[0], w[1], w[2], w[3] = w[2], w[3], w[0], w[1]
        for j in range(4):
            w[j] ^= rk[4 + j]
        return b''.join(w[j].to_bytes(4, 'little') for j in range(4))

    @classmethod
    def decrypt_block(cls, key, block):
        sk, rk = cls._ks(key)
        w = [int.from_bytes(block[4 * j:4 * j + 4], 'little') for j in range(4)]
        for j in range(4):
            w[j] ^= rk[4 + j]
        for r in range(15, -1, -1):
            if r < 15:
                w[0], w[1], w[2], w[3] = w[2], w[3], w[0], w[1]
            t0 = cls._g(w[0], 2 * r, sk)
            t1 = cls._g(rotl32(w[1], 8), 2 * r + 1, sk)
            t0 = (t0 + 2 * t1 + rk[4 + 2 * r]) & 0xFFFFFFFF
            t1 = (2 * t0 + t1 + rk[4 + 2 * r + 1]) & 0xFFFFFFFF
            w[2] = rotl32(w[2], 1) ^ t0
            w[3] = rotr32(w[3] ^ t1, 1)
        for j in range(4):
            w[j] ^= rk[j]
        return b''.join(w[j].to_bytes(4, 'little') for j in range(4))


def twofish_encrypt(key, data):
    iv = os.urandom(16)
    padded = PADDING(data)
    ct = bytearray()
    prev = iv
    for bi in range(0, len(padded), 16):
        block = bytes(a ^ b for a, b in zip(padded[bi:bi + 16], prev))
        enc = _Twofish.encrypt_block(key, block)
        ct.extend(enc)
        prev = enc
    return iv + bytes(ct)


def twofish_decrypt(key, data):
    iv, ct = data[:16], data[16:]
    out = bytearray()
    prev = iv
    for bi in range(0, len(ct), 16):
        block = ct[bi:bi + 16]
        dec = _Twofish.decrypt_block(key, block)
        out.extend(bytes(a ^ b for a, b in zip(dec, prev)))
        prev = block
    return UNPAD(bytes(out))


# ──────────────────────────────────────────────
# 6. Blowfish-448-CBC
# ──────────────────────────────────────────────
def blowfish_encrypt(key, data):
    iv = os.urandom(8)
    padded = PADDING(data)
    c = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    ct = c.encrypt(padded)
    return iv + ct


def blowfish_decrypt(key, data):
    iv, ct = data[:8], data[8:]
    c = Blowfish.new(key, Blowfish.MODE_CBC, iv)
    return UNPAD(c.decrypt(ct))


# ──────────────────────────────────────────────
# 7. CAST5-128-CBC
# ──────────────────────────────────────────────
def cast_encrypt(key, data):
    k = hashlib.sha256(key).digest()[:16]
    iv = os.urandom(8)
    padded = PADDING(data)
    c = CAST.new(k, CAST.MODE_CBC, iv)
    ct = c.encrypt(padded)
    return iv + ct


def cast_decrypt(key, data):
    k = hashlib.sha256(key).digest()[:16]
    iv, ct = data[:8], data[8:]
    c = CAST.new(k, CAST.MODE_CBC, iv)
    return UNPAD(c.decrypt(ct))


# ──────────────────────────────────────────────
# 8. TripleDES-192-CBC
# ──────────────────────────────────────────────
def des3_encrypt(key, data):
    k = hashlib.sha256(key).digest()[:24]
    iv = os.urandom(8)
    padded = PADDING(data)
    c = DES3.new(k, DES3.MODE_CBC, iv)
    ct = c.encrypt(padded)
    return iv + ct


def des3_decrypt(key, data):
    k = hashlib.sha256(key).digest()[:24]
    iv, ct = data[:8], data[8:]
    c = DES3.new(k, DES3.MODE_CBC, iv)
    return UNPAD(c.decrypt(ct))


# ──────────────────────────────────────────────
# 9. SM4-CBC (Chinese standard)
# ──────────────────────────────────────────────
def sm4_encrypt(key, data):
    k = hashlib.sha256(key).digest()[:16]
    iv = os.urandom(16)
    padded = PADDING(data)
    c = CryC(alg.SM4(k), md.CBC(iv))
    e = c.encryptor()
    ct = e.update(padded) + e.finalize()
    return iv + ct


def sm4_decrypt(key, data):
    k = hashlib.sha256(key).digest()[:16]
    iv, ct = data[:16], data[16:]
    c = CryC(alg.SM4(k), md.CBC(iv))
    d = c.decryptor()
    return UNPAD(d.update(ct) + d.finalize())


# ──────────────────────────────────────────────
# 10. SEED-CBC (Korean standard)
# ──────────────────────────────────────────────
def seed_encrypt(key, data):
    k = hashlib.sha256(key).digest()[:16]
    iv = os.urandom(16)
    padded = PADDING(data)
    c = CryC(alg.SEED(k), md.CBC(iv))
    e = c.encryptor()
    ct = e.update(padded) + e.finalize()
    return iv + ct


def seed_decrypt(key, data):
    k = hashlib.sha256(key).digest()[:16]
    iv, ct = data[:16], data[16:]
    c = CryC(alg.SEED(k), md.CBC(iv))
    d = c.decryptor()
    return UNPAD(d.update(ct) + d.finalize())


# ──────────────────────────────────────────────
# CIPHER REGISTRY
# ──────────────────────────────────────────────
CIPHERS = [
    {'id': 'aes', 'name': 'AES-256-GCM', 'desc': 'Advanced Encryption Standard — Gold Standard Worldwide', 'key_size': 32, 'enc': aes_encrypt, 'dec': aes_decrypt},
    {'id': 'chacha', 'name': 'ChaCha20-Poly1305', 'desc': 'Modern Stream Cipher — Google\'s Choice for TLS', 'key_size': 32, 'enc': chacha_encrypt, 'dec': chacha_decrypt},
    {'id': 'camellia', 'name': 'Camellia-256-CBC', 'desc': 'Japanese ISO/IEC 18033-3 — CRYPTREC / NESSIE Approved', 'key_size': 32, 'enc': camellia_encrypt, 'dec': camellia_decrypt},
    {'id': 'serpent', 'name': 'Serpent-256-CBC', 'desc': 'AES Finalist — Most Conservative Design (32 Rounds)', 'key_size': 32, 'enc': serpent_encrypt, 'dec': serpent_decrypt},
    {'id': 'twofish', 'name': 'Twofish-256-CBC', 'desc': 'AES Finalist — Designed by Bruce Schneier', 'key_size': 32, 'enc': twofish_encrypt, 'dec': twofish_decrypt},
    {'id': 'blowfish', 'name': 'Blowfish-448-CBC', 'desc': 'Classic Strong Cipher — Blowfish Family (448-bit Key)', 'key_size': 56, 'enc': blowfish_encrypt, 'dec': blowfish_decrypt},
    {'id': 'cast', 'name': 'CAST5-128-CBC', 'desc': 'CAST Design — Carlisle Adams / Stafford Tavares', 'key_size': 16, 'enc': cast_encrypt, 'dec': cast_decrypt},
    {'id': 'des3', 'name': 'TripleDES-192-CBC', 'desc': 'Triple DES — NIST Standard (112-bit Security)', 'key_size': 24, 'enc': des3_encrypt, 'dec': des3_decrypt},
    {'id': 'sm4', 'name': 'SM4-CBC', 'desc': 'Chinese National Standard — GB/T 32907-2016', 'key_size': 16, 'enc': sm4_encrypt, 'dec': sm4_decrypt},
    {'id': 'seed', 'name': 'SEED-CBC', 'desc': 'Korean National Standard — KISA / ISO/IEC 18033-3', 'key_size': 16, 'enc': seed_encrypt, 'dec': seed_decrypt},
]

CIPHER_MAP = {c['id']: c for c in CIPHERS}
