import os
import base64
import secrets
import hashlib
import random
import string
from .ciphers import CIPHERS, CIPHER_MAP
from .obfuscator import obfuscate

_PREFIX = 'Js'


def _uid():
    return _PREFIX + ''.join(random.choices(string.ascii_letters, k=6))


_TWOFISH_INLINE = '''
import hashlib
class _Tf:
 _q0=[0xA9,0x67,0xB3,0xE8,0x04,0xFD,0xA3,0x76,0x9A,0x92,0x80,0x78,0xE4,0xDD,0xD1,0x38,0x0D,0xC6,0x35,0x98,0x18,0xF7,0xEC,0x6C,0x43,0x75,0x37,0x26,0xFA,0x13,0x94,0x48,0xF2,0xD0,0x8B,0x30,0x84,0x54,0xDF,0x23,0x19,0x5B,0x3D,0x59,0xF3,0xAE,0xA2,0x82,0x63,0x01,0x83,0x2E,0xD9,0x51,0x9B,0x7C,0xA6,0xEB,0xA5,0xBE,0x16,0x0C,0xE3,0x61,0xC0,0x8C,0x3A,0xF5,0x73,0x2C,0x25,0x0B,0xBB,0x4E,0x89,0x6B,0x53,0x6A,0xB4,0xF1,0xE1,0xE6,0xBD,0x45,0xE2,0xF4,0xB6,0x66,0xCC,0x95,0x03,0x56,0xD4,0x1C,0x1E,0xD7,0xFB,0xC3,0x8E,0xB5,0xE9,0xCF,0xBF,0xBA,0xEA,0x77,0x39,0xAF,0x33,0xC9,0x62,0x71,0x81,0x79,0x09,0xAD,0x24,0xCD,0xF9,0xD8,0xE5,0xC5,0xB9,0x4D,0x44,0x08,0x86,0xE7,0xA1,0x1D,0xAA,0xED,0x06,0x70,0xB2,0xD2,0x41,0x7B,0xA0,0x11,0x31,0xC2,0x27,0x90,0x20,0xF6,0x60,0xFF,0x96,0x5C,0xB1,0xAB,0x9E,0x9C,0x52,0x1B,0x5F,0x93,0x0A,0xEF,0x91,0x85,0x49,0xEE,0x2D,0x4F,0x8F,0x3B,0x47,0x87,0x6D,0x46,0xD6,0x3E,0x69,0x64,0x2A,0xCE,0xCB,0x2F,0xFC,0x97,0x05,0x7A,0xAC,0x7F,0xD5,0x1A,0x4B,0x0E,0xA7,0x5A,0x28,0x14,0x3F,0x29,0x88,0x3C,0x4C,0x02,0xB8,0xDA,0xB0,0x17,0x55,0x1F,0x8A,0x7D,0x57,0xC7,0x8D,0x74,0xB7,0xC4,0x9F,0x72,0x7E,0x15,0x22,0x12,0x58,0x07,0x99,0x34,0x6E,0x50,0xDE,0x68,0x65,0xBC,0xDB,0xF8,0xC8,0xA8,0x2B,0x40,0xDC,0xFE,0x32,0xA4,0xCA,0x10,0x21,0xF0,0xD3,0x5D,0x0F,0x00,0x6F,0x9D,0x36,0x42,0x4A,0x5E,0xC1,0xE0]
 _q1=[0x75,0xF3,0xC6,0xF4,0xDB,0x7B,0xFB,0xC8,0x4A,0xD3,0xE6,0x6B,0x45,0x7D,0xE8,0x4B,0xD6,0x32,0xD8,0xFD,0x37,0x71,0xF1,0xE1,0x30,0x0F,0xF8,0x1B,0x87,0xFA,0x06,0x3F,0x5E,0xBA,0xAE,0x5B,0x8A,0x00,0xBC,0x9D,0x6D,0xC1,0xB1,0x0E,0x80,0x5D,0xD2,0xD5,0xA0,0x84,0x07,0x14,0xB5,0x90,0x2C,0xA3,0xB2,0x73,0x4C,0x54,0x92,0x74,0x36,0x51,0x38,0xB0,0xBD,0x5A,0xFC,0x60,0x62,0x96,0x6C,0x42,0xF7,0x10,0x7C,0x28,0x27,0x8C,0x13,0x95,0x9C,0xC7,0x24,0x46,0x3B,0x70,0xCA,0xE3,0x85,0xCB,0x11,0xD0,0x93,0xB8,0xA6,0x83,0x20,0xFF,0x9F,0x77,0xC3,0xCC,0x03,0x6F,0x08,0xBF,0x40,0xE7,0x2B,0xE2,0x79,0x0C,0xAA,0x82,0x41,0x3A,0xEA,0xB9,0xE4,0x9A,0xA4,0x97,0x7E,0xDA,0x7A,0x17,0x66,0x94,0xA1,0x1D,0x3D,0xF0,0xDE,0xB3,0x0B,0x72,0xA7,0x1C,0xEF,0xD1,0x53,0x3E,0x8F,0x33,0x26,0x5F,0xEC,0x76,0x2A,0x49,0x81,0x88,0xEE,0x21,0xC4,0x1A,0xEB,0xD9,0xC5,0x39,0x99,0xCD,0xAD,0x31,0x8B,0x01,0x18,0x23,0xDD,0x1F,0x4E,0x2D,0xF9,0x48,0x4F,0xF2,0x65,0x8E,0x78,0x5C,0x58,0x19,0x8D,0xE5,0x98,0x57,0x67,0x7F,0x05,0x64,0xAF,0x63,0xB6,0xFE,0xF5,0xB7,0x3C,0xA5,0xCE,0xE9,0x68,0x44,0xE0,0x4D,0x43,0x69,0x29,0x2E,0xAC,0x15,0x59,0xA8,0x0A,0x9E,0x6E,0x47,0xDF,0x34,0x35,0x6A,0xCF,0xDC,0x22,0xC9,0xC0,0x9B,0x89,0xD4,0xED,0xAB,0x12,0xA2,0x0D,0x52,0xBB,0x02,0x2F,0xA9,0xD7,0x61,0x1E,0xB4,0x50,0x04,0xF6,0xC2,0x16,0x25,0x86,0x56,0x55,0x09,0xBE,0x91]
 _MDS=[[0x01,0xEF,0x5B,0x5B],[0x5B,0xEF,0xEF,0x01],[0xEF,0x5B,0x01,0xEF],[0xEF,0x01,0xEF,0x5B]]
 @staticmethod
 def _gm(a,b):
  p=0
  for _ in range(8):
   if b&1:p^=a
   hi=a&0x80;a=(a<<1)&0xff
   if hi:a^=0x14d
   b>>=1
  return p
 @staticmethod
 def _ks(key):
  k=hashlib.sha256(key if len(key)==32 else hashlib.sha256(key).digest()).digest()
  buf=b''
  for _ in range(60):
   buf+=hashlib.sha256(k+len(buf).to_bytes(4,'little')).digest()
  sk=[int.from_bytes(buf[i*4:(i+1)*4],'little')for i in range(4)]
  rk=[int.from_bytes(buf[(4+i)*4:(5+i)*4],'little')for i in range(40)]
  return sk,rk
 @staticmethod
 def _g(x,i,sk):
  b=[(x>>j)&0xff for j in(0,8,16,24)]
  p=[_Tf._q0[b[0]],_Tf._q1[b[1]],_Tf._q0[b[2]],_Tf._q1[b[3]]]
  for j in range(4):p[j]^=(sk[(i+j)%4]>>(j*8))&0xff
  o=[0]*4
  for r in range(4):
   for c in range(4):o[r]^=_Tf._gm(_Tf._MDS[r][c],p[c])
  return (o[0]|(o[1]<<8)|(o[2]<<16)|(o[3]<<24))&0xffffffff
 @staticmethod
 def _db(key,block):
  sk,rk=_Tf._ks(key)
  w=[int.from_bytes(block[4*j:4*j+4],'little')for j in range(4)]
  for j in range(4):w[j]^=rk[4+j]
  for r in range(15,-1,-1):
   if r<15:w[0],w[1],w[2],w[3]=w[2],w[3],w[0],w[1]
   t0=_Tf._g(w[0],2*r,sk)
   t1=_Tf._g(_rotl32(w[1],8),2*r+1,sk)
   t0=(t0+2*t1+rk[4+2*r])&0xffffffff
   t1=(2*t0+t1+rk[4+2*r+1])&0xffffffff
   w[2]=_rotl32(w[2],1)^t0
   w[3]=_rotr32(w[3]^t1,1)
  for j in range(4):w[j]^=rk[j]
  return b''.join(w[j].to_bytes(4,'little')for j in range(4))
 @staticmethod
 def dec_cbc(key,data,iv):
  out=b''
  prev=iv
  for i in range(0,len(data),16):
   blk=data[i:i+16]
   dec=_Tf._db(key,blk)
   out+=bytes(a^b for a,b in zip(dec,prev))
   prev=blk
  pad=out[-1]
  return out[:-pad]
'''

_SERPENT_INLINE = '''
import hashlib
class _Sp:
 _S=[[3,8,15,1,10,6,5,11,14,13,4,2,7,0,9,12],[15,12,2,7,9,0,5,10,1,11,14,8,6,13,3,4],[8,6,7,9,3,12,10,15,13,1,14,4,0,11,5,2],[0,15,11,8,12,9,6,3,13,1,2,4,10,7,14,5],[1,15,8,3,12,0,11,6,2,5,4,10,9,14,7,13],[15,5,2,11,4,10,9,12,0,3,14,8,13,6,7,1],[7,2,12,5,8,4,6,11,14,9,1,15,13,3,10,0],[1,13,15,0,14,8,2,11,7,4,12,10,9,3,5,6]]
 @staticmethod
 def _si(s):
  inv=[0]*16
  for i in range(16):inv[s[i]]=i
  return inv
 _I=None
 @classmethod
 def _ig(cls):
  if cls._I is None:cls._I=[cls._si(s)for s in cls._S]
  return cls._I
 @staticmethod
 def _sb(w,s):
  o=0
  for i in range(8):o|=(s[(w>>(i*4))&0xf]<<(i*4))
  return o
 @staticmethod
 def _lt(w):
  w[0]=_rotl32(w[0],13);w[2]=_rotl32(w[2],3)
  w[1]=(w[1]^w[0]^w[2])&0xffffffff;w[3]=(w[3]^w[2]^(w[0]<<3))&0xffffffff
  w[1]=_rotl32(w[1],1);w[3]=_rotl32(w[3],7)
  w[0]=(w[0]^w[1]^w[3])&0xffffffff;w[2]=(w[2]^w[3]^(w[1]<<7))&0xffffffff
  w[0]=_rotl32(w[0],5);w[2]=_rotl32(w[2],22)
 @staticmethod
 def _ilt(w):
  w[0]=_rotr32(w[0],5);w[2]=_rotr32(w[2],22)
  w[0]=(w[0]^w[1]^w[3])&0xffffffff;w[2]=(w[2]^w[3]^(w[1]<<7))&0xffffffff
  w[1]=_rotr32(w[1],1);w[3]=_rotr32(w[3],7)
  w[1]=(w[1]^w[0]^w[2])&0xffffffff;w[3]=(w[3]^w[2]^(w[0]<<3))&0xffffffff
  w[0]=_rotr32(w[0],13);w[2]=_rotr32(w[2],3)
 @staticmethod
 def _ks(key):
  k=hashlib.sha256(key).digest()
  buf=b''
  for i in range(33):buf+=hashlib.sha256(k+i.to_bytes(4,'little')).digest()
  return[[int.from_bytes(buf[(r*4+i)*4:(r*4+i+1)*4],'little')for i in range(4)]for r in range(33)]
 @classmethod
 def _db(cls,key,block):
  rk=cls._ks(key);inv=cls._ig()
  w=[int.from_bytes(block[4*i:4*i+4],'little')for i in range(4)]
  for i in range(4):w[i]^=rk[32][i]
  for i in range(4):w[i]=cls._sb(w[i],inv[31%8])
  for i in range(4):w[i]^=rk[31][i]
  for r in range(30,-1,-1):
   cls._ilt(w)
   for i in range(4):w[i]=cls._sb(w[i],inv[r%8])
   for i in range(4):w[i]^=rk[r][i]
  return b''.join(w[i].to_bytes(4,'little')for i in range(4))
 @classmethod
 def dec_cbc(cls,key,data,iv):
  out=b''
  prev=iv
  for i in range(0,len(data),16):
   blk=data[i:i+16]
   dec=cls._db(key,blk)
   out+=bytes(a^b for a,b in zip(dec,prev))
   prev=blk
  pad=out[-1]
  return out[:-pad]
'''


def _gen_loader(payload_b64: str, keys_b64: list, cipher_chain: list) -> str:
    decrypt_chain = list(reversed(cipher_chain))
    keys_rev = list(reversed(keys_b64))
    n = len(decrypt_chain)

    names = {}
    for token in ['b64_mod', 'hash_mod']:
        names[token] = _uid()

    for i in range(n):
        suf = f'_{i}' if i > 0 else ''
        names[f'enc_var{suf}'] = _uid()
        names[f'enc_bytes{suf}'] = _uid()
        names[f'key_var{suf}'] = _uid()

        names[f'iv_var{suf}'] = _uid()
        names[f'ct_var{suf}'] = _uid()
        names[f'dk_var{suf}'] = _uid()

    payload_lines = '\\\n    '.join(
        f'"{payload_b64[i:i+64]}"'
        for i in range(0, len(payload_b64), 64)
    )

    lines = [f'# Protected by 𝓙𝓸𝓴𝓮𝓻丨𝓜4 Sanctum — Multi-Layer Encryption Engine']
    lines.append(f'# Algorithms: {", ".join(cipher_chain)}')
    lines.append(f'import base64 as {names["b64_mod"]}')
    lines.append(f'import hashlib as {names["hash_mod"]}')

    has_tf = 'twofish' in cipher_chain
    has_sp = 'serpent' in cipher_chain
    if has_tf or has_sp:
        lines.append(f'def _rotl32(x,n): return ((x<<n)|(x>>(32-n)))&0xffffffff')
        lines.append(f'def _rotr32(x,n): return ((x>>n)|(x<<(32-n)))&0xffffffff')
    if has_tf:
        lines.append(_TWOFISH_INLINE)
    if has_sp:
        lines.append(_SERPENT_INLINE)

    prev_eb = None
    for i, cid in enumerate(decrypt_chain):
        suf = f'_{i}' if i > 0 else ''
        ev = names[f'enc_var{suf}']
        eb = names[f'enc_bytes{suf}']
        kv = names[f'key_var{suf}']
        iv_v = names[f'iv_var{suf}']
        ctv = names[f'ct_var{suf}']
        dkv = names[f'dk_var{suf}']

        input_src = f'{payload_lines}' if prev_eb is None else prev_eb

        if cid == 'aes':
            lines.append(f'from Crypto.Cipher import AES as _A{suf}')
            lines.append(f'{ev} = {input_src}')
            lines.append(f'{eb} = {names["b64_mod"]}.b64decode({ev})')
            lines.append(f'{kv} = {names["b64_mod"]}.b64decode("{keys_rev[i]}")')
            lines.append(f'_n{suf} = {eb}[:12]')
            lines.append(f'_c{suf} = {eb}[12:-16]')
            lines.append(f'_t{suf} = {eb}[-16:]')
            lines.append(f'_d{suf} = _A{suf}.new({kv}, _A{suf}.MODE_GCM, nonce=_n{suf})')
            lines.append(f'{eb} = _d{suf}.decrypt_and_verify(_c{suf}, _t{suf})')

        elif cid == 'chacha':
            lines.append(f'from Crypto.Cipher import ChaCha20_Poly1305 as _C{suf}')
            lines.append(f'{ev} = {input_src}')
            lines.append(f'{eb} = {names["b64_mod"]}.b64decode({ev})')
            lines.append(f'{kv} = {names["b64_mod"]}.b64decode("{keys_rev[i]}")')
            lines.append(f'_n{suf} = {eb}[:12]')
            lines.append(f'_ct{suf} = {eb}[12:-16]')
            lines.append(f'_t{suf} = {eb}[-16:]')
            lines.append(f'_ci{suf} = _C{suf}.new(key={kv}, nonce=_n{suf})')
            lines.append(f'{eb} = _ci{suf}.decrypt_and_verify(_ct{suf}, _t{suf})')

        elif cid == 'blowfish':
            lines.append(f'from Crypto.Cipher import Blowfish as _B{suf}')
            lines.append(f'{ev} = {input_src}')
            lines.append(f'{eb} = {names["b64_mod"]}.b64decode({ev})')
            lines.append(f'{kv} = {names["b64_mod"]}.b64decode("{keys_rev[i]}")')
            lines.append(f'{iv_v} = {eb}[:8]')
            lines.append(f'{ctv} = {eb}[8:]')
            lines.append(f'_b{suf} = _B{suf}.new({kv}, _B{suf}.MODE_CBC, {iv_v})')
            lines.append(f'_p{suf} = _b{suf}.decrypt({ctv})')
            lines.append(f'{eb} = _p{suf}[:-_p{suf}[-1]]')

        elif cid == 'cast':
            lines.append(f'from Crypto.Cipher import CAST as _C{suf}')
            lines.append(f'{ev} = {input_src}')
            lines.append(f'{eb} = {names["b64_mod"]}.b64decode({ev})')
            lines.append(f'{kv} = {names["b64_mod"]}.b64decode("{keys_rev[i]}")')
            lines.append(f'{iv_v} = {eb}[:8]')
            lines.append(f'{ctv} = {eb}[8:]')
            lines.append(f'{dkv} = {names["hash_mod"]}.sha256({kv}).digest()[:16]')
            lines.append(f'_c{suf} = _C{suf}.new({dkv}, _C{suf}.MODE_CBC, {iv_v})')
            lines.append(f'_p{suf} = _c{suf}.decrypt({ctv})')
            lines.append(f'{eb} = _p{suf}[:-_p{suf}[-1]]')

        elif cid == 'des3':
            lines.append(f'from Crypto.Cipher import DES3 as _D{suf}')
            lines.append(f'{ev} = {input_src}')
            lines.append(f'{eb} = {names["b64_mod"]}.b64decode({ev})')
            lines.append(f'{kv} = {names["b64_mod"]}.b64decode("{keys_rev[i]}")')
            lines.append(f'{iv_v} = {eb}[:8]')
            lines.append(f'{ctv} = {eb}[8:]')
            lines.append(f'{dkv} = {names["hash_mod"]}.sha256({kv}).digest()[:24]')
            lines.append(f'_d{suf} = _D{suf}.new({dkv}, _D{suf}.MODE_CBC, {iv_v})')
            lines.append(f'_p{suf} = _d{suf}.decrypt({ctv})')
            lines.append(f'{eb} = _p{suf}[:-_p{suf}[-1]]')

        elif cid == 'twofish':
            lines.append(f'{ev} = {input_src}')
            lines.append(f'{eb} = {names["b64_mod"]}.b64decode({ev})')
            lines.append(f'{kv} = {names["b64_mod"]}.b64decode("{keys_rev[i]}")')
            lines.append(f'{iv_v} = {eb}[:16]')
            lines.append(f'{ctv} = {eb}[16:]')
            lines.append(f'{eb} = _Tf.dec_cbc({kv}, {ctv}, {iv_v})')

        elif cid == 'serpent':
            lines.append(f'{ev} = {input_src}')
            lines.append(f'{eb} = {names["b64_mod"]}.b64decode({ev})')
            lines.append(f'{kv} = {names["b64_mod"]}.b64decode("{keys_rev[i]}")')
            lines.append(f'{iv_v} = {eb}[:16]')
            lines.append(f'{ctv} = {eb}[16:]')
            lines.append(f'{eb} = _Sp.dec_cbc({kv}, {ctv}, {iv_v})')

        elif cid == 'camellia':
            lines.append(f'from cryptography.hazmat.primitives.ciphers import Cipher as _C{suf}, algorithms as _A{suf}, modes as _M{suf}')
            lines.append(f'from cryptography.hazmat.primitives import padding as _P{suf}')
            lines.append(f'{ev} = {input_src}')
            lines.append(f'{eb} = {names["b64_mod"]}.b64decode({ev})')
            lines.append(f'{kv} = {names["b64_mod"]}.b64decode("{keys_rev[i]}")')
            lines.append(f'{iv_v} = {eb}[:16]')
            lines.append(f'{ctv} = {eb}[16:]')
            lines.append(f'_ci{suf} = _C{suf}(_A{suf}.Camellia({kv}), _M{suf}.CBC({iv_v}))')
            lines.append(f'_d{suf} = _ci{suf}.decryptor()')
            lines.append(f'_p{suf} = _d{suf}.update({ctv}) + _d{suf}.finalize()')
            lines.append(f'_u{suf} = _P{suf}.PKCS7(128).unpadder()')
            lines.append(f'{eb} = _u{suf}.update(_p{suf}) + _u{suf}.finalize()')

        elif cid == 'sm4':
            lines.append(f'from cryptography.hazmat.primitives.ciphers import Cipher as _C{suf}, algorithms as _A{suf}, modes as _M{suf}')
            lines.append(f'from cryptography.hazmat.primitives import padding as _P{suf}')
            lines.append(f'{ev} = {input_src}')
            lines.append(f'{eb} = {names["b64_mod"]}.b64decode({ev})')
            lines.append(f'{kv} = {names["b64_mod"]}.b64decode("{keys_rev[i]}")')
            lines.append(f'{iv_v} = {eb}[:16]')
            lines.append(f'{ctv} = {eb}[16:]')
            kk_name = _uid()
            lines.append(f'{kk_name} = {names["hash_mod"]}.sha256({kv}).digest()[:16]')
            lines.append(f'_ci{suf} = _C{suf}(_A{suf}.SM4({kk_name}), _M{suf}.CBC({iv_v}))')
            lines.append(f'_d{suf} = _ci{suf}.decryptor()')
            lines.append(f'_p{suf} = _d{suf}.update({ctv}) + _d{suf}.finalize()')
            lines.append(f'_u{suf} = _P{suf}.PKCS7(128).unpadder()')
            lines.append(f'{eb} = _u{suf}.update(_p{suf}) + _u{suf}.finalize()')

        elif cid == 'seed':
            lines.append(f'from cryptography.hazmat.primitives.ciphers import Cipher as _C{suf}, algorithms as _A{suf}, modes as _M{suf}')
            lines.append(f'from cryptography.hazmat.primitives import padding as _P{suf}')
            lines.append(f'{ev} = {input_src}')
            lines.append(f'{eb} = {names["b64_mod"]}.b64decode({ev})')
            lines.append(f'{kv} = {names["b64_mod"]}.b64decode("{keys_rev[i]}")')
            lines.append(f'{iv_v} = {eb}[:16]')
            lines.append(f'{ctv} = {eb}[16:]')
            kk_name = _uid()
            lines.append(f'{kk_name} = {names["hash_mod"]}.sha256({kv}).digest()[:16]')
            lines.append(f'_ci{suf} = _C{suf}(_A{suf}.SEED({kk_name}), _M{suf}.CBC({iv_v}))')
            lines.append(f'_d{suf} = _ci{suf}.decryptor()')
            lines.append(f'_p{suf} = _d{suf}.update({ctv}) + _d{suf}.finalize()')
            lines.append(f'_u{suf} = _P{suf}.PKCS7(128).unpadder()')
            lines.append(f'{eb} = _u{suf}.update(_p{suf}) + _u{suf}.finalize()')

        else:
            raise ValueError(f'Unknown cipher: {cid}')

        prev_eb = eb

    lines.append(f'exec({prev_eb}.decode())')

    return '\n'.join(lines)


def protect(source: str, cipher_ids: list = None, obfuscate_flags: dict = None) -> dict:
    if cipher_ids is None:
        cipher_ids = ['aes']
    if obfuscate_flags is None:
        obfuscate_flags = {'rename': True, 'strip_docs': True, 'deadcode': True}

    result_source = source

    if any(obfuscate_flags.values()):
        result_source = obfuscate(result_source, **obfuscate_flags)

    layers = []
    keys = []
    current_data = result_source.encode('utf-8')

    for cid in cipher_ids:
        c = CIPHER_MAP[cid]
        key = secrets.token_bytes(c['key_size'])
        keys.append(key)
        current_data = c['enc'](key, current_data)
        current_data = base64.b64encode(current_data)
        layers.append(c['name'])

    payload_b64 = current_data.decode()
    keys_b64 = [base64.b64encode(k).decode() for k in keys]
    loader = _gen_loader(payload_b64, keys_b64, cipher_ids)

    return {
        'loader': loader,
        'keys_b64': keys_b64,
        'layers': layers,
        'payload_b64': payload_b64,
    }
