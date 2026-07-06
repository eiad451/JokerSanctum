# Protected by 𝓙𝓸𝓴𝓮𝓻丨𝓜4 Sanctum — Multi-Layer Encryption Engine
# Algorithms: serpent, aes
import base64 as JsISsQnB
import hashlib as JsFLXnjw
def _rotl32(x,n): return ((x<<n)|(x>>(32-n)))&0xffffffff
def _rotr32(x,n): return ((x>>n)|(x<<(32-n)))&0xffffffff

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

from Crypto.Cipher import AES as _A
JsVInvfx = "MvxTqmWlWYmJ9rchnr4C90Q0ryG/qWtMVsXEfBcA5tey5S5SrsiuCi9kI/K3wWo1"\
    "seMTqugDZkxDKY6vtXyOXIVS+8SM4JnmY/u3OCGjcoAeouP+kkAhpxSGDO0ASkUL"\
    "tDuGhvG/RDQR6YjLwTwqHGFQ4SIPrrp0RJhwYmT6aL5dtMDzUSLsF9b3gxLLAC94"\
    "opsCEAyHmvbO//xwVixZpHOC919D/TeSDCnRS8eZZwvNoa455GTHDssgNYRO3ECH"\
    "lnFOPI6UC3EiiQ7VOaftvYOmfWYPwRmhVHxsXSM4Eb4cNyYhbYMtQL3+0wJOfe9S"\
    "fcRbxg=="
JsbtGpYX = JsISsQnB.b64decode(JsVInvfx)
JsIUTgUS = JsISsQnB.b64decode("7A/ODDxU6ArO/bW4/m2lY8efrEU1b8PYDnc7HcE01Fw=")
_n = JsbtGpYX[:12]
_c = JsbtGpYX[12:-16]
_t = JsbtGpYX[-16:]
_d = _A.new(JsIUTgUS, _A.MODE_GCM, nonce=_n)
JsbtGpYX = _d.decrypt_and_verify(_c, _t)
JsVWAxSq = JsbtGpYX
JssTaaaf = JsISsQnB.b64decode(JsVWAxSq)
JsLUuDrl = JsISsQnB.b64decode("JSfFAsJ0/unmiSCkcx9N/j9cbAERe1rDlehuMpVmQ44=")
JsMnHWIn = JssTaaaf[:16]
JsiIirBE = JssTaaaf[16:]
JssTaaaf = _Sp.dec_cbc(JsLUuDrl, JsiIirBE, JsMnHWIn)
exec(JssTaaaf.decode())