#!/usr/bin/env python3
"""Pure-Python Merkle-Damgard length-extension (md5 / sha1 / sha256).

No C build, no internet — a drop-in replacement for hashpumpy on this image.
Use when a server authenticates with a *secret-prefix MAC*  tag = H(secret || data)
(NOT HMAC) and you know tag, data, and len(secret) (brute a range if unknown).

CLI:
    python3 length_extension.py <algo> <known_hex_digest> <original_data> <append> <secret_len>
      algo in {md5,sha1,sha256};  original_data/append may use \\xNN escapes
    -> prints:  new_hex_digest  and  new_message (python-repr bytes, includes glue padding)

API:
    new_digest_hex, new_message_bytes = extend(algo, known_hex, orig_msg_bytes, append_bytes, secret_len)

Verify against the real thing: H(secret || new_message) == new_digest_hex.
"""
import sys, struct

# ---------- MD5 (RFC 1321, little-endian) ----------
_MD5_S = [7,12,17,22]*4 + [5,9,14,20]*4 + [4,11,16,23]*4 + [6,10,15,21]*4
_MD5_K = [int(abs(__import__('math').sin(i+1))*(1<<32)) & 0xffffffff for i in range(64)]
def _md5_compress(state, block):
    a,b,c,d = state
    M = list(struct.unpack('<16I', block))
    A,B,C,D = a,b,c,d
    for i in range(64):
        if i<16:   f=(B&C)|(~B&D); g=i
        elif i<32: f=(D&B)|(~D&C); g=(5*i+1)%16
        elif i<48: f=B^C^D;        g=(3*i+5)%16
        else:      f=C^(B|(~D&0xffffffff)); g=(7*i)%16
        f=(f+A+_MD5_K[i]+M[g])&0xffffffff
        A,D,C = D,C,B
        B=(B+(((f<<_MD5_S[i])|(f>>(32-_MD5_S[i])))&0xffffffff))&0xffffffff
    return [(a+A)&0xffffffff,(b+B)&0xffffffff,(c+C)&0xffffffff,(d+D)&0xffffffff]
def _md5_pad(msglen):
    pad=b'\x80'+b'\x00'*((56-(msglen+1)%64)%64)
    return pad+struct.pack('<Q',(msglen*8)&0xffffffffffffffff)

# ---------- SHA-1 / SHA-256 (big-endian) ----------
def _rotr(x,n,w=32): return ((x>>n)|(x<<(w-n)))&0xffffffff
def _rotl(x,n): return ((x<<n)|(x>>(32-n)))&0xffffffff
def _sha1_compress(state, block):
    h=list(state); w=list(struct.unpack('>16I',block))
    for i in range(16,80): w.append(_rotl(w[i-3]^w[i-8]^w[i-14]^w[i-16],1))
    a,b,c,d,e=h
    for i in range(80):
        if i<20: f=(b&c)|(~b&d); k=0x5A827999
        elif i<40: f=b^c^d; k=0x6ED9EBA1
        elif i<60: f=(b&c)|(b&d)|(c&d); k=0x8F1BBCDC
        else: f=b^c^d; k=0xCA62C1D6
        t=(_rotl(a,5)+f+e+k+w[i])&0xffffffff
        e,d,c,b,a=d,c,_rotl(b,30),a,t
    return [(x+y)&0xffffffff for x,y in zip(h,[a,b,c,d,e])]
_SHA256_K=[0x428a2f98,0x71374491,0xb5c0fbcf,0xe9b5dba5,0x3956c25b,0x59f111f1,0x923f82a4,0xab1c5ed5,0xd807aa98,0x12835b01,0x243185be,0x550c7dc3,0x72be5d74,0x80deb1fe,0x9bdc06a7,0xc19bf174,0xe49b69c1,0xefbe4786,0x0fc19dc6,0x240ca1cc,0x2de92c6f,0x4a7484aa,0x5cb0a9dc,0x76f988da,0x983e5152,0xa831c66d,0xb00327c8,0xbf597fc7,0xc6e00bf3,0xd5a79147,0x06ca6351,0x14292967,0x27b70a85,0x2e1b2138,0x4d2c6dfc,0x53380d13,0x650a7354,0x766a0abb,0x81c2c92e,0x92722c85,0xa2bfe8a1,0xa81a664b,0xc24b8b70,0xc76c51a3,0xd192e819,0xd6990624,0xf40e3585,0x106aa070,0x19a4c116,0x1e376c08,0x2748774c,0x34b0bcb5,0x391c0cb3,0x4ed8aa4a,0x5b9cca4f,0x682e6ff3,0x748f82ee,0x78a5636f,0x84c87814,0x8cc70208,0x90befffa,0xa4506ceb,0xbef9a3f7,0xc67178f2]
def _sha256_compress(state, block):
    h=list(state); w=list(struct.unpack('>16I',block))
    for i in range(16,64):
        s0=_rotr(w[i-15],7)^_rotr(w[i-15],18)^(w[i-15]>>3)
        s1=_rotr(w[i-2],17)^_rotr(w[i-2],19)^(w[i-2]>>10)
        w.append((w[i-16]+s0+w[i-7]+s1)&0xffffffff)
    a,b,c,d,e,f,g,hh=h
    for i in range(64):
        S1=_rotr(e,6)^_rotr(e,11)^_rotr(e,25); ch=(e&f)^(~e&g)
        t1=(hh+S1+ch+_SHA256_K[i]+w[i])&0xffffffff
        S0=_rotr(a,2)^_rotr(a,13)^_rotr(a,22); maj=(a&b)^(a&c)^(b&c)
        t2=(S0+maj)&0xffffffff
        hh,g,f,e,d,c,b,a=g,f,e,(d+t1)&0xffffffff,c,b,a,(t1+t2)&0xffffffff
    return [(x+y)&0xffffffff for x,y in zip(h,[a,b,c,d,e,f,g,hh])]
def _mdpad_be(msglen):
    pad=b'\x80'+b'\x00'*((56-(msglen+1)%64)%64)
    return pad+struct.pack('>Q',(msglen*8)&0xffffffffffffffff)

_ALG={
 'md5':   (16,'<', _md5_compress,   _md5_pad,   [0x67452301,0xefcdab89,0x98badcfe,0x10325476]),
 'sha1':  (20,'>', _sha1_compress,  _mdpad_be,  [0x67452301,0xEFCDAB89,0x98BADCFE,0x10325476,0xC3D2E1F0]),
 'sha256':(32,'>', _sha256_compress,_mdpad_be,  None),
}
def extend(algo, known_hex, orig_msg, append, secret_len):
    algo=algo.lower(); dlen,endian,compress,padfn,_=_ALG[algo]
    nwords=dlen//4
    state=list(struct.unpack(('<' if endian=='<' else '>')+str(nwords)+'I', bytes.fromhex(known_hex)))
    # glue padding the server applied to (secret||orig_msg)
    glue=padfn(secret_len+len(orig_msg))
    new_message=orig_msg+glue+append
    # continue hashing `append` from the recovered state; total prefix = secret_len+len(orig)+len(glue)
    prefix_len=secret_len+len(orig_msg)+len(glue)
    data=append+padfn(prefix_len+len(append))
    for i in range(0,len(data),64):
        state=compress(state, data[i:i+64])
    fmt=('<' if endian=='<' else '>')+str(nwords)+'I'
    return struct.pack(fmt,*state).hex(), new_message

def _unesc(s):
    return s.encode().decode('unicode_escape').encode('latin1')

if __name__=='__main__':
    if len(sys.argv)!=6:
        print(__doc__); sys.exit(1)
    algo, known, data, app, slen = sys.argv[1], sys.argv[2], _unesc(sys.argv[3]), _unesc(sys.argv[4]), int(sys.argv[5])
    d,m=extend(algo, known, data, app, slen)
    print("new_digest :", d)
    print("new_message:", m)
