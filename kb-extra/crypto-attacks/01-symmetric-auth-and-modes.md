# 01 — Symmetric authentication & block-cipher mode attacks

Principle: block-cipher **modes** and **MACs** are only as strong as their construction details. The bug is almost always a deviation from the standard: raw CBC-MAC on variable-length messages, a home-made padding, a reused nonce/IV, tag truncation, ECB. Get the source, find the deviation.

---

## CBC-MAC forgery
CBC-MAC of blocks `m1..mk` under key K with **IV=0**: `t = E_K(mk ⊕ E_K(m_{k-1} ⊕ … E_K(m1)))`. Secure **only** for fixed-length messages. Three practical breaks:

**(a) Length-extension / concatenation forgery (variable length).**
If you can get the tag of chosen messages, then given `t1 = MAC(m)` you can forge the MAC of `m ‖ x` for the two-message construction: the first block of the second message is `x1' = m_lastblock_effect`, concretely `MAC(m ‖ (t1 ⊕ x1) ‖ x2 ‖ …) = MAC(x)`. Classic pattern: with `t1=MAC(a)` and `t2=MAC(b)` you forge `MAC(a ‖ (b1 ⊕ t1) ‖ b2…) = t2`.

**(b) Truncated-tag leakage.** If the scheme returns a tag whose length depends on the message (e.g. it truncates the internal state per message length, so a query with an n-block message leaks specific state bits), each query leaks a fixed slice of the CBC chain. Collect tags for messages of different lengths, then **assemble the pieces**: the intermediate CBC states you learned let you compute the tag of a message you never queried by XOR-splicing the known slices. General recipe: (1) enumerate which state bits each query length reveals; (2) choose query lengths whose revealed slices *cover* the target message's chain; (3) reconstruct the target tag from the union. This is the general form behind "each message length leaks 63 bits → concatenate to forge."

**(c) Non-standard padding side channel.** A bespoke padding (not PKCS#7) often makes two distinct messages collide after padding, or lets you control block boundaries. Diff the padding routine against the standard; look for: padding that isn't length-prefixed, ambiguous padding (two inputs → same padded block), or padding applied *after* the length field.

```python
# (a) two-message CBC-MAC forgery, IV=0, AES/any 128-bit block
from pwn import xor
def forge(mac_a: bytes, a: bytes, b: bytes) -> bytes:
    # returns message whose MAC == MAC(b), using known t1=mac_a for a
    b1, brest = b[:16], b[16:]
    return a + xor(b1, mac_a) + brest      # MAC(this) == MAC(b)
```
Recognition: server verifies `tag == cbc_mac(K, msg)`, IV fixed to 0, message length is attacker-controlled, and you can query tags of chosen messages. **CMAC/OMAC and HMAC are NOT vulnerable** (CMAC xors a length-dependent subkey into the last block; HMAC nests). If you see CMAC, this attack does not apply.

---

## Padding oracle (CBC)
Server decrypts your ciphertext and behaves differently on valid vs invalid PKCS#7 padding (error, timing, or status). You can decrypt **and** encrypt arbitrary plaintext without the key.

Principle: for two adjacent blocks `C_{i-1}, C_i`, `P_i = D_K(C_i) ⊕ C_{i-1}`. Forge `C'_{i-1}` byte by byte so the padding of the decrypted `C_i` is valid; each success reveals one byte of `D_K(C_i)`.

```python
def decrypt_block(oracle, C_prev, C, bs=16):
    # oracle(ct)->True if padding valid. C = target block, C_prev = preceding block (or IV)
    inter = bytearray(bs)                 # D_K(C)
    for pad in range(1, bs+1):
        prefix = bytes(bs-pad)
        for g in range(256):
            tail = bytes(inter[bs-pad+1+j] ^ pad for j in range(pad-1))
            forged = prefix + bytes([g]) + tail
            if oracle(forged + C):
                inter[bs-pad] = g ^ pad
                break
    return bytes(inter[j] ^ C_prev[j] for j in range(bs))   # plaintext block
```
To **encrypt** a chosen plaintext: pick the last ciphertext block at random, use the oracle to learn `D_K` of it, set `C_prev = D_K(C) ⊕ desired_plaintext`, chain backwards.

Home-made padding variants: same idea, just re-derive the "valid padding" predicate for their scheme (ISO 7816-4 `80 00…`, ANSI X9.23, or a custom one). If the oracle leaks *which* pad byte failed, decryption is even faster.

---

## ECB attacks
- **Byte-at-a-time decryption** when the server encrypts `attacker_input ‖ SECRET` in ECB: align so one unknown byte sits at a block boundary, brute the last byte by comparing blocks. Classic; recover the whole secret 1 byte/256 queries.
- **Cut-and-paste**: ECB blocks are independent → rearrange/duplicate ciphertext blocks to build a forged plaintext (e.g. craft `role=admin` by aligning it into its own block and splicing).
- **ECB detection**: identical 16-byte plaintext blocks → identical ciphertext blocks (repeated block finder).

```python
def ecb_byte_at_a_time(encrypt, bs=16, maxlen=256):
    known=b''
    for i in range(maxlen):
        pad=b'A'*((bs-1-len(known))%bs)
        blk=(len(pad)+len(known))//bs
        target=encrypt(pad)[blk*bs:(blk+1)*bs]
        for g in range(256):
            if encrypt(pad+known+bytes([g]))[blk*bs:(blk+1)*bs]==target:
                known+=bytes([g]); break
        else: break
    return known
```

---

## Stream / CTR / OFB keystream reuse (nonce reuse)
If the same key+nonce (⇒ same keystream) encrypts two messages: `C1 ⊕ C2 = P1 ⊕ P2`. Recover plaintext by **crib dragging** (slide a known word, look for readable XOR), or if you know/guess one plaintext you get the other and the keystream. Any reused keystream fully breaks confidentiality and lets you flip bits into a known plaintext.

```python
ks = xor(C1, P1_known)      # recover keystream where P1 known
P2 = xor(C2, ks)            # decrypt second message on that range
```

## CBC bit-flipping
`P_i = D_K(C_i) ⊕ C_{i-1}`, so flipping a bit in `C_{i-1}` flips the same bit in `P_i` (and garbles block i-1). Use to tamper a known plaintext field (e.g. set `admin=1`) when integrity isn't MAC'd.

## GCM nonce reuse — "forbidden attack"
GCM auth is a polynomial MAC (GHASH) in GF(2^128) with key `H=E_K(0)`. **Reusing a nonce** for two messages lets you solve for `H` (subtract the two authentication polynomials → a polynomial in `H`, find its roots over GF(2^128)), then forge tags for arbitrary ciphertext under that nonce. Recognition: AES-GCM, and you see the same 12-byte nonce twice. Skeleton: build the GHASH polynomials from `(ciphertext, aad, tag)` pairs, root-find over GF(2^128) (implement GF(2^128) mul, or use `sympy`/`pyfinite` GF(2) polynomial factoring).

> Rule of thumb: **any reuse (IV, nonce, keystream) or any home-made padding/MAC is the intended bug.** Diff against the textbook construction first.
