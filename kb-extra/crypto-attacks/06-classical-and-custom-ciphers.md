# 06 — Classical & custom-cipher reverse workflow

When the challenge ships its own `encrypt()` (home-made, or a named small cipher like TEA/XTEA), the win is almost always **read the routine and invert it** — not brute force.

## Workflow for any home-made cipher
1. **Obtain the encrypt code** (source, or reverse the binary — see the RE toolchain: ghidra/radare2/gdb). Transcribe it to Python.
2. **Classify the structure**:
   - *Substitution* (byte→byte map, S-box): invert the map. If key-dependent, recover the S-box from known plaintext.
   - *Permutation / transposition* (bits or bytes reordered): recover the permutation from known plaintext (identity input reveals the map), then invert.
   - *Stream / XOR* (keystream from a PRNG/counter): recover keystream from known plaintext, or break the PRNG (see RNG note).
   - *Feistel / SPN* (rounds of mix + key): if invertible with the key, just run it backwards; if the key is unknown, look for weak round count, related-key, or meet-in-the-middle.
   - *Arithmetic* (mul/add mod 2^k, affine): invert with modular inverse; affine `y=a·x+b` → `x=a^{-1}(y−b)`.
3. **Check invertibility.** If every step is a bijection (xor, add mod 2^n, rotate, sbox permutation, full-rank linear map), the decryption is the exact inverse in reverse order — write it and run. If a step loses information (non-injective), you need algebra/brute on the lost bits only.
4. **If the key is unknown**: known-plaintext + small keyspace → brute; algebraic structure → solve (linearization, `sympy.solve`, GF(2) linear system); meet-in-the-middle for double-encryption.

## TEA / XTEA / XXTEA
64-bit block, 128-bit key, `delta=0x9E3779B9`, 32/64 rounds of add/xor/shift. **Fully invertible given the key** — the decrypt routine is the standard mirror (subtract sum, reverse round loop). Watch for: ECB mode over multiple blocks (pattern/cut-paste), endianness (word packing), a modified `delta`/round count (adjust the constants), related-key weaknesses (TEA has equivalent keys — flipping the MSB of two key words gives the same cipher).

```python
def xtea_decrypt(v, key, rounds=32, delta=0x9E3779B9, mask=0xffffffff):
    v0, v1 = v
    s = (delta * rounds) & mask
    for _ in range(rounds):
        v1 = (v1 - (((v0<<4 ^ v0>>5) + v0) ^ (s + key[(s>>11)&3]))) & mask
        s = (s - delta) & mask
        v0 = (v0 - (((v1<<4 ^ v1>>5) + v1) ^ (s + key[s&3]))) & mask
    return v0, v1
```

## Classical ciphers
- **Substitution / Caesar / ROT**: frequency analysis (English `etaoin…`), or brute 26 shifts.
- **Vigenère**: Kasiski / index-of-coincidence to find key length, then per-column frequency.
- **Affine**: solve `a,b` from two known pairs; `a` invertible mod 26.
- **Hill**: recover key matrix from known plaintext (matrix inverse mod 26), needs `n` independent pairs.
- **XOR (repeating key)**: keysize by Hamming distance / IoC, then single-byte XOR per column (score by plaintext frequency). Available offline: write it, or use the classic break.
- **"Dynastic"/custom classical**: identify it's a shift/substitution with a twist (position-dependent shift, keyed alphabet), replicate the keying, invert.

## Meet-in-the-middle (double encryption)
If `c = E_{k2}(E_{k1}(m))` with two small keys: build a table of `E_{k1}(m)` for all `k1`, then for each `k2` check `D_{k2}(c)` in the table → `O(2·2^k)` instead of `2^{2k}`.

Golden rule: **the encryptor is handed to you; the decryptor is (usually) its mirror.** Spend effort reading and transcribing, not brute forcing.
