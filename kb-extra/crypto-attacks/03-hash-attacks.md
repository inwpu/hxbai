# 03 — Hash attacks (length extension, non-crypto hash, Bloom filters)

## Merkle–Damgård length extension
Affects **MD5, SHA-1, SHA-256, SHA-512** (any MD hash). If a server authenticates with `tag = H(secret ‖ msg)` (a "secret-prefix MAC", **not** HMAC), and you know `tag`, `msg`, and `len(secret)`, you can compute `H(secret ‖ msg ‖ glue_pad ‖ ext)` for arbitrary `ext` **without knowing the secret** — because the hash output *is* the internal state, and you just keep hashing from there.

Recognition: signature/MAC computed as `H(key + data)`; you can see `data` and its `tag`; parameter you want to append (`&admin=1`, extra path, extra field). HMAC is immune.

```bash
# Vendored pure-Python tool (no hashpumpy needed): /opt/kb/crypto-attacks/length_extension.py
python3 /opt/kb/crypto-attacks/length_extension.py sha256 "$SIG" "$ORIG_DATA" '&admin=1' "$KEYLEN"
# -> prints new_digest (the forged tag) and new_message (data + glue-padding + your append)
# API:  from length_extension import extend; dig,msg = extend("sha256", sig_hex, data, b"&admin=1", keylen)
# Supports md5/sha1/sha256; verified against hashlib. NB: use pure raw bytes for new_message (URL-encode non-printables).
```
If `len(secret)` is unknown: loop `KEYLEN` over a plausible range (e.g. 8..64), submit each forged `(msg, tag)` until the server accepts. The glue padding (`0x80`, zero bytes, 64-bit length) is emitted for you — send the returned raw message verbatim (URL-encode non-printables).

## Non-cryptographic hashes used as filters/dedup
`MurmurHash3`, `FNV-1a`, `djb2`, `xxHash`, CityHash are **not** collision-resistant and often have recoverable/known seeds. When such a hash gates dedup, membership, or sharding:
- **Seed recovery**: if you can query hashes of chosen inputs, recover the 32-bit murmur seed by brute or by solving (murmur is a fixed sequence of xors/mults/rotls — invertible per step). `mmh3` is available: `mmh3.hash(data, seed)`.
- **Collision construction**: for a target bucket/value, search short inputs (birthday or targeted) that map to it. Murmur3/FNV collisions are cheap to find offline (a few million tries) because the output is short (32/64-bit) and there's no cryptographic mixing.
- Recognition: "diffecient"-style stores that reject duplicates by a non-crypto hash → craft a new item hashing to an existing bucket to bypass the uniqueness check, or to force a false "already exists / is member".

## Bloom filters
A Bloom filter tests set membership with `k` hash functions into an `m`-bit array; **false positives are inherent**. To *bypass* a Bloom-filter gate ("must already be a member"), construct an element whose `k` hash positions are all already set — i.e. a deliberate false positive.
- If the `k` hashes are non-crypto (murmur/FNV with known seeds), enumerate candidate elements and pick one whose `k` bit positions are all set in the observed filter.
- False-positive probability `≈ (1 − e^{−kn/m})^k`; a saturated filter (`n` large) makes crafted positives trivial.
```python
import mmh3
def bloom_positions(x, seeds, m):
    return [mmh3.hash(x, s) % m for s in seeds]
# search x such that all bits set in the target bitarray
```

Practical note: whenever a "hash" is used for **authentication/uniqueness** rather than a keyed HMAC, treat it as broken and look for length-extension (crypto MD hash) or collision (non-crypto hash).
