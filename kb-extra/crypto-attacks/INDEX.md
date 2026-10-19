# Crypto Attack Technique Handbook (offline, general)

**What this is.** General cryptographic *attack* techniques — recognition signals, the underlying principle, and a reusable Python skeleton for each. This is domain knowledge (like PayloadsAllTheThings for web), NOT solutions to any specific challenge. Read a page, recognize the pattern in front of you, adapt the skeleton.

**No internet.** All skeletons use libraries present offline: `pycryptodome` (`Crypto`), `sympy`, `gmpy2`, `fpylll`, `pyfinite`, `pwntools`, `hashlib`, `mmh3`, plus the CLI tools `RsaCtfTool` and `hashpumpy` when installed. `sage` is intentionally absent — every technique below is written to work without it.

## How to pick a page — recognition table

| You observe / are given | Likely technique | Page |
|---|---|---|
| A MAC = `E_cbc(m)[-1]` / raw CBC-MAC, variable-length messages, you can query tags | CBC-MAC forgery (length-extension / truncation leak / non-standard padding) | 01 |
| Server decrypts your ciphertext and tells you *pad valid?* | Padding oracle | 01 |
| You control plaintext prefixed/suffixed to a secret, ECB mode | Byte-at-a-time ECB / cut-and-paste | 01 |
| Two ciphertexts, same stream/CTR keystream (nonce reuse) | Keystream reuse / crib dragging | 01 |
| GCM, same nonce twice | Forbidden attack (recover H, forge) | 01 |
| RSA service returns 1 bit about the plaintext (parity / `<B` vs `>=B` / LSB) | RSA LSB/parity oracle → binary search | 02 |
| RSA with tiny `e` (=3), no/short padding, or same `m` to many keys | Cube root / Håstad / Franklin-Reiter / Coppersmith short-pad | 02 |
| You know the top (or bottom) bits of a prime, or a stereotyped message | Coppersmith small-root (`fpylll`) | 02 |
| Same modulus `n`, two coprime exponents | Common modulus | 02 |
| `d` small / `e` huge | Wiener / Boneh–Durfee | 02 |
| Server signs/decrypts PKCS#1 v1.5 and leaks validity | Bleichenbacher; e=3 signature forgery | 02 |
| `MAC = H(secret ‖ data)` with a Merkle–Damgård hash (md5/sha1/sha256), no HMAC | Length-extension | 03 |
| A **non-crypto** hash (MurmurHash3, FNV, djb2, xxHash) used as a filter/dedup | Seed recovery / collision | 03 |
| A Bloom filter gates access | Membership-collision construction | 03 |
| CRC used as integrity/auth, or many noisy CRCs of one secret | CRC linear algebra / noise cancellation / reversal | 04 |
| A novel/academic construction (encrypted graph, "GES/SDSP", ORAM…) with a query API | Leakage-abuse: model what each query reveals | 05 |
| A home-made or classical cipher, or TEA/XTEA/XXTEA, or a permutation network | Custom-cipher reverse workflow | 06 |
| Discrete-log / Diffie–Hellman with a factorable order, small subgroup | Pohlig–Hellman / BSGS / smoothness | 07 |

## Universal first moves
1. **Get the source.** Most crypto challenges hand you the server/encrypt code. Read it: exact mode, padding, nonce handling, key/IV reuse, what the oracle returns. The *deviation from the standard* is the bug.
2. **Model the oracle.** Write down precisely: input space, output (how many bits leak per query), query budget. Attacks are "turn N bits/query into the secret."
3. **Use homomorphism.** RSA is multiplicative (`E(a)·E(b)=E(ab)`), textbook ElGamal too; additive for Paillier; XOR for stream ciphers. Almost every oracle attack multiplies/adds a known factor and reads the leak.
4. **Automate the interaction** with `pwntools` (`remote()/process()`, `recvuntil`, `sendline`). Oracle attacks are thousands of queries — never do it by hand.
5. **Reach for a solver** only after modeling: `sympy` (factor, discrete_log, solve, crt, Matrix over GF(p)), `gmpy2` (iroot, invert, big-int), `fpylll` (LLL/BKZ for lattices), `RsaCtfTool` (RSA quick wins), `hashpumpy` (length extension).

Pages: `01-symmetric-auth-and-modes.md` · `02-rsa-oracles-and-attacks.md` · `03-hash-attacks.md` · `04-crc-linear-algebra.md` · `05-leakage-abuse-and-academic-crypto.md` · `06-classical-and-custom-ciphers.md` · `07-dlog-dh-and-lattices.md`
