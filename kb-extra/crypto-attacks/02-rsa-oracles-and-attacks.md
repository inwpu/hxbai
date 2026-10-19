# 02 — RSA oracles & attacks

RSA is **multiplicatively homomorphic**: `(m·s)^e ≡ c·s^e (mod n)`. Almost every RSA attack blinds the target ciphertext by a known factor `s^e`, sends it, and reads whatever the server leaks. First: try `RsaCtfTool --publickey key.pem --uncipher c` for the easy wins (factordb, Fermat, Wiener, small-e, common factors) — then reach for the specific attack.

---

## LSB / parity / comparison decryption oracle  ← binary-search recovery
The server decrypts your ciphertext and returns **one bit** about the plaintext: its LSB (`m mod 2`), its parity, or a comparison like "`m < B` vs `m ≥ B`". This recovers `m` in `⌈log2 n⌉` queries (~1024) by binary search, using the homomorphism `c·2^e mod n` to double the plaintext each step (doubling wraps mod n, and the leaked bit tells you which half the true value fell in).

```python
from Crypto.Util.number import long_to_bytes
def lsb_oracle_recover(n, e, c, oracle):
    # oracle(ct)->int in {0,1}: LSB of decryption of ct. Recovers m.
    lo, hi = 0, n
    mult = pow(2, e, n)
    cur = c
    from fractions import Fraction
    lo, hi = Fraction(0), Fraction(n)
    for _ in range(n.bit_length()):
        cur = (cur * mult) % n
        if oracle(cur) == 0:            # m*2^k did NOT wrap -> even -> lower half
            hi = (lo + hi) / 2
        else:                           # wrapped (odd) -> upper half
            lo = (lo + hi) / 2
    return long_to_bytes(int(hi))
```
Variants:
- **Comparison oracle ("`<B`" / "`≥B`")** — same binary search; map the returned symbol to which half. This is the general "maze / navigation" oracle: each query is a step, the two answers are the two branches of the search.
- **Parity instead of strict LSB** — identical, parity of `m·2^k mod n`.
- Convergence: track `lo/hi` as exact `Fraction`s (above) to avoid rounding at the last bits; the answer is `int(hi)` (or search a few neighbors and check padding/format).

Recognition: any RSA service that repeatedly decrypts attacker ciphertext and returns a small, deterministic function of the plaintext. **Model exactly what 1 bit it leaks**, then it's a binary search.

---

## Small public exponent
- **e=3, no padding, small m**: if `m^3 < n`, `m = iroot(c,3)`. `gmpy2.iroot(c,3)`.
- **Håstad broadcast**: same `m` sent under `e` different moduli with `e≤` count → CRT the `c_i` then take e-th root.
- **Franklin–Reiter related messages**: two ciphertexts of `m` and `f(m)` (affine relation) under same n,e → gcd of polynomials recovers m.
- **Coppersmith short-pad (Coppersmith–Franklin–Reiter)**: same message with two short random pads → recover.

```python
import gmpy2
r, exact = gmpy2.iroot(c, 3)
if exact: m = int(r)
```

## Coppersmith small-root (known bits) — via fpylll/LLL (no sage)
When a small unknown fits in a polynomial with a small root mod n (or mod a divisor), LLL finds it:
- **Known high/low bits of a prime p** → factor n. If you know `p_high` (top bits), root-find `f(x)=p_high·2^k + x (mod n)` with `|x|` small.
- **Stereotyped message**: `m = known ‖ x`, small unknown `x`, `c=(known+ x)^e` → recover `x`.

A **ready, tested** Howgrave-Graham implementation is vendored at `/opt/kb/crypto-attacks/coppersmith.py` (fpylll + sympy, no sage). It recovers a 512-bit `p` from its top bits.
```python
import sys; sys.path.insert(0, "/opt/kb/crypto-attacks")
from coppersmith import factor_with_high_bits, coppersmith_small_roots
# 1) factor N knowing the HIGH bits of p (low `unknown_bits` unknown; p_high has them zeroed):
p, q = factor_with_high_bits(N, p_high, unknown_bits, m=4, t=2)   # raise m,t if it returns None
# 2) stereotyped message  m = (known << k) + x0  with small x0, c = m^e mod N:
#    f(x) = (known<<k + x)^e - c  is NOT monic; instead work mod N with the monic form:
#    for "m = prefix + x", build f(x)=(prefix + x)^e - c over Z, make monic by multiplying by inverse
#    of leading coeff mod N, then coppersmith_small_roots([...], N, 1.0, X, m, t).
# Bound rule: X < N**(beta**2/deg)  (deg=1,beta=0.5 -> X < N**0.25, i.e. up to ~1/4 of p unknown).
```
Also try `RsaCtfTool --publickey key.pem --uncipher c` first — it bundles partial-`p`/known-high-bits Coppersmith cases and may one-shot it.

## Common modulus
Same `n`, two ciphertexts of the same `m` with **coprime** `e1,e2`. Bézout `a·e1+b·e2=1` → `m = c1^a · c2^b mod n` (use `invert` for negative exponent).
```python
from Crypto.Util.number import inverse
def common_modulus(c1,e1,c2,e2,n):
    import sympy
    s,t,g = sympy.gcdex(e1,e2)        # NOTE order: coeffs FIRST, gcd LAST -> s*e1 + t*e2 = g
    assert g == 1, "e1,e2 must be coprime"
    s,t = int(s), int(t)
    x = pow(c1,s,n) if s>=0 else pow(inverse(c1,n),-s,n)
    y = pow(c2,t,n) if t>=0 else pow(inverse(c2,n),-t,n)
    return (x*y)%n                    # == m
```
> Pitfall: `sympy.gcdex(a,b)` returns `(s, t, g)` with `s·a + t·b = g` — the **coefficients come first, the gcd last**. Do not unpack it as `g,a,b`; that silently uses the gcd as an exponent and the attack fails without error.

## Small private exponent
- **Wiener** (`d < n^0.25`): continued-fraction of `e/n` → recover d. In `RsaCtfTool`, or `sympy`/`owiener`-style loop.
- **Boneh–Durfee** (`d < n^0.292`): lattice attack (fpylll).

## Factorization quick wins
- **Fermat** (p,q close): iterate `a=ceil(sqrt(n))`, check `a^2−n` square.
- **`sympy.factorint(n)`** for small/smooth n; **factordb** for known n (offline only if you have a dump; else sympy).
- **Common factor** across many keys: `gcd(n_i, n_j)`.
- **Pollard p−1** when p−1 is smooth (`RsaCtfTool` / gmpy2 loop).

## Bleichenbacher & signature forgery
- **PKCS#1 v1.5 padding oracle (Bleichenbacher'98)**: server tells you if `c` decrypts to a `00 02 …` conformant block → adaptively narrow `m` (interval arithmetic). Works for decryption and for signing (RSA-decrypt oracle == sign oracle).
- **e=3 signature forgery (Bleichenbacher'06)**: if the verifier parses PKCS#1 v1.5 signatures loosely (doesn't check the full suffix), you can craft a perfect-cube signature with the ASN.1/hash prefix near the top and garbage low bits → `sig = iroot(forged_block, 3)`. Recognition: `e=3` verifier, "BER/DER not strictly checked."

> Workflow: (1) read the service, decide exactly what it leaks; (2) if it's a 1-bit decrypt oracle → LSB/parity binary search; (3) if it's structure of the key (small e/d, close/known-bit primes, shared modulus) → the matching algebraic attack or `RsaCtfTool`; (4) lattices (Coppersmith/Boneh–Durfee) via `fpylll` when a small unknown is involved.
