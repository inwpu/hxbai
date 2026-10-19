# 04 — CRC as linear algebra (forge, recover polynomial, denoise)

**CRC is affine over GF(2).** For a fixed generator polynomial, `CRC(x) = M·x ⊕ c` where `M` is a fixed binary matrix and `c = CRC(0)` (the constant from initial value / final XOR). The single most useful consequence:

```
CRC(a ⊕ b) = CRC(a) ⊕ CRC(b) ⊕ CRC(0)
```

Never treat CRC as a hash/MAC — it is linear and forgeable.

## Forge a message with a target CRC
Append/patch 4 (or `deg/8`) bytes so the CRC equals any target. Because CRC is affine, solve a small linear system over GF(2) (32 unknowns for CRC-32): set up `CRC(prefix ‖ x) = target` and solve for `x`. `pwntools` doesn't ship it, but it's ~20 lines with a GF(2) matrix, or use the classic "reverse the CRC register" trick (run the CRC state machine backwards from the target through the tail bytes).

## Recover an unknown generator polynomial / parameters
If poly, init, xorout are unknown but you can obtain CRCs of chosen inputs: CRC-32 has ≤ 32+32+32 unknown bits (poly, init, xorout). Collect CRCs of structured inputs (e.g. all-zero of increasing length, single-bit-set inputs) and solve the linear system, or brute the 32-bit poly against a couple of known (input, crc) pairs (`crcmod`/`crc` libs or a hand loop). Known reflected/normal forms and common polynomials (CRC-32/IEEE `0x04C11DB7`, CRC-32C `0x1EDC6F41`) are worth trying first.

## "Noisy CRC" — recover a secret from many CRCs (with noise)
Pattern (noisy-crc / noisier-crc family): the service reveals `CRC_p(secret)` for **many different random polynomials `p`** (some of them fake/noise). Because each true CRC is a **linear** function of the secret over GF(2), each honest `(p, CRC_p(secret))` is a batch of linear equations in the secret's bits. Strategy:
1. Treat every returned `(polynomial, residue)` as linear constraints on the unknown secret bits (`CRC_p` reduces `secret·x^deg` mod `p`, which is GF(2)-linear in the secret bits).
2. You get **more equations than unknowns**; the noise means some equations are wrong. Use a **majority / consistency** approach: solve over-determined systems on random subsets and keep the solution that most equations agree with, or model as decoding a linear code (find the codeword within Hamming distance = noise budget). CRT-style reassembly works when each `p` gives an independent residue of the secret modulo an irreducible factor.
3. With enough honest shares, Gaussian elimination over GF(2) (`sympy.Matrix(... ).rref()` with mod-2, or a bitset elimination) recovers the secret.

```python
# GF(2) linear solve skeleton (bit-packed rows as Python ints)
def gf2_solve(rows, rhs, nbits):
    # rows: list[int] (each a bitmask of coefficients), rhs: list[int in {0,1}]
    piv={}
    for r,b in zip(rows,rhs):
        cur, bb = r, b
        while cur:
            h = cur.bit_length()-1
            if h in piv:
                pr,pb = piv[h]; cur^=pr; bb^=pb
            else:
                piv[h]=(cur,bb); break
    x=0
    for h,(pr,pb) in sorted(piv.items()):
        bit = pb
        cur=pr & ((1<<h)-1)
        # back-substitute known higher bits
        bit ^= bin(cur & x).count("1") & 1
        if bit: x|=(1<<h)
    return x
```

Recognition: integrity check or "prove you know x" implemented with CRC; or a service leaking many CRCs of one hidden value. The move is always **linear algebra over GF(2)**, never brute force of the secret.
