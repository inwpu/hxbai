# 07 — Discrete log, Diffie–Hellman weak params, lattices (no sage)

## Discrete logarithm — pick by group order
Given `g^x = h (mod p)`, recover `x`. Choose the algorithm by the factorization of the group order `n = ord(g)` (usually `p−1`):
- **Pohlig–Hellman** when `n` is **smooth** (only small prime factors): solve the DLP modulo each prime power, CRT the results. Cost ~`Σ e_i·(p_i)` — tiny for smooth `n`. This is the #1 DH weakness.
- **Baby-step giant-step (BSGS)**: `O(√n)` time and memory — feasible up to ~`n<2^50`.
- **Pollard's rho**: `O(√n)` time, `O(1)` memory.
- `sympy.ntheory.residue_ntheory.discrete_log(p, h, g)` implements BSGS/Pohlig–Hellman automatically — try it first.

```python
from sympy.ntheory.residue_ntheory import discrete_log
x = discrete_log(p, h, g)          # sympy picks BSGS / Pohlig-Hellman
```

## Diffie–Hellman weak parameters — what to check
1. **Smooth `p−1`** → Pohlig–Hellman recovers any exponent. Detect: `sympy.factorint(p-1)` has only small factors.
2. **Small subgroup / non-prime-order generator** → confine the secret to a small subgroup; recover `x mod q` for each small `q | ord(g)`.
3. **Small-subgroup confinement / invalid parameters**: server accepts an attacker-chosen generator or a `g` of small order → leaks `x mod (small)`.
4. **Composite / repeated modulus, tiny `p`** → just brute or BSGS.
5. Reused ephemeral secret across sessions → algebraic recovery.

```python
import sympy
f = sympy.factorint(p-1)
smooth = all(pk < 2**40 for pk in f)      # if True -> Pohlig-Hellman is easy
```

## Elliptic curve pitfalls (if you see ECC)
- **Singular curve** (discriminant 0) → map to additive/multiplicative group, DLP trivial.
- **Anomalous curve** (`#E = p`) → Smart's attack (p-adic), linear-time DLP.
- **Smooth group order** → Pohlig–Hellman on the curve.
- **Invalid-curve attack**: server doesn't validate the input point is on the curve → send points on a weaker curve, recover key mod small factors.
- **MOV/embedding degree** small → transfer to a field DLP.

## Lattices with fpylll (the sage substitute)
`fpylll` gives `LLL`/`BKZ`; build the basis, reduce, read short vectors. Uses:
- **Knapsack / subset-sum** (low density) → lattice with the weights + a big multiplier; short vector is the 0/1 solution.
- **Hidden Number Problem / biased-nonce ECDSA** (partial nonce leakage across signatures) → build the HNP lattice, LLL/BKZ, read the private key. Recognition: many ECDSA/DSA signatures where nonces share bits or are short.
- **Coppersmith** (see page 02): Howgrave-Graham lattice.
- **LWE / lattice challenges**: primal/dual embedding, BKZ with a tuned block size.

```python
from fpylll import IntegerMatrix, LLL, BKZ
B = IntegerMatrix.from_matrix(rows)        # rows = your lattice basis (list of lists)
LLL.reduction(B)                            # or BKZ.reduction(B, BKZ.Param(block_size=20))
# read reduced rows: [ [B[i][j] for j in range(B.ncols)] for i in range(B.nrows) ]
```

## ECDSA/DSA nonce problems (very common, high value)
- **Reused nonce `k`** across two signatures → solve for `k` then the private key directly (two linear equations).
- **Biased/partial nonce** (top or bottom bits known/zero) → Hidden Number Problem via lattice (fpylll).
```python
# reused-nonce DSA/ECDSA private key recovery
def recover_priv(r, s1, z1, s2, z2, n):
    k = ((z1 - z2) * pow((s1 - s2) % n, -1, n)) % n
    d = ((s1 * k - z1) * pow(r, -1, n)) % n
    return d
```

Order of attack: factor the group order → if smooth, Pohlig-Hellman/`discrete_log`; if ECDSA/DSA, check nonce reuse/bias first (cheapest total break); otherwise lattice-reduce with `fpylll`.
