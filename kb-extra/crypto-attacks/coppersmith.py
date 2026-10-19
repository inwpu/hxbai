#!/usr/bin/env python3
"""Univariate Coppersmith (Howgrave-Graham) over fpylll — the sage-free small-root tool.

Finds a small integer root x0 of a MONIC polynomial f(x) modulo an unknown divisor of N
(|x0| <= X, gcd(f(x0),N) >= N^beta). No sage needed; uses fpylll's LLL + sympy for the
final integer root. Verified: recovers a 512-bit p from its top bits.

Main use cases (see /opt/kb/crypto-attacks/02):
  * factor N knowing the HIGH bits of a prime p        -> factor_with_high_bits(N, p_high, unknown_bits)
  * stereotyped RSA message m = known<<k + x, small x  -> coppersmith_small_roots([...], N, 1.0, X, m, t)

Tuning: raise m (and t) until it works; lattice dim = deg*m + t. Bound rule of thumb
        X < N**(beta**2/deg). For high-bits factoring deg=1, beta=0.5 -> X < N**0.25.
"""
from fpylll import IntegerMatrix, LLL
import sympy

def coppersmith_small_roots(coeffs, N, beta, X, m, t):
    """coeffs: f = sum coeffs[i]*x^i, MONIC (coeffs[-1]==1). Returns list of integer roots x0."""
    d = len(coeffs) - 1
    def pmul(a, b):
        r = [0]*(len(a)+len(b)-1)
        for i, ai in enumerate(a):
            for j, bj in enumerate(b):
                r[i+j] += ai*bj
        return r
    fpow = [[1]]
    for _ in range(1, m+1):
        fpow.append(pmul(fpow[-1], coeffs))
    polys = []
    for i in range(m):                       # g_{i,j} = N^{m-i} * x^j * f(x)^i
        Ni = N**(m-i)
        for j in range(d):
            polys.append([0]*j + [c*Ni for c in fpow[i]])
    for k in range(t):                       # h_k = x^k * f(x)^m
        polys.append([0]*k + fpow[m][:])
    dim = len(polys)
    M = IntegerMatrix(dim, dim)
    for r, p in enumerate(polys):
        for c in range(dim):
            M[r, c] = (p[c] if c < len(p) else 0) * (X**c)
    LLL.reduction(M)
    g = [M[0, c] // (X**c) for c in range(dim)]     # shortest vector -> unscale
    x = sympy.symbols('x')
    G = sum(int(g[i])*x**i for i in range(len(g)))
    if G == 0:
        return []
    try:
        return [int(r) for r in sympy.Poly(G, x).ground_roots().keys()]
    except Exception:
        return [int(r) for r in sympy.solve(G, x) if getattr(r, "is_integer", False)]

def factor_with_high_bits(N, p_high, unknown_bits, m=4, t=2):
    """p = p_high + x0 with |x0| < 2**unknown_bits (p_high has the low bits zeroed). Returns (p,q) or None."""
    X = 1 << unknown_bits
    for x0 in coppersmith_small_roots([p_high, 1], N, 0.5, X, m, t):
        p = p_high + x0
        if p > 1 and N % p == 0:
            return p, N // p
    return None

if __name__ == "__main__":
    # self-test
    from sympy import randprime
    p = int(randprime(2**511, 2**512)); q = int(randprime(2**511, 2**512)); N = p*q
    unk = 110; ph = (p >> unk) << unk
    r = factor_with_high_bits(N, ph, unk)
    print("self-test:", "OK" if r and r[0] == p else "FAIL")
