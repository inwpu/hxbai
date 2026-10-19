from __future__ import annotations

import math

SPRT_P1, SPRT_P0 = 0.9, 0.1
SPRT_ALPHA, SPRT_BETA = 0.05, 0.05
SPRT_MAX_N = 50


def sprt_bounds(*, p1: float = SPRT_P1, p0: float = SPRT_P0,
                alpha: float = SPRT_ALPHA, beta: float = SPRT_BETA) -> tuple[float, float]:
    return math.log((1 - beta) / alpha), math.log(beta / (1 - alpha))


def sprt_decide(observations: list, *, p1: float = SPRT_P1, p0: float = SPRT_P0,
                alpha: float = SPRT_ALPHA, beta: float = SPRT_BETA,
                max_n: int = SPRT_MAX_N) -> tuple[str, float, int]:
    log_a, log_b = sprt_bounds(p1=p1, p0=p0, alpha=alpha, beta=beta)
    ll = 0.0
    step_hit = math.log(p1 / p0)
    step_miss = math.log((1 - p1) / (1 - p0))
    n = 0
    for x in observations[:max_n]:
        n += 1
        ll += step_hit if x else step_miss
        if ll >= log_a:
            return "CONFIRMED", ll, n
        if ll <= log_b:
            return "NOT_REPRODUCED", ll, n
    return ("INCONCLUSIVE" if n >= max_n else "CONTINUE"), ll, n


def binom_p_value(k: int, n: int, p0: float) -> float:
    if n <= 0 or k < 0 or not (0 < p0 < 1):
        return 1.0
    k = min(k, n)
    tail = sum(math.comb(n, i) * p0 ** i * (1 - p0) ** (n - i) for i in range(k, n + 1))
    return min(1.0, tail)


def bh_fdr_control(pvalues: list, alpha: float = 0.1) -> list:
    n = len(pvalues)
    if n == 0:
        return []
    order = sorted(range(n), key=lambda i: pvalues[i])
    keep = 0
    for rank, i in enumerate(order, start=1):
        if pvalues[i] <= (rank / n) * alpha:
            keep = rank
    passed = set(order[:keep])
    return [i in passed for i in range(n)]
