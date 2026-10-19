from __future__ import annotations


def weighted_cover(files: dict, weights: dict, chosen) -> float:
    covered: set = set()
    for f in chosen or ():
        covered |= set(files.get(f, ()))
    return sum(weights.get(loc, 0.0) for loc in covered)


def greedy_cover(files: dict, weights: dict, budget: int) -> list:
    chosen: list = []
    covered: set = set()
    remaining = set(files)
    for _ in range(max(0, budget)):
        best, best_gain = None, -1.0
        for f in remaining:
            gain = sum(weights.get(loc, 0.0) for loc in files[f] - covered)
            if gain > best_gain + 1e-12:
                best, best_gain = f, gain
        if best is None or best_gain <= 0:
            break
        chosen.append(best)
        covered |= set(files[best])
        remaining.discard(best)
    return chosen


class BayesTargeter:

    def __init__(self, targets: dict, costs: dict, *, sensitivity: float = 0.8, specificity: float = 0.9):
        self._p = {t: float(p) for t, p in targets.items()}
        self._c = {t: max(1e-9, float(costs.get(t, 1.0))) for t in targets}
        self._sens, self._spec = sensitivity, specificity

    def posterior(self) -> dict:
        return dict(self._p)

    def update(self, target: str, *, positive: bool) -> None:
        if target not in self._p:
            return
        p = self._p[target]
        if positive:
            lik_t, lik_nt = self._sens, 1 - self._spec
        else:
            lik_t, lik_nt = 1 - self._sens, self._spec
        post = lik_t * p / max(1e-12, lik_t * p + lik_nt * (1 - p))
        self._p[target] = min(1 - 1e-9, max(1e-9, post))

    def rank(self) -> list:
        return sorted(self._p, key=lambda t: self._p[t] / self._c[t], reverse=True)
