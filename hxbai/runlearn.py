from __future__ import annotations

import threading
from dataclasses import dataclass, field


def _tokens(s: str) -> set:
    import re
    return {t for t in re.split(r"[^a-z0-9一-鿿]+", (s or "").lower()) if len(t) >= 2}


@dataclass
class Learning:
    technique: str
    fingerprint: str
    lesson: str
    source: str
    confidence: float = 0.7

    def key(self) -> str:
        return f"{self.technique}|{self.lesson.strip().lower()[:120]}"


class RunLearningStore:

    def __init__(self):
        self._items: dict[str, Learning] = {}
        self._deadends: dict[str, dict[str, list]] = {}
        self._creds: dict[str, str] = {}
        self._lock = threading.Lock()

    def add_cred(self, user: str, secret: str, provenance: str = "") -> bool:
        import re as _re
        u, s_ = (user or "").strip(), (secret or "").strip()
        if not u or not s_ or len(u) > 48 or len(s_) > 64:
            return False
        if _re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}(:\d+)?", u) or _re.fullmatch(r"(\d{1,3}\.){3}\d{1,3}(:\d+)?", s_):
            return False
        if any(c in s_ for c in "([{ \t") or "$_" in s_ or s_.startswith(("/", "./", "../")):
            return False
        if any(c in u for c in " \t") or "$_" in u or u.startswith(("/", "./", "../")):
            return False
        with self._lock:
            if u in self._creds or len(self._creds) >= 12:
                return False
            self._creds[u] = (s_, (provenance or "").strip()[:80])
            return True

    def render_creds(self) -> str:
        with self._lock:
            items = list(self._creds.items())
        if not items:
            return ""
        lines = ["【本场凭据池（同靶场跨题可复用——新认证面第一波：先逐条重放这里+产品默认族，最后才字典；"
                 "勿自动爆破/触发锁定）】"]
        for u, (s_, prov) in items:
            lines.append(f"- {u} / {s_}" + (f"  ← {prov}" if prov else ""))
        return "\n".join(lines)

    @staticmethod
    def _dnorm(path: str) -> str:
        return " ".join(sorted(_tokens(path)))[:160]

    def add_deadend(self, source: str, path: str, why: str = "") -> bool:
        path = (path or "").strip()
        if not source or not path:
            return False
        key = self._dnorm(path)
        if not key:
            return False
        with self._lock:
            bucket = self._deadends.setdefault(source, {})
            rec = bucket.get(key)
            if rec is None:
                bucket[key] = [path[:200], (why or "").strip()[:160], 1]
                return False
            rec[2] += 1
            if why and not rec[1]:
                rec[1] = why.strip()[:160]
            return rec[2] >= 2

    def deadends_for(self, source: str) -> list[tuple]:
        with self._lock:
            return [(r[0], r[1]) for r in self._deadends.get(source, {}).values()]

    def render_deadends(self, source: str) -> str:
        items = self.deadends_for(source)
        if not items:
            return ""
        lines = ["# 【本轮已证死路 — 不要再走】"]
        for path, why in items[-8:]:
            lines.append(f"- {path}" + (f"  （原因：{why}）" if why else ""))
        return "\n".join(lines)

    def add(self, technique: str, fingerprint: str, lesson: str, source: str, confidence: float = 0.7) -> bool:
        lesson = (lesson or "").strip()
        if not lesson:
            return False
        it = Learning(technique=(technique or "").strip(), fingerprint=(fingerprint or "").strip(),
                      lesson=lesson, source=source, confidence=confidence)
        with self._lock:
            prev = self._items.get(it.key())
            if prev is None or confidence > prev.confidence:
                self._items[it.key()] = it
                return prev is None
            return False

    def recall(self, text: str, techniques=None, *, top: int = 3, exclude_source: str = "") -> list[Learning]:
        tset = set(techniques or [])
        ttok = _tokens(text)
        scored: list[tuple[float, Learning]] = []
        with self._lock:
            items = list(self._items.values())
        for it in items:
            if exclude_source and it.source == exclude_source:
                continue
            score = 0.0
            if it.technique and it.technique in tset:
                score += 3.0
            fp_overlap = len(_tokens(it.fingerprint) & ttok)
            score += fp_overlap
            if score > 0:
                scored.append((score * it.confidence, it))
        scored.sort(key=lambda x: -x[0])
        return [it for _s, it in scored[:top]]

    def render(self, learnings: list[Learning]) -> str:
        if not learnings:
            return ""
        lines = ["# Learned earlier THIS RUN on other challenges (same range/author — likely applies here):"]
        for it in learnings:
            tag = f"[{it.technique}] " if it.technique else ""
            lines.append(f"- {tag}{it.lesson}  (from {it.source})")
        return "\n".join(lines)

    def __len__(self):
        return len(self._items)


_RUN_STORE: RunLearningStore | None = None
_STORE_LOCK = threading.Lock()


def get_run_store() -> RunLearningStore:
    global _RUN_STORE
    with _STORE_LOCK:
        if _RUN_STORE is None:
            _RUN_STORE = RunLearningStore()
        return _RUN_STORE


def reset_run_store() -> None:
    global _RUN_STORE
    with _STORE_LOCK:
        _RUN_STORE = None
