from __future__ import annotations

import json
import re
from dataclasses import dataclass, field

from . import observability as obs
from .llm import LLMClient
from .oob import poll_server as _oob_hits

_OASSERT = {
    "ssti": lambda out: "49" in out,
    "cmdi": lambda out: bool(re.search(r"uid=\d+\([^)]*\)\s+gid=\d+", out)),
    "lfi": lambda out: bool(re.search(r"root:.*:0:0:", out)),
    "pathtrav": lambda out: bool(re.search(r"root:.*:0:0:", out)),
    "sqli": lambda out: bool(re.search(r"(SQL syntax|SQLITE_ERROR|ORA-\d|PG::|you have an error in your sql|UNION_OK)", out, re.I)),
    "xxe": lambda out: bool(re.search(r"root:.*:0:0:", out)),
}

_FLAG_PLACEHOLDER = ("...", "unknown", "flag{...}", "your_flag", "todo", "xxxx", "example")
_DECOY_BODY_MARKERS = ("test_flag", "testflag", "for_development", "development", "placeholder",
                       "sample", "dummy", "changeme", "change_me", "redacted", "notreal", "not_real",
                       "fake_flag", "fakeflag", "replace_me", "replaceme", "your_flag_here",
                       "verify_me", "verifyme", "welcome", "hello_world", "helloworld", "demo_flag",
                       "not_the_flag", "notthflag", "decoy", "example_flag",
                       "d3c0y", "d3coy", "f4ke", "f4k3", "fak3", "t3st", "te5t", "dumm1", "s4mple",
                       "n0tr3al", "n0t_real", "b4it", "bait", "honeypot", "trap_flag",
                       "示例", "沙箱", "诱饵", "假的", "测试flag", "占位", "样例", "陷阱")


@dataclass
class Claim:
    kind: str
    statement: str = ""
    value: str = ""
    vuln_class: str = ""
    expect: str = ""
    oob_token: str = ""
    observed_output: str = ""
    evidence_window: str = ""
    flag_format: str | None = None
    evidence: list = field(default_factory=list)
    verdict: str = "tentative"
    confidence: float = 0.0
    reasons: list = field(default_factory=list)


class Verifier:

    def __init__(self, llm: LLMClient | None = None, skeptic_votes: int | None = None):
        self.llm = llm
        import os as _os
        self.skeptic_votes = max(1, int(skeptic_votes if skeptic_votes is not None
                                        else _os.getenv("SKEPTIC_VOTES", "1")))
        self._verdict_cache: dict[str, tuple] = {}

    def verify(self, claim: Claim) -> Claim:
        key = self._cache_key(claim)
        if key in self._verdict_cache:
            verdict, conf, reasons = self._verdict_cache[key]
            return self._finalize(claim, verdict, conf,
                                  list(reasons) + ["verdict cached — same claim+evidence, same conclusion"])
        claim = self._verify_uncached(claim)
        self._verdict_cache[key] = (claim.verdict, claim.confidence, list(claim.reasons))
        if len(self._verdict_cache) > 512:
            self._verdict_cache.pop(next(iter(self._verdict_cache)))
        return claim

    @staticmethod
    def _cache_key(c: Claim) -> str:
        import hashlib
        return hashlib.sha1("|".join([
            c.kind, c.statement, c.value, c.vuln_class, c.expect, c.oob_token,
            c.evidence_window or (c.observed_output or "")[:4000], str(c.flag_format),
        ]).encode("utf-8", "replace")).hexdigest()

    def _verify_uncached(self, claim: Claim) -> Claim:
        obs.emit("claim_new", layer="verify",
                 payload={"kind": claim.kind, "statement": _evt_statement(claim),
                          "value": _evt_value(claim), "vuln_class": claim.vuln_class},
                 evidence=_evref(claim))
        ok, why = self._grounding(claim)
        self._gate_event("grounding", ok, why)
        if not ok:
            return self._finalize(claim, "rejected", 0.0, [f"grounding: {why}"])
        refuted, ran, nreason = self._negation(claim)
        self._gate_event("negation", (not refuted) and ran, nreason)
        if refuted:
            return self._finalize(claim, "rejected", 0.1, [f"negation refuted: {nreason}"])
        answered, missing = self._interrogation(claim)
        self._gate_event("interrogation", answered, "" if answered else f"missing: {missing}")
        if ran and answered:
            return self._finalize(claim, "confirmed", 0.9, ["passed all three gates"])
        if not ran:
            return self._finalize(claim, "tentative", 0.5, ["skeptic unavailable — cannot fully clear (safe default)"])
        return self._finalize(claim, "tentative", 0.5, [f"interrogation incomplete: {missing}"])

    def grounding_ok(self, claim: Claim) -> tuple[bool, str]:
        return self._grounding(claim)

    def _grounding(self, c: Claim) -> tuple[bool, str]:
        if c.oob_token:
            hits = _oob_hits(c.oob_token)
            if hits:
                protos = ",".join(sorted({h.get("protocol", "?") for h in hits}))
                return True, f"OOB callback received ({len(hits)} via {protos}) — blind finding confirmed out-of-band"
        out = c.observed_output or ""
        if not out.strip():
            return False, "no real execution output attached (and no OOB callback)"
        if c.kind == "flag":
            if _looks_placeholder(c.value):
                return False, "flag looks like a placeholder, not a real value"
            try:
                import urllib.parse as _up
                _out_decoded = _up.unquote(out)
            except Exception:
                _out_decoded = out
            if (c.value not in out and c.value.lower() not in out.lower()
                    and c.value not in _out_decoded and c.value.lower() not in _out_decoded.lower()):
                return False, "flag value does not appear in the real tool output (possible hallucination)"
            if c.flag_format and not _format_ok(c.value, c.flag_format):
                return False, f"flag does not match required format {c.flag_format}"
            return True, "flag present in real output and well-formed"
        if c.expect:
            return (c.expect in out, "expected marker present" if c.expect in out
                    else "expected marker absent from output")
        oracle = _OASSERT.get(c.vuln_class)
        if oracle is None:
            return False, f"no oracle for class '{c.vuln_class}' and no explicit expect marker"
        return (oracle(out), f"{c.vuln_class} oracle fired" if oracle(out) else f"{c.vuln_class} oracle did NOT fire")

    def _negation(self, c: Claim) -> tuple[bool, bool, str]:
        if self.llm is None:
            return False, False, "no skeptic model (cannot clear)"
        sysmsg = (
            "You are a maximally skeptical red-team reviewer. Your ONLY job is to REFUTE the security claim "
            "below. You are shown ONLY the claim and its raw evidence — deliberately NOT the original author's "
            "reasoning — so judge independently. Look hard for: environment noise, output that is not UNIQUELY "
            "explained by the claim, an unreachable trigger path, a guard/sanitizer that would block it, a "
            "coincidence, or a hallucinated/misread value. Default to skepticism. "
            'Reply ONLY JSON: {"refuted": true|false, "reason": "..."} — refuted=true only if you found a '
            "CREDIBLE concrete reason it is false; if you genuinely cannot, refuted=false."
        )
        ev = c.evidence_window or (c.observed_output or "")[:6000]
        base = (f"CLAIM ({c.kind}): {c.statement}\nVALUE: {c.value}\nCLASS: {c.vuln_class}\n"
                f"RAW EVIDENCE (real tool output):\n{ev}")
        refutes = ran = 0
        reasons: list[str] = []
        for v in range(self.skeptic_votes):
            user = base + (f"\n[independent review pass {v + 1}]" if self.skeptic_votes > 1 else "")
            d = self._ask_json(sysmsg, user)
            if d is None:
                continue
            ran += 1
            if bool(d.get("refuted")):
                refutes += 1
                reasons.append(str(d.get("reason", ""))[:150])
        if ran == 0:
            return False, False, "skeptic unavailable/unparseable (cannot clear)"
        refuted = refutes * 2 > ran
        return refuted, True, ("; ".join(reasons[:2]) if refuted else f"cleared ({refutes}/{ran} refuted)")

    def _interrogation(self, c: Claim) -> tuple[bool, list]:
        if self.llm is None:
            return False, ["no interrogator model (defaulted tentative)"]
        checklist = (["which exact input is attacker-controlled?",
                      "which line/endpoint is the sink the input reaches?",
                      "what exact bytes/payload triggered it?",
                      "is the observed output UNIQUELY explained by this claim (not another cause)?"]
                     if c.kind == "vuln" else
                     ["did this flag come from the target's REAL output (not model narration)?",
                      "what exact action/command produced it?",
                      "does it match the challenge's flag format?"])
        sysmsg = (
            "You are a rigorous verifier interrogating a security claim. For EACH question, decide whether "
            "the attached evidence concretely answers it. Be strict: 'probably' or 'the model said so' is NOT "
            "an answer. Reply ONLY JSON: {\"answered\": true|false, \"missing\": [\"<unanswered question>\", ...]}. "
            "answered=true only if EVERY question is concretely answered by the evidence."
        )
        ev = c.evidence_window or (c.observed_output or "")[:6000]
        user = (f"CLAIM ({c.kind}): {c.statement}\nVALUE: {c.value}\nCLASS: {c.vuln_class}\n"
                f"EVIDENCE:\n{ev}\n\nQUESTIONS:\n- " + "\n- ".join(checklist))
        d = self._ask_json(sysmsg, user)
        if d is None:
            return False, ["interrogator unavailable (defaulted tentative)"]
        return bool(d.get("answered")), list(d.get("missing", []))[:8]

    def _ask_json(self, sysmsg: str, user: str) -> dict | None:
        try:
            res = self.llm.chat([{"role": "system", "content": sysmsg},
                                 {"role": "user", "content": user}], max_tokens=700, temperature=0.0)
        except Exception as e:
            obs.emit("error", layer="verify", payload={"where": "adversarial-gate", "err": str(e)[:200]})
            return None
        return _parse_json(res.text or "")

    def _gate_event(self, gate: str, passed: bool, why: str) -> None:
        obs.emit("gate_pass" if passed else "gate_fail", layer="verify",
                 payload={"gate": gate, "why": why[:300]})

    def _finalize(self, c: Claim, verdict: str, conf: float, reasons: list) -> Claim:
        c.verdict, c.confidence, c.reasons = verdict, conf, reasons
        obs.emit("claim_verdict", layer="verify",
                 payload={"kind": c.kind, "value": _evt_value(c), "verdict": verdict,
                          "confidence": conf, "reasons": reasons},
                 evidence=_evref(c))
        return c


def _evt_value(c: Claim) -> str:
    if c.kind == "flag" and c.value:
        return c.value[:8] + "…"
    return (c.value or "")[:120]


def _evt_statement(c: Claim) -> str:
    s = c.statement or ""
    if c.kind == "flag" and c.value:
        s = re.sub(re.escape(c.value), c.value[:8] + "…", s, flags=re.IGNORECASE)
    return s[:300]


def _flag_body(flag: str) -> str:
    f = flag or ""
    if "{" in f and f.endswith("}"):
        return f[f.index("{") + 1:-1]
    return f


def _looks_placeholder(flag: str) -> bool:
    low = (flag or "").lower()
    if not low or low in _FLAG_PLACEHOLDER:
        return True
    body = _flag_body(low)
    if not body:
        return True
    if any((not m.isascii()) and m in body for m in _DECOY_BODY_MARKERS):
        return True
    segs = [t for t in re.split(r"[^a-z0-9]+", body) if t]
    return bool(segs) and all(t in _DECOY_VOCAB for t in segs)


def _marker_vocab() -> set:
    vocab = set()
    for m in _FLAG_PLACEHOLDER + _DECOY_BODY_MARKERS:
        if m.isascii():
            vocab.update(t for t in re.split(r"[^a-z0-9]+", m) if t)
    return vocab


_DECOY_VOCAB = _marker_vocab()


def _low_signal_body(flag: str) -> bool:
    body = _flag_body(flag or "")
    return len(body) < 6 or len(set(body)) < 3


def normalize_flag_body(flag: str) -> str:
    return _flag_body(flag or "").strip().lower()


def flag_confidence(flag: str, observed_output: str, flag_format: str | None = None) -> str:
    if _looks_placeholder(flag) or _low_signal_body(flag):
        return "low"
    out = observed_output or ""
    exact = bool(flag) and flag in out
    fmt_ok = (not flag_format) or _format_ok(flag, flag_format)
    if exact and fmt_ok:
        return "high"
    return "marginal"


def _format_ok(flag: str, fmt: str) -> bool:
    pat = re.escape(fmt).replace(r"\.\.\.", ".*").replace(r"\*", ".*")
    pat = re.sub(r"(?:\.\*)+", ".*", pat)
    return re.fullmatch(pat, flag, re.IGNORECASE) is not None


def _evref(c: Claim) -> dict:
    return {"chain": (c.evidence or [])[:10], "output_head": (c.observed_output or "")[:400]}


_JSON = re.compile(r"\{.*\}", re.DOTALL)


def _parse_json(text: str) -> dict | None:
    if not text:
        return None
    for cand in (text, _strip_fence(text)):
        try:
            d = json.loads(cand)
            if isinstance(d, dict):
                return d
        except Exception:
            pass
    m = _JSON.search(text)
    if not m:
        return None
    frag = m.group(0)
    for cand in (frag, frag[: frag.rfind("}") + 1]):
        try:
            d = json.loads(cand)
            if isinstance(d, dict):
                return d
        except Exception:
            continue
    return None


def _strip_fence(text: str) -> str:
    t = text.strip()
    if t.startswith("```"):
        t = re.sub(r"^```[a-zA-Z]*\n?", "", t)
        t = re.sub(r"\n?```$", "", t)
    return t
