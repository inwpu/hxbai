from __future__ import annotations

import inspect


def _takes_two_pos(fn) -> bool:
    try:
        params = list(inspect.signature(fn).parameters.values())
    except (ValueError, TypeError):
        return False
    pos = sum(1 for p in params if p.kind in (p.POSITIONAL_ONLY, p.POSITIONAL_OR_KEYWORD))
    return pos >= 2 or any(p.kind == p.VAR_POSITIONAL for p in params)


class ScenarioProfile:
    name = "base"
    is_koh = False

    def is_achieved(self, loop) -> bool:
        raise NotImplementedError

    def adjudicate(self, loop, candidates: set) -> None:
        return None

    def summary(self, loop) -> dict:
        raise NotImplementedError

    def verifiable(self, cap_extra: dict) -> bool:
        from engine import verify as V
        return (cap_extra.get("access") or "").lower() in V.EXEC_ACCESS and bool(cap_extra.get("payload"))

    def verify(self, execute_fn, payload, recipe: str = "") -> tuple[bool, dict]:
        from engine import verify as V
        return V.verify_capability(execute_fn, payload, recipe=recipe)

    def enrich(self, tsg, scope_check=None) -> int:
        return 0

    def verify_candidates(self, tsg, attempted: set) -> list:
        import json as _json
        out = []
        try:
            for r in tsg.q("SELECT id, ukey, title, extra FROM nodes WHERE type='capability' "
                           "AND verified=0 ORDER BY updated_ts DESC"):
                if r["ukey"] in attempted:
                    continue
                ex = _json.loads(r["extra"] or "{}")
                if self.verifiable(ex):
                    out.append(("capability", r["id"], r["ukey"], r["title"], ex))
        except Exception:
            return []
        return out


class BenchmarkProfile(ScenarioProfile):
    name = "benchmark"

    def __init__(self, need_flags: int = 1, adjudicate_fn=None):
        self.need_flags = max(1, need_flags)
        self._adjudicate_fn = adjudicate_fn

    def _oracle(self, loop):
        return self._adjudicate_fn or getattr(loop, "on_wave", None)

    def is_achieved(self, loop) -> bool:
        if self._oracle(loop) is not None:
            r = loop.tsg.q1("SELECT COUNT(*) c FROM nodes WHERE type='flag' AND state='confirmed'")
            return (r["c"] if r else 0) >= self.need_flags
        from engine.judge import confident_flags
        return len(confident_flags(loop.captured, self.need_flags)) >= self.need_flags

    def adjudicate(self, loop, candidates: set) -> None:
        oracle = self._oracle(loop)
        if oracle is None:
            return
        lo = loop.local_only_of(candidates) if hasattr(loop, "local_only_of") else set()
        verdict = (oracle(candidates, lo) if lo and _takes_two_pos(oracle)
                   else oracle(candidates))
        loop._apply_verdict(verdict)

    def summary(self, loop) -> dict:
        rows = loop.tsg.q("SELECT ukey FROM nodes WHERE type='flag' AND state='confirmed' ORDER BY created_ts")
        confirmed = [r["ukey"] for r in rows]
        return {"flags": sorted(confirmed) or sorted(loop.captured)}


class KOHScenarioAdapter:
    pass


def make_koh_profile(need_flags: int = 1):
    from engine.koh import KOHProfile
    core = KOHProfile(need_flags)

    class _KOH(FindingLiveProfile):
        name = "koh"
        is_koh = True

        def is_achieved(self, loop) -> bool:
            return core.is_achieved(loop)

        def hold_value(self, loop) -> float:
            return core.hold_value(loop)

        def summary(self, loop) -> dict:
            _s = {"held": core.hold_value(loop)}
            return _s

    return _KOH()


class FindingLiveProfile(ScenarioProfile):
    name = "finding-live"

    def __init__(self, need_findings: int | None = None, oob=None, in_scope=None):
        self.need_findings = None if need_findings is None else max(1, need_findings)
        self.oob = oob
        self.in_scope = in_scope

    def verify(self, execute_fn, payload, recipe: str = "") -> tuple[bool, dict]:
        from engine import verify as V
        if self.oob is not None:
            return V.verify_capability_oob(execute_fn, payload, self.oob, self.in_scope, recipe=recipe)
        return V.verify_capability(execute_fn, payload, recipe=recipe)

    def enrich(self, tsg, scope_check=None) -> int:
        from engine import enrich as _EN
        _hard = scope_check or (lambda h: True)
        _extra = self.in_scope or (lambda ip: True)
        return _EN.enrich_pending(tsg, scope_check=lambda h: _hard(h) and _extra(h))

    def verify_candidates(self, tsg, attempted: set) -> list:
        out = super().verify_candidates(tsg, attempted)
        try:
            for r in tsg.q("SELECT id, vulnclass, summary, evidence_ref, extra FROM findings "
                           "WHERE verified=0 AND (evidence_ref IS NOT NULL OR vulnclass IN "
                           "('sqli','authbypass','infoleak','ssrf','idor')) ORDER BY rowid DESC"):
                import json as _json
                ex = _json.loads(r["extra"] or "{}")
                ukey = f"fdiff:{r['id']}"
                if ukey in attempted or ex.get("rechecked"):
                    continue
                ev = tsg.q1("SELECT content FROM evidence WHERE id=?", (r["evidence_ref"],)) if r["evidence_ref"] else None
                recipe = (ev["content"] if ev else "") or r["summary"]
                out.append(("finding", r["id"], ukey, f"{r['vulnclass']}: {r['summary'][:80]}",
                            {"recipe": recipe[:2000], "vulnclass": r["vulnclass"]}))
        except Exception:
            pass
        return out

    def verify_effect(self, effect_type: str, **kwargs) -> str:
        from engine.effect_oracle import canary_rce_verdict, db_checksum_diff, content_exact_exfil, privesc_verdict
        if effect_type == "canary_rce":
            return canary_rce_verdict(kwargs.get("shell_output", ""), kwargs.get("canary", ""))
        if effect_type == "db_diff":
            return db_checksum_diff(kwargs.get("before", ""), kwargs.get("after", ""))["verdict"]
        if effect_type == "exfil":
            return content_exact_exfil(kwargs.get("observed", ""), kwargs.get("expected", ""))
        if effect_type == "privesc":
            return privesc_verdict(kwargs.get("before_id", ""), kwargs.get("after_id", ""))
        return "UNKNOWN_EFFECT_TYPE"

    def _confirmed(self, loop) -> int:
        r = loop.tsg.q1("SELECT COUNT(*) c FROM findings WHERE verified=1")
        return r["c"] if r else 0

    def is_achieved(self, loop) -> bool:
        return (self.need_findings is not None
                and self._confirmed(loop) >= self.need_findings)

    def summary(self, loop) -> dict:
        rows = loop.tsg.q("SELECT vulnclass,cwe,owasp,severity,summary,evidence_ref FROM findings "
                          "WHERE verified=1 ORDER BY created_ts")
        return {"confirmed_findings": [dict(r) for r in rows]}


class FindingSourceProfile(ScenarioProfile):
    name = "finding-source"

    def __init__(self, gate, need_findings: int | None = None, src_runner=None):
        self.gate = gate
        self.need_findings = None if need_findings is None else max(1, need_findings)
        self.src_runner = src_runner

    def verifiable(self, cap_extra: dict) -> bool:
        return bool(cap_extra.get("payload"))

    def verify(self, execute_fn, payload, recipe: str = "") -> tuple[bool, dict]:
        passed, detail = self.gate.gate(payload)
        detail = {**detail, "criterion": detail.get("criterion", "CVE-replay gate"), "flags": set()}
        if not passed:
            return False, detail
        if self.src_runner is None:
            return False, {**detail, "passed": False, "stage": "config",
                           "reason": "no /src runner: cannot confirm a source finding"}
        hit = self.src_runner(payload)
        if not hit:
            return False, {**detail, "passed": False, "stage": "src",
                           "reason": "gated checker but no real /src hit"}
        h = hit if isinstance(hit, dict) else {}
        loc = f"{h.get('file','?')}:{h.get('line','?')}"
        return True, {**detail,
                      "src_hit": loc,
                      "vulnclass": h.get("vulnclass"),
                      "summary": h.get("summary") or f"{detail.get('replayed_cve','checker')} match at {loc}",
                      "criterion": f"CVE-replay gate + /src hit @ {loc}"}

    def verify_effect(self, effect_type: str, **kwargs) -> str:
        from engine.effect_oracle import canary_rce_verdict, db_checksum_diff, content_exact_exfil, privesc_verdict
        if effect_type == "canary_rce":
            return canary_rce_verdict(kwargs.get("shell_output", ""), kwargs.get("canary", ""))
        if effect_type == "db_diff":
            return db_checksum_diff(kwargs.get("before", ""), kwargs.get("after", ""))["verdict"]
        if effect_type == "exfil":
            return content_exact_exfil(kwargs.get("observed", ""), kwargs.get("expected", ""))
        if effect_type == "privesc":
            return privesc_verdict(kwargs.get("before_id", ""), kwargs.get("after_id", ""))
        return "UNKNOWN_EFFECT_TYPE"

    def _confirmed(self, loop) -> int:
        r = loop.tsg.q1("SELECT COUNT(*) c FROM findings WHERE verified=1")
        return r["c"] if r else 0

    def is_achieved(self, loop) -> bool:
        return (self.need_findings is not None
                and self._confirmed(loop) >= self.need_findings)

    def summary(self, loop) -> dict:
        rows = loop.tsg.q("SELECT vulnclass,cwe,owasp,severity,summary,evidence_ref FROM findings "
                          "WHERE verified=1 ORDER BY created_ts")
        return {"gated_findings": [dict(r) for r in rows]}
