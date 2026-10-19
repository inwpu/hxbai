from __future__ import annotations

from typing import Any, Callable


class CheckerGate:

    def __init__(self, runner: Callable[[Any, str], bool], corpus: list[dict]):
        self.runner = runner
        self.corpus = corpus or []

    def _hit(self, checker: Any, code: str) -> bool:
        return bool(self.runner(checker, code))

    def gate(self, checker: Any) -> tuple[bool, dict]:
        self._tp_code = ""
        """回放判定。返回 (passed, detail)。
        §14 #1 三形态归一:入口先归一(yaml/pattern/command → 统一 semgrep YAML),再过闸门。
        规则:**任一补丁版命中(FP)→ 立即拒**(不可信);要求**至少一条漏洞版命中(TP)**;二者兼备才过。"""
        from engine.semgrep_runner import _detect_checker_form, _as_rule_yaml
        _form = _detect_checker_form(checker)
        if _form == "command":
            checker = _as_rule_yaml(checker)
        if not self.corpus:
            return False, {"passed": False, "reason": "no CVE-replay corpus configured"}
        tp_case = None
        for case in self.corpus:
            try:
                if self._hit(checker, case.get("patched", "")):
                    return False, {"passed": False, "reason": f"false-positive on patched {case.get('name')}",
                                   "replayed_cve": case.get("name")}
                if tp_case is None and self._hit(checker, case.get("vulnerable", "")):
                    tp_case = case.get("name")
                    self._tp_code = case.get("vulnerable", "")
            except Exception as e:
                return False, {"passed": False, "reason": f"runner error: {e!r}"[:120]}
        if tp_case is None:
            return False, {"passed": False, "reason": "did not detect any known-vulnerable case (no TP)"}
        from engine.seqtest import sprt_decide
        _obs = [self._hit(checker, self._tp_code) for _ in range(3)] if self._tp_code else [True]
        _sprt_v, _ll, _n = sprt_decide(_obs)
        if _sprt_v == "NOT_REPRODUCED":
            return False, {"passed": False, "reason": f"SPRT: evidence insufficient (logLR={_ll:.2f}, n={_n})"}
        return True, {"passed": True, "replayed_cve": tp_case, "criterion": "CVE-replay: TP on vuln & no FP on patched",
                      "sprt": _sprt_v, "sprt_n": _n, "sprt_loglr": round(_ll, 2)}
