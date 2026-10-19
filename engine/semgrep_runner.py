from __future__ import annotations

import json
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path

_SEMGREP = shutil.which("semgrep")
def _int_env(name: str, default: int) -> int:
    try:
        return max(1, int(os.environ.get(name, str(default))))
    except (TypeError, ValueError):
        return default


_TIMEOUT = _int_env("HXCTF_SEMGREP_TIMEOUT", 60)
_SAMPLE_EXTS = ("py", "js", "ts", "java", "go", "php", "rb", "c", "cpp")

_CLASS_HINT = (("sql", "sqli"), ("cmdi", "cmdi"), ("command", "cmdi"), ("os.system", "cmdi"), ("ssrf", "ssrf"),
               ("path", "path-traversal"), ("traversal", "path-traversal"), ("deserial", "deserialization"),
               ("xxe", "xxe"), ("xss", "xss"), ("ssti", "ssti"), ("rce", "rce"), ("inject", "injection"))


def semgrep_available() -> bool:
    return _SEMGREP is not None


_RULE_DOC_RX = re.compile(r"(?m)^\s*rules\s*:")


def _is_oneline_json_rule(s: str) -> bool:
    t = (s or "").strip()
    if "\n" in t or not (t.startswith("{") and t.endswith("}")):
        return False
    try:
        d = json.loads(t)
        return isinstance(d, dict) and "rules" in d
    except Exception:
        return False


def _detect_checker_form(checker) -> str:
    s = str(checker).strip()
    if _RULE_DOC_RX.search(s) or _is_oneline_json_rule(s):
        return "yaml"
    _CMD_STRONG = re.compile(r"[|;`]\s|/bin/\w|\$\(|&&\s|\|\|\s")
    if _CMD_STRONG.search(s) or s.startswith("`"):
        return "command"
    return "pattern"


def _as_rule_yaml(checker) -> str:
    s = str(checker)
    if _RULE_DOC_RX.search(s):
        return s
    if _is_oneline_json_rule(s):
        try:
            d = json.loads(s)
        except Exception:
            return s
        for r in d.get("rules") or []:
            if isinstance(r, dict):
                r.setdefault("severity", "WARNING")
                r.setdefault("message", f"synthesized checker {r.get('id', 'rule')}")
        return json.dumps(d, ensure_ascii=False)
    form = _detect_checker_form(s)
    if form == "command":
        ids = re.findall(r"[a-zA-Z_]\w{2,30}", re.sub(r"[|;$`/]", " ", s))
        core = " ".join(sorted(set(ids))[:5])
        if core:
            pat = core.replace("\\", "\\\\").replace('"', '\\"')
        else:
            pat = s.replace("\\", "\\\\").replace('"', '\\"')[:100]
    else:
        pat = s.replace("\\", "\\\\").replace('"', '\\"')
    return ("rules:\n"
            "  - id: synth-checker\n"
            "    languages: [python, javascript, typescript, java, go, php, ruby, c, cpp]\n"
            "    severity: WARNING\n"
            "    message: synthesized checker match\n"
            f'    pattern: "{pat}"\n')


_SENSITIVE_ENV = ("BENCHMARK_TOKEN", "BENCHMARK_BASE_URL", "SOLVER_API_KEY")


def _clean_env() -> dict:
    return {k: v for k, v in os.environ.items() if k not in _SENSITIVE_ENV}


def _run_semgrep(checker, target_path: str) -> list[dict]:
    if not _SEMGREP:
        return []
    with tempfile.NamedTemporaryFile("w", suffix=".yaml", delete=False) as rf:
        rf.write(_as_rule_yaml(checker))
        rule = rf.name
    try:
        p = subprocess.run(
            [_SEMGREP, "--config", rule, "--json", "--quiet", "--disable-version-check",
             "--metrics=off", "--no-git-ignore", "--timeout", str(_TIMEOUT), target_path],
            capture_output=True, text=True, timeout=_TIMEOUT + 15, env=_clean_env())
        if not p.stdout.strip():
            return []
        return json.loads(p.stdout).get("results", []) or []
    except (subprocess.TimeoutExpired, json.JSONDecodeError, OSError, ValueError):
        return []
    finally:
        try:
            os.unlink(rule)
        except OSError:
            pass


def make_runner():
    def runner(checker, code: str) -> bool:
        d = tempfile.mkdtemp()
        try:
            for ext in _SAMPLE_EXTS:
                (Path(d) / f"sample.{ext}").write_text(str(code))
            return bool(_run_semgrep(checker, d))
        finally:
            shutil.rmtree(d, ignore_errors=True)
    return runner


def _vulnclass_of(res: dict) -> str | None:
    hay = (str(res.get("check_id", "")) + " " + str(res.get("extra", {}).get("message", ""))).lower()
    for key, vc in _CLASS_HINT:
        if ("." in key and key in hay) or re.search(r"(?<![a-z])" + re.escape(key) + r"(?![a-z])", hay):
            return vc
    return None


def make_src_runner(src_root: str):
    root = str(src_root)

    def src_runner(checker):
        results = _run_semgrep(checker, root)
        if not results:
            return None
        r = results[0]
        start = r.get("start", {}) or {}
        f = r.get("path", "?")
        try:
            f = os.path.relpath(f, root)
        except ValueError:
            pass
        return {"file": f, "line": start.get("line", "?"),
                "vulnclass": _vulnclass_of(r),
                "summary": (r.get("extra", {}).get("message") or f"checker match in {f}")[:200]}
    return src_runner


def load_corpus(path: str | None) -> list[dict]:
    if not path:
        return []
    p = Path(path)
    files = sorted(p.glob("*.json")) if p.is_dir() else ([p] if p.is_file() else [])
    out: list[dict] = []
    for fp in files:
        try:
            data = json.loads(fp.read_text())
        except (OSError, json.JSONDecodeError):
            continue
        for c in (data if isinstance(data, list) else [data]):
            if isinstance(c, dict) and c.get("name") and "vulnerable" in c and "patched" in c:
                out.append({"name": c["name"], "vulnerable": c["vulnerable"], "patched": c["patched"]})
    return out
