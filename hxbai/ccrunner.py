from __future__ import annotations

import json
import os
import re
import subprocess
from dataclasses import dataclass, field
from typing import Callable, Optional

from .config import SolverConfig

_FLAG_BODY = r"[A-Za-z0-9_!?@#$%.+*~^-]{1,200}"
_BUILTIN_PREFIXES = ("flag", "HTB")
_FINAL_RX = re.compile(r"<FinalAnswer>(.*?)</FinalAnswer>", re.IGNORECASE | re.DOTALL)
_HANDOFF_RX = re.compile(r"<Handoff>(.*?)</Handoff>", re.IGNORECASE | re.DOTALL)


def _flag_rxes(flag_format):
    prefixes = list(_BUILTIN_PREFIXES)
    if flag_format and "{" in flag_format:
        p = flag_format.split("{", 1)[0].strip()
        if p and p.lower() not in (x.lower() for x in prefixes):
            prefixes.insert(0, p)
    return [re.compile(re.escape(p) + r"\{" + _FLAG_BODY + r"\}", re.IGNORECASE) for p in prefixes]

_MAX_TOOL_CHARS = 20000
_MAX_EVIDENCE = 400_000


def _first_flag_output_idx(outs, flag: str) -> int:
    if not flag:
        return -1
    import urllib.parse as _up
    for i, (_t, _a, o) in enumerate(outs):
        s = str(o)
        if flag in s:
            return i
        try:
            if flag in _up.unquote(s):
                return i
        except Exception:
            pass
    return -1


@dataclass
class CCResult:
    final_text: str = ""
    final_answer: str = ""
    handoff: str = ""
    flags: list[str] = field(default_factory=list)
    observed_output: str = ""
    tool_outputs: list[tuple] = field(default_factory=list)
    num_turns: int = 0
    tokens_used: int = 0
    is_error: bool = False
    error: str = ""

    def evidence_for(self, flag: str) -> str:
        return (self.observed_output or "")[:_MAX_EVIDENCE]

    def flag_from_probe_echo(self, flag: str) -> bool:
        outs = self.tool_outputs or []
        idx = _first_flag_output_idx(outs, flag)
        if idx < 0:
            return False
        _t, a, _o = outs[idx]
        cmd = (a.get("command") if isinstance(a, dict) else str(a)) or ""
        if isinstance(a, dict):
            cmd += " " + " ".join(f"{k}={v}" for k, v in a.items() if k != "command")
        return bool(flag) and (flag in cmd or flag.lower() in cmd.lower())

    def flag_from_own_narration(self, flag: str) -> bool:
        outs = self.tool_outputs or []
        idx = _first_flag_output_idx(outs, flag)
        if idx < 0:
            return False
        return _is_notes_read(outs[idx][0], outs[idx][1])

    def flag_from_static_source(self, flag: str) -> bool:
        outs = self.tool_outputs or []
        idx = _first_flag_output_idx(outs, flag)
        if idx < 0:
            return False
        _t, a, _o = outs[idx]
        cmd = (a.get("command") if isinstance(a, dict) else str(a)) or ""
        cl = cmd.lower()
        if not any(r in cl for r in ("cat ", "less ", "more ", "head ", "tail ", "strings ",
                                     "xxd ", "nl ", "sed -n", "type ", "get-content", "read ")):
            return False
        _SRC_EXT = (".py", ".js", ".ts", ".php", ".java", ".rb", ".go", ".c", ".cpp", ".rs", ".pl",
                    ".env", ".yml", ".yaml", ".conf", ".cnf", ".ini", ".xml", ".json", ".toml",
                    ".properties", ".cfg", ".config")
        if any(e in cl for e in _SRC_EXT):
            return True
        return any(w in cl for w in ("config", "settings", "source", "src/", "application.", "web.xml"))

    def evidence_window(self, flag: str) -> str:
        outs = self.tool_outputs or []
        idx = _first_flag_output_idx(outs, flag)
        if idx >= 0:
            window = outs[max(0, idx - 2): idx + 3]
            body = "\n".join(f"$ {(a.get('command') if isinstance(a, dict) else a)}\n{str(o)[:2000]}"
                             for _t, a, o in window)
            return (body + "\n\n[FinalAnswer]\n" + (self.final_answer or ""))[:12000]
        if outs:
            tail = "\n".join(f"$ {(a.get('command') if isinstance(a, dict) else a)}\n{str(o)[:1200]}"
                             for _t, a, o in outs[-4:])
            return ((self.final_answer or "") + "\n\n[近期输出]\n" + tail)[:12000]
        o = self.observed_output or ""
        return (o[:3000] + "\n...\n" + o[-3000:] + "\n\n" + (self.final_answer or ""))[:12000]


def extract_final_answer(text: str) -> str:
    m = _FINAL_RX.search(text or "")
    return m.group(1).strip() if m else ""


def extract_handoff(text: str) -> str:
    m = _HANDOFF_RX.search(text or "")
    return m.group(1).strip() if m else ""


def _is_notes_read(tool, args) -> bool:
    cmd = (args.get("command") if isinstance(args, dict) else str(args or "")) or ""
    note_path = str((args.get("file_path") or args.get("path") or "") if isinstance(args, dict) else "")
    low = (cmd + " " + note_path).lower()
    if "memory.md" not in low:
        return False
    return tool == "Read" or any(v in low for v in
                                 ("cat ", "head ", "tail ", "less ", "more ", "grep ", "nl ", "strings "))


def extract_flags(text: str, flag_format: Optional[str] = None) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()

    def _emit(v: str):
        v = v.strip()
        if not v or "{" not in v or "}" not in v:
            return
        body = v[v.index("{") + 1:v.rindex("}")]
        if v in seen or not body or body in ("...", "…"):
            return
        seen.add(v)
        out.append(v)

    for rx in _flag_rxes(flag_format):
        for m in rx.finditer(text or ""):
            _emit(m.group(0))
    try:
        import urllib.parse as _up
        decoded = _up.unquote(text or "")
        if decoded != (text or ""):
            for rx in _flag_rxes(flag_format):
                for m in rx.finditer(decoded):
                    _emit(m.group(0))
    except Exception:
        pass
    return out


def _install_longtask_guard(workdir: str) -> None:
    import shutil
    try:
        claude_dir = os.path.join(workdir, ".claude")
        os.makedirs(claude_dir, exist_ok=True)
        src = os.path.join(os.path.dirname(os.path.abspath(__file__)), "longtask_guard.py")
        if os.path.exists(src):
            shutil.copyfile(src, os.path.join(claude_dir, "longtask_guard.py"))
        settings_path = os.path.join(claude_dir, "settings.json")
        settings: dict = {}
        if os.path.exists(settings_path):
            try:
                with open(settings_path, encoding="utf-8") as f:
                    settings = json.load(f)
            except Exception:
                settings = {}
        hooks = settings.setdefault("hooks", {})
        pre = hooks.setdefault("PreToolUse", [])
        entry = {"matcher": "Bash",
                 "hooks": [{"type": "command",
                            "command": 'python3 "$CLAUDE_PROJECT_DIR/.claude/longtask_guard.py"'}]}
        if entry not in pre:
            pre.append(entry)
        with open(settings_path, "w", encoding="utf-8") as f:
            json.dump(settings, f, ensure_ascii=False, indent=1)
    except Exception:
        pass


def solve_with_claude_code(
    prompt: str,
    workdir: str,
    solver: SolverConfig,
    *,
    flag_format: Optional[str] = None,
    on_fact: Optional[Callable[[str, dict, str], None]] = None,
    claude_bin: Optional[str] = None,
    extra_args: Optional[list] = None,
    transcript_path: Optional[str] = None,
) -> CCResult:
    os.makedirs(workdir, exist_ok=True)
    _install_longtask_guard(workdir)
    binary = claude_bin or os.getenv("CLAUDE_BIN", "claude")
    env = dict(os.environ)
    for _k in ("BENCHMARK_TOKEN", "BENCHMARK_BASE_URL", "SOLVER_API_KEY"):
        env.pop(_k, None)
    env.update(solver.anthropic_env())

    argv = [
        binary, "-p",
        "--output-format", "stream-json",
        "--verbose",
        "--dangerously-skip-permissions",
        "--max-turns", str(solver.max_turns),
        "--model", solver.model,
    ]
    if extra_args:
        argv.extend(extra_args)

    res = CCResult()
    pending: dict[str, tuple] = {}
    assistant_text_parts: list[str] = []
    evidence_len = 0
    assistant_turns = 0

    try:
        proc = subprocess.Popen(
            argv, cwd=workdir, env=env,
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True, bufsize=1,
        )
    except FileNotFoundError as e:
        res.is_error = True
        res.error = f"claude CLI not found ({binary}): {e}"
        return res
    except Exception as e:
        res.is_error = True
        res.error = f"failed to launch claude: {e}"
        return res

    try:
        stdout, stderr = proc.communicate(input=prompt, timeout=solver.session_seconds)
    except subprocess.TimeoutExpired:
        proc.kill()
        try:
            stdout, stderr = proc.communicate(timeout=15)
        except Exception:
            stdout, stderr = "", ""
        res.error = "session timeout (normal for a long solve)"
    except Exception as e:
        res.error = f"communicate failed: {e}"
        stdout, stderr = "", ""

    if transcript_path:
        try:
            os.makedirs(os.path.dirname(transcript_path) or ".", exist_ok=True)
            with open(transcript_path, "w", encoding="utf-8") as tf:
                tf.write("=== MODEL: " + solver.model + " | BASE: " + solver.base_url + " ===\n")
                tf.write("=== TASK PROMPT ===\n" + prompt + "\n=== STREAM-JSON (raw) ===\n")
                tf.write(stdout or "")
                if stderr:
                    tf.write("\n=== STDERR ===\n" + stderr[:4000])
        except Exception:
            pass

    for line in (stdout or "").splitlines():
        line = line.strip()
        if not line or line[0] != "{":
            continue
        try:
            ev = json.loads(line)
        except Exception:
            continue
        etype = ev.get("type")
        if etype == "assistant":
            assistant_turns += 1
            try:
                _u = (ev.get("message", {}) or {}).get("usage") or {}
                if isinstance(_u, dict):
                    res.tokens_used += sum(int(_u.get(k, 0) or 0) for k in
                                           ("input_tokens", "output_tokens",
                                            "cache_creation_input_tokens", "cache_read_input_tokens"))
            except Exception:
                pass
            for block in (ev.get("message", {}) or {}).get("content", []) or []:
                if not isinstance(block, dict):
                    continue
                if block.get("type") == "text":
                    assistant_text_parts.append(block.get("text", ""))
                elif block.get("type") == "tool_use":
                    pending[block.get("id", "")] = (block.get("name", ""), block.get("input", {}) or {})
        elif etype == "user":
            for block in (ev.get("message", {}) or {}).get("content", []) or []:
                if not isinstance(block, dict) or block.get("type") != "tool_result":
                    continue
                name, args = pending.pop(block.get("tool_use_id", ""), ("tool", {}))
                output = _tool_result_text(block.get("content"))
                if not output:
                    continue
                snippet = output[:_MAX_TOOL_CHARS]
                res.tool_outputs.append((name, args, snippet))
                if evidence_len < _MAX_EVIDENCE:
                    res.observed_output += snippet + "\n"
                    evidence_len += len(snippet) + 1
                if on_fact is not None:
                    try:
                        on_fact(name, args, snippet)
                    except Exception:
                        pass
        elif etype == "result":
            res.final_text = ev.get("result", "") or ""
            res.num_turns = int(ev.get("num_turns", 0) or 0)
            if ev.get("is_error") or ev.get("subtype") not in (None, "success"):
                res.is_error = True

    if not res.num_turns:
        res.num_turns = assistant_turns
    if not res.final_text:
        res.final_text = "\n".join(assistant_text_parts).strip()
    if (not res.final_text) and stderr:
        res.error = (res.error + " | " if res.error else "") + f"stderr: {stderr[:400]}"

    res.final_answer = extract_final_answer(res.final_text)
    res.handoff = extract_handoff(res.final_text)
    ordered: list[str] = []
    seen: set[str] = set()
    for src in (res.final_answer, res.final_text, res.observed_output):
        for f in extract_flags(src, flag_format):
            if f not in seen:
                seen.add(f)
                ordered.append(f)
    verbatim = [f for f in ordered if f in res.observed_output]
    res.flags = verbatim + [f for f in ordered if f not in verbatim]
    return res


def _tool_result_text(content) -> str:
    if content is None:
        return ""
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        parts = []
        for b in content:
            if isinstance(b, dict) and b.get("type") == "text":
                parts.append(b.get("text", ""))
            elif isinstance(b, str):
                parts.append(b)
        return "\n".join(parts)
    return str(content)
