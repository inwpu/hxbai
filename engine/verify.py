from __future__ import annotations

import hashlib
import os
import re
import time

from engine.judge import Judge, text_of_event

EXEC_ACCESS = {"rce", "shell", "webshell", "root", "sudo", "code execution", "code_execution"}

_VERIFY_SYSTEM = """\
You are a VERIFICATION probe. A prior step CLAIMED a command-execution primitive works against the \
target. Your ONLY job is to test whether that primitive REALLY executes code ON THE TARGET, by \
driving the engine's challenge through it and reporting what THE TARGET returned.

Rules (read carefully):
- Make the TARGET execute the challenge, via the given primitive. The point is to test the target, \
not to produce the answer.
- Do NOT compute the answer on your own machine. Do NOT run the hash locally, do NOT guess, do NOT \
fabricate. Only the target's own response counts.
- If the primitive does NOT actually execute on the target (e.g. it just reflects your input), the \
answer will simply be ABSENT from the target's response. That is the correct, expected, useful \
result — report it as-is. A missing answer is a valid negative; a fabricated answer is worthless.
- End with exactly one line giving the target's response to the challenge, verbatim:
    verify_output: <exact bytes the target returned, trimmed>\
"""


def make_challenge() -> tuple[str, str]:
    nonce = os.urandom(16).hex()
    expected = hashlib.sha256(nonce.encode()).hexdigest()[:16]
    return nonce, expected


def _recipe_block(recipe: str) -> list[str]:
    r = str(recipe or "").strip()
    if not r:
        return []
    r = r[-2500:]
    return ["", "PRIOR STEPS THAT ESTABLISHED THIS PRIMITIVE (a multi-step/stateful exploit may need you to "
            "REPRODUCE these first — e.g. re-poison then re-trigger — before the challenge will run through it):",
            "\n".join("  | " + ln for ln in r.splitlines())]


def render_differential(recipe: str) -> str:
    return (
        "Differential verification task. A candidate vulnerability was observed with this primitive:\n"
        f"{recipe[:2000]}\n\n"
        "Reproduce it as a controlled experiment — fire the request TWICE against the same endpoint:\n"
        "  A) BASELINE — the normal/authorized context (e.g. your own session, unmodified params).\n"
        "  B) PROOF — the attack context from the primitive (e.g. other-user identifier, bypass payload).\n"
        "Then echo the raw key parts of BOTH responses exactly as observed, wrapped in markers:\n"
        "===BASELINE===\n<raw response key lines>\n===PROOF===\n<raw response key lines>\n===END===\n"
        "Rules: use real tool calls (no guesses); echo raw output only (no summaries); if the endpoint is "
        "unreachable, say so in plain output (no markers).")


def render_verify(primitive_payload: str, nonce: str, recipe: str = "") -> str:
    payload = str(primitive_payload or "")[:2000]
    return "\n".join([
        _VERIFY_SYSTEM, "",
        "ESTABLISHED PRIMITIVE (claimed to give command execution on the target):",
        "\n".join("  | " + ln for ln in payload.splitlines()) or "  | (none given)",
    ] + _recipe_block(recipe) + [
        "",
        "CHALLENGE — make the TARGET (via that primitive, executing on the target) compute the "
        "SHA-256 hex digest of this exact string and return the first 16 hex characters of it. "
        "The target must run the hashing itself; you only relay its response:",
        f"  nonce = {nonce}",
        "Report the target's raw response and the verify_output line.",
    ])


_OOB_SYSTEM = """\
You are a VERIFICATION probe. A prior step CLAIMED a command-execution (or SSRF) primitive against \
the target. Test whether it REALLY makes the TARGET reach out: using ONLY that primitive, cause the \
TARGET to send an HTTP request to the engine callback URL below. Report what you did. Do NOT curl \
the URL from your own machine — the callback must originate FROM THE TARGET, or it proves nothing.\
"""


def render_oob_verify(primitive_payload: str, callback_url: str, recipe: str = "") -> str:
    payload = str(primitive_payload or "")[:2000]
    return "\n".join([
        _OOB_SYSTEM, "",
        "ESTABLISHED PRIMITIVE (claimed to execute / SSRF on the target):",
        "\n".join("  | " + ln for ln in payload.splitlines()) or "  | (none given)",
    ] + _recipe_block(recipe) + [
        "",
        f"CHALLENGE — make the TARGET itself request this engine callback URL: {callback_url}",
        "(e.g. run `curl <url>` THROUGH the primitive so it fires from the target, not your box).",
    ])


def verify_capability_oob(execute_fn, primitive_payload: str, oob, in_scope=None,
                          wait_s: float = 6.0, recipe: str = "") -> tuple[bool, dict]:
    nonce = "cb" + os.urandom(12).hex()
    if hasattr(oob, "expect"):
        oob.expect(nonce)
    prompt = render_oob_verify(primitive_payload, oob.url(nonce), recipe=recipe)
    events = execute_fn(prompt)
    j = Judge()
    for ev in (events or []):
        t, ch = text_of_event(ev)
        if t:
            j.observe(t, ch)
    src = None
    deadline = time.time() + wait_s
    while time.time() < deadline:
        src = oob.hit(nonce)
        if src is not None:
            break
        time.sleep(0.1)

    def _reject_all(ip):
        return False
    scoped = in_scope or _reject_all
    confirmed = src is not None and bool(scoped(src))
    detail = {"nonce": nonce, "callback_src": src, "criterion": "oob callback from in-scope target",
              "confirmed": confirmed, "flags": set(j.submittable())}
    return confirmed, detail


EXTRACTION_CLASSES = {"sqli", "authbypass", "infoleak", "ssrf", "idor"}
DIFF_CLASSES = {"lfi", "cmdi", "ssti", "deserialization", "upload", "csrf", "crlf"}


def render_differential_for(vulnclass: str, recipe: str) -> str:
    vc = (vulnclass or "").lower()
    if vc in EXTRACTION_CLASSES:
        if vc == "sqli":
            return (
                "Data-extraction verification task. A candidate SQL injection was identified:\n"
                f"Primitive: {recipe[:1500]}\n\n"
                "Run the controlled experiment — fire the SAME query TWICE:\n"
                "  WITHOUT injection — a benign value (e.g. product_id=1): observe what an authorized user sees.\n"
                "  WITH injection — the attack payload that extracts protected data: observe what leaks.\n"
                "Then echo the raw responses wrapped in markers:\n"
                "===BASELINE===\n<raw response: benign query result>\n"
                "===PROOF===\n<raw response: injected query result showing protected data>\n===END===\n"
                "Rules: use real tool calls; echo raw output; if extraction fails, say so plainly.")
        elif vc == "authbypass":
            return (
                "Access-control verification task. An auth bypass was claimed:\n"
                f"Claim: {recipe[:1500]}\n\n"
                "Run the controlled experiment — access the protected resource TWICE:\n"
                "  WITHOUT bypass — unauthenticated/denied request: observe the rejection.\n"
                "  WITH bypass — using the claimed bypass: observe the unauthorized access.\n"
                "Then echo both raw responses wrapped in markers:\n"
                "===BASELINE===\n<raw response: denied/unauthorized>\n"
                "===PROOF===\n<raw response: unauthorized access granted, protected data visible>\n===END===\n"
                "Rules: use real tool calls; echo raw output; if bypass fails, say so.")
        else:
            return (
                f"Data-exposure verification task ({vulnclass}).\nPrimitive: {recipe[:1500]}\n\n"
                "Demonstrate the exposure differential:\n"
                "===BASELINE===\n<what should be visible/authorized>\n"
                "===PROOF===\n<what is actually exposed/leaked>\n===END===\n"
                "Rules: use real tool calls; echo raw output.")
    return render_differential(recipe)


def verify_extraction(execute_fn, vulnclass: str, finding_summary: str) -> tuple:
    from engine.judge import text_of_event
    events = execute_fn(
        f"Extraction verification for {vulnclass}: {finding_summary[:500]}\n"
        "Re-demonstrate the extraction: use the established technique to obtain the protected data, "
        "then state ===EXTRACTED===\n<data obtained>\n===END=== in your response. "
        "Use real tool calls (no guesses).")
    has_tool = False
    assertion_texts = []
    for ev in (events or []):
        if not isinstance(ev, dict):
            continue
        t, ch = text_of_event(ev)
        if isinstance(ev, dict) and ev.get("type") == "assistant":
            for c in (ev.get("message", {}).get("content") or []):
                if isinstance(c, dict) and c.get("type") == "tool_use":
                    has_tool = True
        if t and ch == "assertion":
            assertion_texts.append(t)
    joined = "\n".join(assertion_texts)
    has_extracted = bool(re.search(r"===\s*EXTRACTED\s*===", joined))
    if has_extracted and has_tool:
        m = re.search(r"===\s*EXTRACTED\s*===\s*((?:(?!===\s*(?:END|EXTRACTED)\b).)+?)\s*"
                      r"(?:===\s*END\s*===|$)", joined, re.S)
        extracted = m.group(1).strip()[:2000] if m else ""
        substantive = [ln for ln in extracted.splitlines() if len(ln.strip()) >= 4]
        if not substantive:
            return "inconclusive", {"extracted": extracted, "vulnclass": vulnclass,
                                    "criterion": "extraction markers present but content empty/trivial (no data shown)"}
        return "confirmed", {"extracted": extracted, "vulnclass": vulnclass,
                             "criterion": "extraction demonstrated with real tool calls"}
    if has_extracted and not has_tool:
        return "inconclusive", {"extracted": "", "vulnclass": vulnclass,
                                "criterion": "extraction claimed but no tool calls (fabrication shape)"}
    return "inconclusive", {"extracted": "", "vulnclass": vulnclass,
                            "criterion": "no extraction evidence found"}


_DIFF_BASE_RX = re.compile(r"===\s*BASELINE\s*===\s*(.+?)\s*===\s*PROOF\s*===\s*(.+?)\s*(?:===\s*END\s*===|$)", re.S)


def _effect_of(diff_lines: list) -> dict:
    joined = "\n".join(diff_lines)
    if re.search(r"uid\s*=\s*0\b|gid\s*=\s*0\b|\broot\b.*:.*0.*0|NT AUTHORITY\\SYSTEM", joined):
        return {"type": "privesc", "kwargs": {"before_id": "non-root", "after_id": "uid=0/root"}}
    if re.search(r"@(\w+\.)?\w+\.com|password|secret|token|api[_-]?key", joined, re.I):
        return {"type": "exfil", "kwargs": {"observed": joined[:400], "expected": "baseline-private-data"}}
    return {}


def verify_differential(execute_fn, recipe: str = "", vulnclass: str = "") -> tuple[str, dict]:
    prompt = render_differential_for(vulnclass, recipe) if vulnclass else render_differential(recipe)
    events = execute_fn(prompt)
    _seg_rx = re.compile(r"===\s*BASELINE\s*===\s*(.+?)\s*(?:===\s*PROOF\s*===|$)", re.S)
    _prf_rx = re.compile(r"===\s*PROOF\s*===\s*(.+?)\s*(?:===\s*END\s*===|$)", re.S)
    base_raw = proof_raw = None
    has_tool_use = False
    _assertion_texts = []
    for ev in (events or []):
        t, ch = text_of_event(ev)
        if not t:
            if isinstance(ev, dict) and ev.get("type") == "assistant":
                for c in (ev.get("message", {}).get("content") or []):
                    if isinstance(c, dict) and c.get("type") == "tool_use":
                        has_tool_use = True
            continue
        mb, mp = _seg_rx.search(t), _prf_rx.search(t)
        if mb and mp and ch == "observation":
            return "inconclusive", {"baseline": "", "proof": "", "diff": [], "effect": {},
                                    "criterion": "rejected: both sections in ONE tool result (fabrication shape)"}
        if ch == "observation":
            if mb and base_raw is None:
                base_raw = mb.group(1).strip()
            if mp and proof_raw is None:
                proof_raw = mp.group(1).strip()
        elif ch == "assertion":
            _assertion_texts.append(t)
            if isinstance(ev, dict) and ev.get("type") == "assistant":
                for c in (ev.get("message", {}).get("content") or []):
                    if isinstance(c, dict) and c.get("type") == "tool_use":
                        has_tool_use = True
    if not (base_raw and proof_raw) and has_tool_use and _assertion_texts:
        _joined = "\n".join(_assertion_texts)
        mb, mp = _seg_rx.search(_joined), _prf_rx.search(_joined)
        if mb:
            base_raw = base_raw or mb.group(1).strip()
        if mp:
            proof_raw = proof_raw or mp.group(1).strip()
    if not (base_raw and proof_raw):
        return "inconclusive", {"baseline": "", "proof": "", "diff": [], "effect": {},
                                "criterion": "BASELINE and PROOF in separate events (observation or tooled assertion)"}
    base_lines = {ln.strip() for ln in base_raw.splitlines() if ln.strip()}
    proof_lines = {ln.strip() for ln in proof_raw.splitlines() if ln.strip()}
    diff = sorted(ln for ln in proof_lines - base_lines if len(ln) >= 4)
    verdict = "confirmed" if diff else "refuted"
    return verdict, {"baseline": base_raw[:2000], "proof": proof_raw[:2000], "diff": diff[:50],
                     "effect": _effect_of(diff), "criterion": "proof-only lines vs baseline (observation channel)"}


def verify_capability(execute_fn, primitive_payload: str, recipe: str = "") -> tuple[bool, dict]:
    nonce, expected = make_challenge()
    prompt = render_verify(primitive_payload, nonce, recipe=recipe)
    events = execute_fn(prompt)
    j = Judge()
    obs_parts = []
    for ev in (events or []):
        t, ch = text_of_event(ev)
        if not t:
            continue
        if ch == "observation":
            obs_parts.append(t)
        j.observe(t, ch)
    obs = "\n".join(obs_parts)
    confirmed = expected in obs
    from engine.judge import channel_state, is_unreachable
    detail = {"nonce": nonce, "expected": expected,
              "criterion": "sha256(nonce)[:16] echoed via primitive",
              "confirmed": confirmed, "channel": channel_state(obs),
              "unreachable": is_unreachable(obs), "flags": set(j.submittable())}
    return confirmed, detail


import re as _re_mod
_CRASH_ANOMALY_RX = _re_mod.compile(
    r"Connection reset by peer|connection closed unexpectedly|Broken pipe|EOFError"
    r"|Connection timed out|Segmentation fault|core dumped|SIGSEGV|signal 11 received"
    r"|stack smashing detected|buffer overflow detected|\*\*\* stack smashing", _re_mod.I)
_EXPLOIT_RUN_RX = _re_mod.compile(
    r"(python3?|perl|bash|sh|\./|node)\s+\S*(exploit|poc|exp)[\w.-]*"
    r"|\S*(exploit|poc)[\w.-]*\.(py|pl|sh)\b", _re_mod.I)


def harvest_crash_primitive(events, target_hint: str = ""):
    hits, seen = [], set()
    evs = [e for e in (events or []) if isinstance(e, dict)]
    for i, ev in enumerate(evs):
        cmd = _tool_use_cmd(ev)
        if not cmd or not _EXPLOIT_RUN_RX.search(cmd):
            continue
        nxt = evs[i + 1] if i + 1 < len(evs) else {}
        res = nxt.get("type") == "user" and nxt.get("message", {}).get("content")
        text = ""
        if isinstance(res, list):
            text = " ".join(str(b.get("content", "")) for b in res if isinstance(b, dict))
        m = _CRASH_ANOMALY_RX.search(text)
        if not m:
            continue
        title = f"crash primitive vs {target_hint or 'target'} ({m.group(0)[:40]})"
        if title not in seen:
            seen.add(title)
            hits.append((title, f"$ {cmd[:300]}\n→ {m.group(0)}"))
    return hits


def _tool_use_cmd(ev) -> str:
    try:
        for b in (ev.get("message", {}).get("content") or []):
            if isinstance(b, dict) and b.get("type") == "tool_use":
                inp = b.get("input") or {}
                return str(inp.get("command") or inp.get("cmd") or inp.get("file_text") or "")
    except Exception:
        pass
    return ""


_ORACLE_CHANNELS = {
    "sqli": [
        "CASE WHEN (<COND>) THEN pg_sleep(2) ELSE pg_sleep(0) END",
        "(SELECT CASE WHEN (<COND>) THEN 1 ELSE 0 END)=1 -- boolean",
        "CAST((SELECT <COND>) AS int) -- error channel",
        "COPY t FROM PROGRAM $p$<cmd>$p$ -- file-read primitive (pg)",
        "dblink('host=... user=...', 'SELECT <COND>') -- out-of-band",
    ],
    "cmdi": [
        "$(sleep 2)", "`sleep 2`", "$IFS", "$(printf \\x73\\x68)", "base64 -d|sh",
    ],
}

_SYNTAX_XFORMS = [
    "%c2%27", "%2527", "%u0027",
    "chr(39)", "||'',", "''||''",
    "/**/", "+", "%0a", "%09",
]


def variant_matrix(payload: str, vulnclass: str = "sqli") -> list:
    out = []
    base = (payload or "").strip()
    for xf in _SYNTAX_XFORMS:
        out.append(base.replace("'", xf) if "'" in base else xf + base)
    for ch in _ORACLE_CHANNELS.get(vulnclass, []):
        out.append(ch)
    return out[:24]


def no_sqli_conclusion_gate(*, differential_done: bool, stacking_checked: bool) -> bool:
    return bool(differential_done and stacking_checked)
