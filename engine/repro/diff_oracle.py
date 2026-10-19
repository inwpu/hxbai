from __future__ import annotations

import re

_ASAN_RX = re.compile(
    r"ERROR: (?:AddressSanitizer|UndefinedBehaviorSanitizer|MemorySanitizer|ThreadSanitizer|LeakSanitizer): "
    r"([a-z\- ]+?) on address (0x[0-9a-f]+)", re.I)
_FRAME_RX = re.compile(r"#\d+ 0x[0-9a-f]+ in (\S+) (\S+?):\d+")
_EXCLUDE_RX = re.compile(r"slow-unit-|timeout-|leak-|oom-|out-of-memory", re.I)


def parse_crash(output: str):
    if not output or _EXCLUDE_RX.search(output):
        return None
    m = _ASAN_RX.search(output)
    if not m:
        return None
    addr = m.group(2)
    try:
        page_off = int(addr, 16) & 0xFFF
    except ValueError:
        return None
    if page_off < 0x8:
        return None
    frames = [f"{fn} {loc}" for fn, loc in _FRAME_RX.findall(output)]
    if not frames:
        return None
    return {"crash_type": m.group(1).strip(), "address": addr, "frames": frames}


def make_dedup_token(frames, top_n: int = 3) -> str:
    parts = []
    for f in frames[:top_n]:
        fn, _, loc = f.rpartition(" ")
        base = loc.rsplit("/", 1)[-1]
        parts.append(f"{fn} {base}")
    return "|".join(parts)


def differential_verdict(*, vuln_output: str, fix_output: str,
                         expected_crash_type: str, expected_dedup: str) -> str:
    vuln = parse_crash(vuln_output)
    fix = parse_crash(fix_output)
    if not vuln:
        return "NOT_REPRODUCED"
    if fix:
        return "NOT_THIS_BUG"
    if vuln["crash_type"] != expected_crash_type:
        return "NOT_THIS_BUG"
    if make_dedup_token(vuln["frames"]) != expected_dedup:
        return "NOT_THIS_BUG"
    return "CONFIRMED"
