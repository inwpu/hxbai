from __future__ import annotations

import hashlib
import os
import re
import threading
from concurrent.futures import ThreadPoolExecutor, wait as _cf_wait
from typing import NamedTuple

from engine import fold as F
from engine import invariants as INV
from engine import kb_search as KB
from engine import subgoal as SG
from engine import verify as V
from engine.decide import parse_decisions
from engine.judge import (Judge, text_of_event, tool_use_text, extract_candidates, _INNER_OF,
                          channel_state, is_unreachable, parse_flag_declarations, roundtrip_verify)
from engine.prompts import render_decide, render_execute
from engine.scope import EngagementScope
from engine.tsg import queries as Q
from engine.tsg.store import TSG

def log(msg: str) -> None:
    import sys
    sys.stdout.write(msg + "\n")
    sys.stdout.flush()


_KB_INDEX: "list | None" = None
_KB_INDEX_LOADED = False
_KB_INDEX_LOCK = threading.Lock()


def _kb_index():
    global _KB_INDEX, _KB_INDEX_LOADED
    if _KB_INDEX_LOADED:
        return _KB_INDEX
    with _KB_INDEX_LOCK:
        if _KB_INDEX_LOADED:
            return _KB_INDEX
        parts: list = []
        for _loader in (
            lambda: KB._load_index(KB.INDEX_PATH),
            lambda: KB._load_index(KB.NUCLEI_INDEX_PATH),
            lambda: KB._load_index(KB.DEFAULT_LOGIN_INDEX_PATH),
            lambda: KB.load_msf_index(KB.MSF_INDEX_PATH),
            lambda: KB.load_exploitdb_index(KB.EXPLOITDB_CSV_PATH, KB.EXPLOITDB_ROOT),
        ):
            try:
                parts.extend(list(_loader() or []))
            except Exception:
                pass
        _KB_INDEX = KB.attach_search_cache(parts) if parts else None
        _KB_INDEX_LOADED = True
    return _KB_INDEX


_FACT_RX = re.compile(r"submit_fact:\s*(.+)")
_RULEDOUT_RX = re.compile(r"submit_ruledout:\s*(.+)")
_PLAN_RX = re.compile(r"submit_plan:\s*(.+)")
_CAP_RX = re.compile(r"submit_capability:\s*(.+?)\s*::\s*(.+)")
_CAP_IFACE_RX = re.compile(r"\b(entry|grammar|failures)=", re.I)


def _parse_capability(payload: str) -> dict:
    out = {"payload": payload}
    marks = [(m.start(), m.group(1).lower()) for m in _CAP_IFACE_RX.finditer(payload or "")]
    if not marks:
        return out
    out["payload"] = payload[:marks[0][0]].strip()
    for i, (pos, key) in enumerate(marks):
        val_start = payload.index("=", pos) + 1
        val_end = marks[i + 1][0] if i + 1 < len(marks) else len(payload)
        out[key] = payload[val_start:val_end].strip()
    return out
_CIDR_RX = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3}/\d{1,2})\b")
_FLAGPATH_RX = re.compile(r"(/[\w./\-]*flag\w*\.\w+)", re.I)
_CAND_FLAG_RX = re.compile(r"[A-Za-z][\w.\-]{1,30}\{[^}\r\n]{2,}\}")

_ECHO_MARK_RX = re.compile(
    r"<the exact command|<one durable finding|<another durable|<where you are|<short label|<the exact value|"
    r"<rule-name>|<rule-id>|<the exact semgrep pattern>|<the-language>|"
    r"the exact command or payload, verbatim|emit as many as you have|if you are mid-way|"
    r"one durable finding, with its concrete|a later step would reuse|your plan and working hypotheses|"
    r"submit_(?:fact|capability|plan):|"
    r"the MOMENT you establish|inline as you work|a timeout can cut this session|anything not yet emitted is lost|"
    r"--output-format\b|--max-turns\b|stream-json\b|--dangerously\b|--verbose\b|--input-format\b", re.I)
_PROMPT_HEAD_RX = re.compile(
    r"OVERALL TASK:|YOUR OBJECTIVE:|TARGET:|ENGAGEMENT SCOPE|MACHINE-VERIFIED|COMPLETE INDEX|"
    r"EARLIER FACTS|CONCRETE NEXT ACTIONS|DELIVERABLES ALREADY IN HAND|PROVEN PRIMITIVES|CANDIDATE PRIMITIVES")
_LEVERAGE_SG_RX = re.compile(r"leverage the (?:obtained|established|gained)\b", re.I)
_DELIVERABLE_INTENT_RX = re.compile(
    r"\b(?:capture|captur\w+|read|obtain|retriev\w+|exfiltrat\w+|exfil|extract|steal|dump|acquire|access)\b"
    r"[^.\n]{0,52}\b(?:flags?|sensitive\s+(?:data|info\w*|file\w*|document\w*)|secret\w*|credential\w*|"
    r"databases?|the\s+data|PII|customer\s+(?:data|record\w*|database)|crown[\s-]?jewel\w*|domain\s+admin\w*|"
    r"protected\s+(?:data|file\w*)|core\s+(?:business\s+)?data)\b", re.I)
_SELF_COMPLETE_RX = re.compile(
    r"objective complete|mission accomplished|all flags (?:captured|obtained|found)|task complete|已完成.{0,4}目标", re.I)
_PROMOTE_LEAD_RX = re.compile(
    r"unbreach|untested|not yet (?:breach|exploit|access)|still\s+\S{0,12}\s*(?:unbreach|open|unexploit)|"
    r"remaining\s+(?:optional|target)|test\s+\S+\s+(?:there|creds|password)|credential hypothesis|未[攻利].{0,4}(?:破|用)", re.I)
_NEGATIVE_EXHAUST_RX = re.compile(
    r"no flag(?:s)? (?:found|in|present|here)|not (?:found|present) in (?:the )?(?:db|database|dump)|"
    r"dump\S{0,20}(?:empty|no flag)|no (?:FILE|write) (?:priv|permission)|exhausted\S{0,20}no flag|"
    r"(?:全|整)库\S{0,6}无.?flag|无\S{0,4}(?:写|FILE)权限", re.I)


def _clean_harvest(text: str):
    if not text:
        return None
    t = text.strip()
    if t.startswith("<"):
        return None
    cut = len(t)
    for rx in (_ECHO_MARK_RX, _PROMPT_HEAD_RX):
        m = rx.search(t)
        if m and m.start() < cut:
            cut = m.start()
    t = t[:cut].strip(" \t\n:-|")
    return t or None
_ACCESS_RX = re.compile(r"\b(root|admin|rce|shell|code execution|webshell|sudo)\b", re.I)

_VERIF_PROGRESS_KEYS = ("flags_confirmed", "capabilities_verified", "findings_verified")
_HINT_PROGRESS_KEYS = ("flags_confirmed", "capabilities_verified", "findings_verified", "analysis_insights")


def _face_anchored_progressed(prev: dict, cur: dict, has_unmet_pivot_route: bool) -> bool:
    keys = ("flags_confirmed", "deeper_verified") if has_unmet_pivot_route else _HINT_PROGRESS_KEYS
    return any(cur.get(k, 0) > prev.get(k, 0) for k in keys)


BRIDGE_STUCK_WAVES = 2
PIVOT_DROUGHT_WAVES = 4
FRONTIER_STALE_WAVES = 2
REFOCUS_CONTINUE_CALLS = 20
STALL_CUT_CALLS = 16
LEDGER_STALL_CALLS = 24
_PROGRESS_DECL_RX = re.compile(r"\bsubmit_(?:fact|capability|flag)\s*:|\bFinalAnswer\s*:", re.I)
_FLAG_DECL_RX = re.compile(r"\bsubmit_flag\s*:|\bFinalAnswer\s*:", re.I)
FLAG_GRACE_CALLS = 5
DEEP_MODE_MIN_OBS = 10

_SRC_DIST_RX_C = re.compile(
    r"(?:href=.|https?://\S{0,80}|curl\s+\S{0,80}|wget\s+\S{0,80}|available\s+at\s+\S{0,60}"
    r"|attachment\s+\S{0,60}|\bdownload\b.{0,40})"
    r"[^ \"'<>]{0,120}?[.](?:zip|apk|tgz|tar[.]gz)"
    r"|/(?:files|dl|downloads?)/[^ \"'<>]+?[.](?:zip|apk|tgz|tar[.]gz)",
    re.I)
_WAF_DENY_RX_C = re.compile('rule["\\s:=]*["\\s]*([A-Za-z0-9_.-]+)', re.I)
_CRED_SHAPE_RX_C = re.compile(
    r"password|passwd|\bpwd\b|credential|\bcred\b|secret|\btoken\b|api[_-]?key|"
    r"[\w.-]+\s*[/:]\s*[\w!@#$%^&*()_+\-=]{6,}", re.I)
def _effective_ledger(*, wave: int, pivot: bool, profile_name: str = "",
                      has_submit: bool = False, has_new_obs: bool = False) -> int:
    base = LEDGER_STALL_CALLS
    if profile_name in ("finding-live", "finding-source"):
        return base * 3
    if not has_submit and has_new_obs:
        return max(base * 3, base * 2 if pivot else base * 3)
    if wave < 2:
        return max(base * 3, base * 2 if pivot else base * 3)
    return base * 2 if pivot else base
_PRIV_TARGET_RX_C = re.compile(
    r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
    r"|192\.168\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?\b")


PARALLEL_STALL_WAVES = 2
PARALLEL_WAVES_CAP = 2
COLLAB_WORKER_HANG_CAP_S = 900 + 120
_PROOF_RX = re.compile(
    r"uid=\d+\([^)]*\)\s+gid=\d+"
    r"|\broot:[^:\s]*:0:0\b"
    r"|\broot@[\w.-]+:\s*[~/]"
    r"|\bLinux\s+\S+\s+\d+\.\d+\.\d+",
    re.I | re.M)


_PIVOT_DEPLOY_RX = re.compile(
    r"\bchisel\s+(?:server|client)\b"
    r"|\bsocat\s+tcp-?listen"
    r"|\bssh\s+-[NfDLR]\b|\bssh\s+-\w*[DLR]\b"
    r"|\bsshuttle\b|\bligolo|\biox\b|\bfrpc?\b|\bfrps\b|\bgost\b|\brevsocks\b"
    r"|\bncat\b[^|]*\b-l\b[^|]*\b-k\b"
    r"|\b(?:setsid|nohup)\b[^|]*(?:\b(?:socat|chisel|ncat|nc|python[0-9.]*)\b|/tmp/\S+)",
    re.I)


def _host_ukey(target: str) -> str:
    return target.split("//")[-1].split("/")[0].split(":")[0]


_CMD_TARGET_RX = re.compile(
    r"https?://([A-Za-z0-9_.\-]+)(?::(\d+))?"
    r"|\b(\d{1,3}(?:\.\d{1,3}){3})(?::(\d+))?\b")


def _cmd_target(cmd: str) -> str | None:
    m = _CMD_TARGET_RX.search(cmd or "")
    if not m:
        return None
    host = m.group(1) or m.group(3)
    port = m.group(2) or m.group(4)
    return f"{host}:{port}" if port else host


def _cmd_targets(cmd: str) -> list[str]:
    out: list[str] = []
    for m in _CMD_TARGET_RX.finditer(cmd or ""):
        host = m.group(1) or m.group(3)
        port = m.group(2) or m.group(4)
        out.append(f"{host}:{port}" if port else host)
    return out


_STRIP_ECHO = str.maketrans("", "", "\\'\"")


def _normalize_typed(s: str) -> str:
    from urllib.parse import unquote
    try:
        s = unquote(s or "")
    except Exception:
        s = s or ""
    return s.translate(_STRIP_ECHO)


def _typed_echo(cands, typed_norm: str) -> set:
    out = set()
    for c in cands:
        if c and len(c) >= 6 and c in typed_norm:
            out.add(c)
    return out


def _like_prefix(title: str, n: int = 40) -> str:
    esc = (title or "")[:n].replace("\\", "\\\\").replace("%", "\\%").replace("_", "\\_")
    return esc + "%"


_VULN_HINTS = [
    ("cmdi", r"command injection|cmdi|os command inject"),
    ("ssti", r"\bssti\b|template injection"),
    ("sqli", r"\bsqli\b|sql injection"),
    ("deserialization", r"deserial|pickle|unmarshal|objectinputstream|ysoserial"),
    ("lfi", r"\blfi\b|local file inclus|file inclusion|log poison|arbitrary file read"),
    ("pathtraversal", r"path traversal|directory traversal|\.\./"),
    ("ssrf", r"\bssrf\b|server-?side request"),
    ("fileupload", r"file upload|webshell upload|arbitrary (?:file )?upload"),
    ("xxe", r"\bxxe\b|xml external entit"),
    ("authbypass", r"auth(?:entication)? bypass|login bypass|jwt forg|alg=none"),
    ("privesc", r"privilege escalation|privesc|setuid|sudo abuse"),
    ("idor", r"\bidor\b|insecure direct object"),
    ("xss", r"\bxss\b|cross-?site script"),
    ("weakcred", r"weak (?:password|cred)|default (?:password|cred)|brute[- ]?force"),
    ("infoleak", r"info(?:rmation)? (?:leak|disclos)|sensitive data expos"),
    ("rce", r"\brce\b|remote code exec|code execution|reverse shell|web ?shell"),
]
_VULN_RX = [(k, re.compile(p, re.I)) for k, p in _VULN_HINTS]
_ACCESS_TO_VULN = {"root": "privesc", "sudo": "privesc", "admin": "authbypass",
                   "rce": "rce", "shell": "rce", "webshell": "rce", "code execution": "rce"}


def _classify_vuln(text: str, access: str = "") -> str | None:
    for k, rx in _VULN_RX:
        if rx.search(text or ""):
            return k
    return _ACCESS_TO_VULN.get((access or "").lower())


_SALIENT_RX = re.compile(
    r"\b[1-5]\d\d\b\s+(?:OK|Found|Moved|Redirect|Forbidden|Unauthorized|Bad|Not Found|Error)"
    r"|\b\d{1,5}/(?:tcp|udp)\b|\bopen\b"
    r"|Server:|X-Powered-By|WWW-Authenticate|Set-Cookie|Location:|Content-Type:"
    r"|\bv?\d+\.\d+(?:\.\d+)?\b"
    r"|error|exception|traceback|denied|refused|unauthorized|forbidden|timeout"
    r"|/(?:admin|login|api|upload|export|import|debug|actuator|swagger|graphql|console|manage)"
    r"|0x[0-9a-fA-F]{3,}|\.(?:text|data|bss|rodata|plt|got)\b|\bELF\b|\bPIE\b|\b(?:opcode|instruction|disasm|decompil|bytecode|register|stack canary|nx|relro)\b"
    r"|\b(?:xor|rc4|aes|des|rsa|base64|hex|keystream|cipher|plaintext|ciphertext|decrypt|decode|nonce|iv|md5|sha\d)\b"
    r"|\b(?:password|passwd|secret|api[_-]?key|token|credential|private[_-]?key|BEGIN [A-Z ]*PRIVATE KEY)\b|\buid=\d+|\broot:x:0:0|[A-Za-z0-9_.\-]+@[A-Za-z0-9.\-]+:\d+"
    r"|\b(?:10|172|192)\.\d{1,3}\.\d{1,3}\.\d{1,3}\b|\b(?:tunnel|pivot|reachable|internal host|jump host|lateral)\b"
    r"|\b(?:extracted|recovered|decrypted|decoded|cracked|bypassed|leaked|exfiltrated|ruled out|confirmed|obtained)\b",
    re.I)


_VOL_SUBS = [
    (re.compile(r"(?i)(set-cookie:\s*[^=\s]+=)[^\s;,]+"), r"\1<v>"),
    (re.compile(r"(?i)\b(nonce|csrf|xsrf|_?token|state|sid|session|etag|request-id|authorization|bearer)"
                r"(['\"]?\s*[:=]\s*)[^\s;,&'\"]+"), r"\1\2<v>"),
    (re.compile(r"\b[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}\b", re.I), "<uuid>"),
    (re.compile(r"\b[0-9a-f]{12,}\b", re.I), "<hex>"),
    (re.compile(r"\b\d{4}-\d\d-\d\d([ T][\d:.]+)?\b"), "<date>"),
    (re.compile(r"(?i)\b(?:mon|tue|wed|thu|fri|sat|sun),\s+\d{1,2}\s+"
                r"(?:jan|feb|mar|apr|may|jun|jul|aug|sep|oct|nov|dec)\s+\d{4}\s+[\d:]+(?:\s*gmt|\s*utc)?"), "<httpdate>"),
    (re.compile(r"\b\d{10,}\b"), "<ts>"),
    (re.compile(r"([?&][A-Za-z0-9_%.\-]{1,40}=)[^\s&#;]+"), r"\1<v>"),
    (re.compile(r"\b(?=[A-Za-z0-9]*[A-Za-z])(?=[A-Za-z0-9]*\d)[A-Za-z0-9]{8,}\b"), "<rand>"),
]


def _normalize_volatile(s: str) -> str:
    for rx, rep in _VOL_SUBS:
        s = rx.sub(rep, s)
    return s


_SECRET_RX = re.compile(
    r"AKIA[0-9A-Z]{12,}"
    r"|eyJ[A-Za-z0-9_\-]{8,}\.[A-Za-z0-9_\-]{8,}\.?[A-Za-z0-9_\-]*"
    r"|-----BEGIN [A-Z ]+-----"
    r"|(?i:(?:api[_-]?key|secret|password|passwd|token|access[_-]?key)\s*[:=]\s*\S{4,})"
    r"|[A-Za-z0-9+/]{40,}={0,2}")


_SVC_NMAP_RX = re.compile(r"\b(\d{1,5})/(?:tcp|udp)\s+open\s+([a-z0-9_.\-]+)", re.I)
_NMAP_HOST_RX = re.compile(r"[Nn]map scan report for\s+(.+)")
_IPV4_RX = re.compile(r"\d{1,3}(?:\.\d{1,3}){3}")
_HOSTNAME_RX = re.compile(r"[A-Za-z0-9_][A-Za-z0-9_.\-]*$")


def _host_of_scan_line(tail: str) -> str | None:
    tail = (tail or "").strip()
    m = re.search(r"\((" + _IPV4_RX.pattern + r")\)", tail)
    if m:
        return m.group(1)
    tok = tail.split()[0] if tail.split() else ""
    if _IPV4_RX.fullmatch(tok) or _HOSTNAME_RX.fullmatch(tok):
        return tok
    return None


def _ports_by_host_from_scan(obs: str, default_host: str) -> dict[str, list[int]]:
    result: dict[str, set] = {}
    cur = default_host
    for line in (obs or "").splitlines():
        mh = _NMAP_HOST_RX.search(line)
        if mh:
            cur = _host_of_scan_line(mh.group(1)) or default_host
            continue
        for mp in _SVC_NMAP_RX.finditer(line):
            port = int(mp.group(1))
            if 1 <= port <= 65535 and cur:
                result.setdefault(cur, set()).add(port)
    return {h: sorted(ps) for h, ps in result.items()}


_SVCBANNER_NMAP_RX = re.compile(r"\b\d{1,5}/(?:tcp|udp)\s+open\s+(\S[^\r\n]{0,70})", re.I)


def _svcbanners_by_host_from_scan(obs: str, default_host: str) -> dict[str, list[str]]:
    result: dict[str, list] = {}
    cur = default_host
    for line in (obs or "").splitlines():
        mh = _NMAP_HOST_RX.search(line)
        if mh:
            cur = _host_of_scan_line(mh.group(1)) or default_host
            continue
        for mp in _SVCBANNER_NMAP_RX.finditer(line):
            b = mp.group(1).strip()
            if b and cur:
                result.setdefault(cur, []).append(b)
    return result


_SVCBANNER_NMAP_PORT_RX = re.compile(r"\b(\d{1,5})/(?:tcp|udp)\s+open\s+(\S[^\r\n]{0,70})", re.I)


def _svcbanners_by_hostport_from_scan(obs: str, default_host: str) -> dict:
    result: dict = {}
    cur = default_host
    for line in (obs or "").splitlines():
        mh = _NMAP_HOST_RX.search(line)
        if mh:
            cur = _host_of_scan_line(mh.group(1)) or default_host
            continue
        for mp in _SVCBANNER_NMAP_PORT_RX.finditer(line):
            port = int(mp.group(1))
            b = mp.group(2).strip()
            if 1 <= port <= 65535 and b and cur:
                result.setdefault(cur, {})[port] = b
    return result
_SVC_HDR_RX = re.compile(r"(?im)^(?:Server|X-Powered-By):\s*(.{1,80})$")
_URL_RX = re.compile(r"(https?)://([A-Za-z0-9_.\-]+)(?::(\d{1,5}))?(/[^\s\"'<>)\]]*)?", re.I)
_REQLINE_RX = re.compile(r"(?im)^\s*(?:GET|POST|PUT|DELETE|PATCH|HEAD|OPTIONS)\s+(/[^\s?#]{0,120})")
_LOCATION_RX = re.compile(r"(?im)^Location:\s*(/[^\s?#]{0,120})")
_URLCRED_RX = re.compile(r"[a-z][a-z0-9+.\-]*://([A-Za-z0-9_.\-]{1,40}):([^\s:@/]{3,60})@", re.I)
_PW_BAD_RX = re.compile(r"""[\s&='"\[\];<>|`(){}/]""")
_URLENC_RX = re.compile(r"%[0-9A-Fa-f]{2}")
_B64_RX = re.compile(r"[A-Za-z0-9+/]+={0,2}$")


def _password_from_secret(secret: str) -> str | None:
    if not secret:
        return None
    s = secret.strip().rstrip("]")
    if _B64_RX.fullmatch(s) and len(s) % 4 == 0 and len(s) >= 8 and "=" in s[-2:] + "":
        try:
            dec = __import__("base64").b64decode(s).decode("utf-8")
            if dec.isprintable() and dec:
                s = dec.split(":", 1)[1] if ":" in dec else dec
        except Exception:
            pass
    if 3 <= len(s) <= 60 and not _PW_BAD_RX.search(s) and not _URLENC_RX.search(s):
        return s
    return None
_AUTHHDR_RX = re.compile(r"(?im)^Authorization:\s*(Basic|Bearer)\s+(\S{6,120})")
_USERPASS_RX = re.compile(r"(?i)\b(?:user(?:name)?|login)\s*[:=]\s*([A-Za-z0-9_.\-@]{2,40}).{0,40}?"
                          r"\bpass(?:word|wd)?\s*[:=]\s*(\S{3,60})")
_SELF_DESTRUCT_RX = re.compile(
    r"(?:^|[;&|]|\bsudo\s+)\s*(?:reboot|shutdown|poweroff|halt|init\s+0)\b"
    r"|\bsystemctl\s+(?:stop|poweroff|halt)\b|\bservice\s+\S+\s+stop\b", re.I | re.M)
_SERVER_5XX_RX = re.compile(
    r"\bHTTP/\d(?:\.\d)?\s+50[0-9]\b|\b50[0-9]\s+(?:bad\s+gateway|service\s+unavailable|"
    r"internal\s+server\s+error|gateway\s+time)|\bbad\s+gateway\b|\bservice\s+unavailable\b|"
    r"(?:=>|http_code[\"']?\s*[:=]?|\bstatus[\"']?\s*[:=])\s*50[0-9]\b", re.I)
_HTTP_2XX_RX = re.compile(
    r"\bHTTP/\d(?:\.\d)?\s+2\d\d\b|(?:=>|http_code[\"']?\s*[:=]?|\bstatus[\"']?\s*[:=])\s*2\d\d\b", re.I)
SERVER_DEGRADE_STREAK = 3
_RFC1918_IP = (r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
               r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
               r"|192\.168\.\d{1,3}\.\d{1,3})")
_SSRF_DST_RX = re.compile(r"://(" + _RFC1918_IP + r")\b")
_SSRF_OK_RX = re.compile(r"\bHTTP/\d(?:\.\d)?\s+\d{3}\b|<!doctype|<html|<title|\bServer:\s", re.I)
_RFC1918_ANY_RX = re.compile(_RFC1918_IP)
_CONN_FAIL_RX = re.compile(
    r"100(?:\.0)?%?\s*packet\s*loss|0\s*packets?\s+received|\b\d+\.\d+%\s+packet\s+loss"
    r"|request\s+timeout|destination\s+host\s+unreachable|\bunreachable\b"
    r"|connection\s+(?:refused|timed?\s*out)|no\s+route\s+to\s+host|\bfailed\b", re.I)


def _ssrf_url_port(cmd_text: str, host_ip: str) -> int:
    m = re.search(r"(https?)://" + re.escape(host_ip) + r"(?::(\d{1,5}))?", cmd_text, re.I)
    if m:
        if m.group(2):
            p = int(m.group(2))
            if 1 <= p <= 65535:
                return p
        return 443 if m.group(1).lower() == "https" else 80
    m2 = re.search(re.escape(host_ip) + r":(\d{1,5})\b", cmd_text)
    if m2:
        p = int(m2.group(1))
        if 1 <= p <= 65535:
            return p
    return 80
_CRED_SINGLE_RX = re.compile(
    r"sshpass\s+-p\s*['\"]?([^\s'\"]{3,40})"
    r"|\bpassword=([^\s&'\"]{3,40})"
    r"|--password[=\s]+['\"]?([^\s'\"]{3,40})"
    r"|(?:mysql|psql|redis-cli|mongo|ftp|mysqladmin)\b[^\n]{0,60}?-p\s*['\"]?([^\s'\"]{3,40})", re.I)
_CRED_BRUTE_RX = re.compile(r"\bfor\b|\bwhile\b|\.txt\b|hydra|medusa|ncrack|patator|\bwordlist\b|<<|\bxargs\b", re.I)
_CRED_FAIL_RX = re.compile(
    r"用户名或密码|密码错误|登录失败|账号或密码|login\s*(?:failed|incorrect)|authentication\s*failed|"
    r"invalid\s*(?:username|password|credential)|incorrect\s*password|bad\s*credential", re.I)
_CRED_OK_RX = re.compile(r"dashboard|welcome|欢迎|登录成功|logout|退出登录", re.I)
_ARTIFACT_BUILD_RX = re.compile(
    r"(?:^|[\n;&|]|\bsudo\s+)\s*cat\s*>{1,2}\s*([\w./-]+\.(?:py|php|sh|pl|rb|js|c|go))\s*<<"
    r"|(?:^|[\n;&|]|\bsudo\s+)\s*tee(?:\s+-a)?\s+([\w./-]+\.(?:py|php|sh|pl|rb|js|c|go))\s*<<"
    r"|(?:^|[\n;&|])\s*(?:gcc|cc|g\+\+|go\s+build)\b[^\n]*?-o\s+([\w./-]+)"
    r"|(?:^|[\n;&|])\s*\bcp\s+\S+\s+([\w./-]+\.(?:py|php|sh|pl|rb))\b", re.I | re.M)
_ARTIFACT_USAGE_RX = re.compile(r"#\s*usage[:\s]+([^\n]{4,120})", re.I)


def _salient_digest(obs_texts: list, max_lines: int = 10, max_chars: int = 800,
                    sg_titles: list | None = None) -> str:
    seen, picked = [], []
    _sg_pref = [re.sub(r"\s+", " ", (s or "").strip().lower())[:40] for s in (sg_titles or []) if s and s.strip()]

    def add(x):
        x = x.strip()
        if x and x not in seen:
            seen.append(x); picked.append(x)
    for t in obs_texts:
        for raw in str(t).splitlines():
            ln = raw.strip()
            if not ln:
                continue
            if _LEVERAGE_SG_RX.search(ln) or _PROMPT_HEAD_RX.search(ln):
                continue
            _lnl = re.sub(r"\s+", " ", ln.lower())
            if any(p and p in _lnl for p in _sg_pref):
                continue
            for m in _SECRET_RX.finditer(ln):
                add(m.group(0)[:120])
            if _SALIENT_RX.search(ln):
                add(ln if len(ln) <= 200 else ln[:200])
            if len(picked) >= max_lines:
                return " | ".join(picked)[:max_chars]
    return " | ".join(picked)[:max_chars]


_ENGINE_NONCE = os.urandom(4).hex()
_ENGINE_NOTE_PREFIX = f"[ENGINE_NOTE:{_ENGINE_NONCE}] "
_ENGINE_NOTE_LINE_RX = re.compile(
    r"^\s*(?:\d+\s*[→:|]\s*)?\[ENGINE_NOTE:" + _ENGINE_NONCE + r"\] ")


def _strip_engine_notes(text: str) -> str:
    lines = text.splitlines()
    kept = [ln for ln in lines if not _ENGINE_NOTE_LINE_RX.match(ln)]
    return "\n".join(kept) if len(kept) != len(lines) else text


def _obs_signature(txt: str) -> str:
    import hashlib
    import re as _re2
    s = _normalize_volatile(txt or "")
    s = _re2.sub(r"\s+", " ", s.strip().lower())
    return hashlib.blake2b(s.encode("utf-8", "ignore"), digest_size=8).hexdigest()


class _CallBreaker:

    RETRY = 2
    TRIP = 2
    RESET_PROBE_S = 30 * 60

    def __init__(self, primary: dict, fallback, log_tag: str = ""):
        self.primary = primary
        self._chain = list(fallback) if isinstance(fallback, (list, tuple)) else [fallback]
        self._opens = [0.0] * (1 + len(self._chain))
        self.fails = 0
        self.open = False
        self._tag = log_tag
        self._probing = set()

    def call(self, prompt, call_fn, timeout):
        import time as _time
        _now = _time.time()
        _n = len(self._chain) + 1
        for _i in range(_n):
            _opened_at = self._opens[_i]
            if _opened_at and _i < _n - 1:
                if _now - _opened_at < self.RESET_PROBE_S or _i in self._probing:
                    continue
                self._probing.add(_i)
            elif _opened_at:
                continue
            try:
                _kw = self.primary if _i == 0 else self._chain[_i - 1]()
            except Exception as _e:
                log(f"[breaker{('/' + self._tag) if self._tag else ''}] 端{_i} 构造异常(计熔断): {_e!r}")
                if _i == len(self._chain):
                    return ""
                self._opens[_i] = _time.time()
                continue
            _is_tail = (_i == _n - 1)
            for _ in range(self.RETRY):
                try:
                    _txt = call_fn(_kw, prompt, timeout)
                except Exception as _e:
                    log(f"[breaker{('/' + self._tag) if self._tag else ''}] 端{_i} 异常(计熔断): {_e!r}")
                    _txt = ""
                if _txt.strip():
                    if self._opens[_i]:
                        log(f"[breaker{('/' + self._tag) if self._tag else ''}] 端{_i} half-open 探测成功 → 回 closed"
                            f"(额度重置类故障的轮询回切)")
                        self._opens[_i] = 0.0
                        if _i == 0:
                            self.open = False
                    self._probing.discard(_i)
                    if _i == 0:
                        self.fails = 0
                    return _txt
            self._probing.discard(_i)
            if _is_tail:
                return ""
            self._opens[_i] = _time.time()
            if _i == 0:
                self.open = True
            log(f"[breaker{('/' + self._tag) if self._tag else ''}] 端{_i} 连续 {self.RETRY} 次无产出 → "
                f"open({self.RESET_PROBE_S // 60}min 后 half-open 探测),切下一端(共{_n}端,链尾兜底)")
        return ""


def _default_cc_decide(**kw):
    from engine.cc import run_claude, collect_text

    def _call(_kw, prompt, timeout):
        _tb = _kw.pop("thinking_budget", None)
        _evts = list(run_claude(prompt, tools=False, max_turns=2, timeout=timeout,
                                thinking_budget=_tb, **_kw))
        for _e in _evts:
            if isinstance(_e, dict) and (_e.get("is_error") or _e.get("type") == "error"):
                log(f"[breaker{('/' + 'decide') if _kw.get('provider') else ''}] 端侧错误事件(计熔断,不冒充产出): "
                    f"{str(_e.get('result') or _e.get('error') or '')[:120]}")
                return ""
        _txt = collect_text(_evts)
        if not _txt.strip():
            for _e in _evts:
                if isinstance(_e, dict) and (_e.get("is_error") or _e.get("type") == "error"):
                    log(f"[decide-diag] 空输出会话端侧明细: "
                        f"{str(_e.get('result') or _e.get('error') or _e)[:300]}")
                    break
            else:
                log("[decide-diag] 空输出且无 error 事件(无文本产出,疑似协议输出不合规/被杀无痕)")
        return _txt

    def _fallback():
        from engine.providers import resolve_active
        _fb = resolve_active()
        _d = {"provider": _fb["provider"], "model": _fb["model"],
              "api_key": _fb.get("key", ""), "custom_base_url": _fb.get("base_url", "")}
        if kw.get("workspace"):
            _d["workspace"] = kw["workspace"]
        return _d

    from engine.providers import glm_key_pool
    _pool = glm_key_pool() if kw.get("provider") == "glm" else []
    _extra_keys = [k for k in _pool if k and k != kw.get("api_key")]
    _chain = [lambda k=k: {**kw, "api_key": k} for k in _extra_keys] + [_fallback]
    _br = _CallBreaker(kw, _chain, log_tag="decide")

    def fn(prompt: str, timeout: int | None = None) -> str:
        return _br.call(prompt, _call, timeout or CC_MAX_TIMEOUT)
    return fn


def _default_cc_execute(**kw):
    from engine.cc import run_claude

    def fn(prompt: str, timeout: int | None = None, resume_session_id: str = "", workspace: str | None = None):
        _kw = kw
        if workspace is not None:
            _kw = dict(kw); _kw["workspace"] = workspace
        return run_claude(prompt, tools=True, timeout=timeout or CC_MAX_TIMEOUT,
                          max_turns=EXEC_MAX_TURNS, resume_session_id=resume_session_id, **_kw)
    return fn


def role_llm_params(provider: str, model: str, api_key: str, role: str) -> dict:
    from engine.providers import resolve_role as _rr, role_overridden as _ro
    _kw = {"provider": provider, "model": model, "api_key": api_key}
    if _ro(role):
        _s = _rr(role)
        _kw = {"provider": _s["provider"], "model": _s["model"], "api_key": _s["key"],
               "custom_base_url": _s["base_url"]}
    if role == "decide" and _ro(role):
        _kw["thinking_budget"] = DECIDE_THINKING_BUDGET
    if not _ro(role):
        from engine.providers import main_rotation as _mr
        _rot = _mr()
        if _rot and _kw.get("provider") == _rot.get("failed_provider"):
            _kw = {"provider": _rot["provider"], "model": _rot["model"], "api_key": _rot["api_key"],
                   "custom_base_url": _rot["base_url"]}
    return _kw


def earliest_unrechecked(tsg):
    r = tsg.q1("SELECT ukey, title FROM nodes WHERE type='insight' AND ukey LIKE 'refuted:%' "
               "AND (extra IS NULL OR extra NOT LIKE '%\"rechecked\"%') "
               "ORDER BY created_ts ASC LIMIT 1")
    return dict(r) if r else None


def mark_rechecked(tsg, title: str) -> None:
    import json as _json
    r = tsg.q1("SELECT id, extra FROM nodes WHERE type='insight' AND ukey LIKE 'refuted:%' AND title=? "
               "ORDER BY created_ts ASC LIMIT 1", (title,))
    if not r and len(title) >= 12:
        _lit = title[:60].replace("%", "\\%").replace("_", "\\_")
        r = tsg.q1("SELECT id, extra FROM nodes WHERE type='insight' AND ukey LIKE 'refuted:%' "
                   "AND title LIKE ? ESCAPE '\\' ORDER BY created_ts ASC LIMIT 1", (_lit + "%",))
    if not r:
        return
    try:
        ex = _json.loads(r["extra"] or "{}")
    except Exception:
        ex = {}
    ex["rechecked"] = 1
    try:
        with tsg._lock:
            tsg.conn.execute("UPDATE nodes SET extra=? WHERE id=?", (_json.dumps(ex), r["id"]))
            tsg.conn.commit()
    except Exception:
        pass


def note_wave_trace(tsg, subgoal_id, subgoal_title: str, *, wave: int,
                    tail_obs: list, stop_kind: str) -> None:
    import hashlib as _h
    uk = f"wtrace:{_h.md5(f'{subgoal_title}|{wave}'.encode(), usedforsecurity=False).hexdigest()[:10]}"
    tail = " | ".join((o or "").strip()[:120] for o in (tail_obs or [])[-3:])
    title = f"[wave {wave} {stop_kind}] progress so far: {tail}"[:400]
    nid = tsg.upsert_node("step", uk, title=title, state="open", provenance="wave-trace")
    try:
        tsg.add_edge(nid, subgoal_id, "serves")
    except Exception:
        pass


def _fn_takes_timeout(fn) -> bool:
    import inspect
    try:
        return "timeout" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def _fn_takes_resume(fn) -> bool:
    import inspect
    try:
        return "resume_session_id" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def _fn_takes_workspace(fn) -> bool:
    import inspect
    try:
        return "workspace" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


def _fn_takes_fork(fn) -> bool:
    import inspect
    try:
        return "fork_session" in inspect.signature(fn).parameters
    except (TypeError, ValueError):
        return False


PATIENCE = 2
CC_MAX_TIMEOUT = 900
EXEC_MAX_TURNS = 80
WAVE_FLOOR_S = 60
DECIDE_CEILING_S = 360
DECIDE_THINKING_BUDGET = 4000
MAX_RESUME_WAVES = 3

SHARED_RECON_PULL_CAP = 16


class RunOutcome(NamedTuple):
    captured: set
    status: str
    waves_used: int
    progress: dict
    local_only: frozenset = frozenset()


class EngineLoop:
    def __init__(self, tsg: TSG, target: str, task: str, *, decide_fn, execute_fn,
                 max_waves: int = 4, concurrency: int = 3, flag_regex: str | None = None,
                 patience: int = PATIENCE, deadline: float | None = None, need_flags: int = 1,
                 profile=None, shared_recon=None, label: str = "", known_wrong=None, known_correct=None,
                 on_wave=None, reserved=None, ekb=None, workspace=None, hint_fn=None,
                 hint_wanted=None, initial_hint=None, revived: bool = False, high_effort: bool = False,
                 authorized: list[str] | None = None, extra_targets: list[str] | None = None,
                 budget_stop=None):
        self.tsg = tsg
        self.target = target
        self.high_effort = bool(high_effort)
        self._parallel_waves_used = 0
        self._revived = revived
        self.hint_fn = hint_fn
        self._hint_wanted = hint_wanted
        self._hint_text: str | None = (str(initial_hint).strip() if initial_hint else None)
        self._hint_pulled = bool(self._hint_text)
        self.ekb = ekb
        self.label = label
        self.shared_recon = shared_recon
        self.task = task
        self.decide_fn = decide_fn
        self.execute_fn = execute_fn
        self.max_waves = max_waves
        self.concurrency = concurrency
        self.patience = max(1, patience)
        self.deadline = deadline
        self.need_flags = max(1, need_flags)
        from engine.profile import BenchmarkProfile
        self.profile = profile or BenchmarkProfile(need_flags=self.need_flags)
        self.captured: set[str] = set()
        self.on_wave = on_wave
        self.budget_stop = budget_stop
        self._session_new_obs = 0
        self._wave_kill_hist: list = []
        self._exec_ceiling_s: int = CC_MAX_TIMEOUT
        self._intent_lease_fired = False
        self.usage_total: dict = {"input_tokens": 0, "output_tokens": 0, "cache_read_tokens": 0,
                                  "cache_creation_tokens": 0, "llm_requests": 0,
                                  "estimated_cost_usd": 0.0, "api_latency_s": 0.0}

        self.known_wrong: set[str] = set(known_wrong or [])
        self._confirmed_foothold = bool(known_correct)
        self._flag_origin: dict[str, bool] = {}
        self._flag_host: dict[str, str] = {}
        self._flag_birth: dict[str, str] = {}
        self._declared: dict[str, dict] = {}
        self._decl_lowconf: set[str] = set()
        self.workspace = workspace
        self._cap_lock = threading.Lock()
        self._exec_ok = False
        self._obs_lock = threading.Lock()
        self._recent_obs = ""
        self._5xx_streak: dict = {}
        self._typed_norm = ""
        self._prev_wave_timeout_killed = False
        self._cur_wave_timeout_killed = False
        self._pivot_recipe: str = ""
        self._last_net_cmd: str = ""
        self._net_obs_buf: list = []
        self._last_flag_wave = 0
        self._last_flag_count = 0
        self._cur_wave = 0
        self._interrupt_cmds: list = []
        self._free_fix_wave = -1
        self._l1_unreach: dict = {}
        self._gate_rejects: dict = {}
        self._src_rejects: dict = {}
        self._exec_takes_timeout = _fn_takes_timeout(execute_fn)
        self._decide_takes_timeout = _fn_takes_timeout(decide_fn)
        self._session_id = ""
        self._resume_waves = 0
        self._exec_takes_resume = _fn_takes_resume(execute_fn)
        self._exec_takes_fork = _fn_takes_fork(execute_fn)
        self._exec_takes_workspace = _fn_takes_workspace(execute_fn)
        self.host_ukey = _host_ukey(target)
        self._tag = (f"q{hashlib.sha256(label.encode()).hexdigest()[:6]}@{self.host_ukey}"
                     if label else self.host_ukey)
        self.scope = EngagementScope(targets=[self.target] + list(extra_targets or []),
                                     reserved=reserved, authorized=authorized)
        self.host_id = tsg.upsert_node("host", self.host_ukey, title=self.host_ukey)
        self._sg_sigs: dict[str, list[str]] = {}
        self._sg_wave: dict[str, int] = {}
        self._sg_progress: dict[str, bool] = {}
        self._findings_seen: dict = {}
        self._find_lock = threading.Lock()
        self._l1_attempted: set = set()
        for r in tsg.q("SELECT ukey FROM nodes WHERE type='l1mark'"):
            self._l1_attempted.add(r["ukey"])
        self._recall_kw: list = []
        for r in tsg.q("SELECT vulnclass, summary, verified FROM findings WHERE node_id=?", (self.host_id,)):
            self._findings_seen[(r["vulnclass"], self.host_ukey, (r["summary"] or "")[:200])] = bool(r["verified"])
        for r in tsg.q("SELECT ukey FROM nodes WHERE type='flag' AND state='refuted'"):
            self.known_wrong.add(r["ukey"])
        try:
            tsg.conn.execute("UPDATE nodes SET state='closed' WHERE type='lease' AND state='open'")
        except Exception:
            pass
        if tsg.q1("SELECT 1 FROM nodes WHERE type='flag' AND state='confirmed'"):
            self._confirmed_foothold = True
        for r in tsg.q("SELECT ukey FROM nodes WHERE type='flag'"):
            self._capture(r["ukey"])
        _fh = [r["ukey"] for r in tsg.q("SELECT ukey FROM nodes WHERE type='foothold_host'")]
        _nets = [r["ukey"] for r in tsg.q("SELECT ukey FROM nodes WHERE type='scope_net'")]
        if _fh or _nets:
            self.scope.rehydrate(_fh, _nets)
        _pr = tsg.q1("SELECT title FROM nodes WHERE type='pivot_recipe' ORDER BY updated_ts DESC LIMIT 1")
        if _pr and _pr["title"]:
            self._pivot_recipe = _pr["title"]

    def _own_nets(self) -> set:
        cached = getattr(self, "_own_nets_cache", None)
        if cached is not None:
            return cached
        nets = set()
        try:
            with open("/proc/net/route") as f:
                for ln in f.read().splitlines()[1:]:
                    parts = ln.split()
                    if len(parts) < 8 or parts[1] == "00000000":
                        continue
                    ip = ".".join(str(int(parts[1][i:i + 2], 16)) for i in (6, 4, 2, 0))
                    mask = ".".join(str(int(parts[7][i:i + 2], 16)) for i in (6, 4, 2, 0))
                    m = [int(x) for x in mask.split(".")]
                    n = [int(x) & mi for x, mi in zip(ip.split("."), m)]
                    nets.add(".".join(map(str, n)) + "/" + str(sum(bin(mi).count("1") for mi in m)))
        except OSError:
            pass
        self._own_nets_cache = nets
        return nets

    def _dst_in_own_net(self, dst: str) -> bool:
        if not dst:
            return False
        import re as _re
        _dm = _re.match(r"^(\d+\.\d+\.\d+\.\d+)", dst)
        if not _dm:
            return False
        _dst_host = _dm.group(1)
        _announced = {str(t).split(":")[0].strip("/") for t in self.scope.targets if t}
        for net in self._own_nets():
            if SG.net_match(net, dst) and _dst_host not in _announced:
                return True
        return False

    def _obj_targets_legal(self, title: str) -> bool:
        hits = _PRIV_TARGET_RX_C.findall(title or "")
        if not hits:
            return True
        import ipaddress as _ipa
        _announced = {str(t).split(":")[0].strip("/") for t in self.scope.targets if t}
        for h in hits:
            hip = h.split("/")[0]
            if hip in _announced:
                continue
            try:
                a = _ipa.ip_address(hip)
            except ValueError:
                return False
            if any(a in n for n in self.scope.nets):
                continue
            return False
        return True

    def _critical_creds(self) -> list:
        try:
            rows = self.tsg.q(
                "SELECT title, verified, created_ts FROM nodes "
                "WHERE type IN ('fact','capability') ORDER BY verified DESC, created_ts DESC LIMIT 400")
            out = []
            for r in rows:
                t = (r["title"] or "")
                if "://" in t:
                    continue
                if _CRED_SHAPE_RX_C.search(t):
                    out.append(t[:160])
                if len(out) >= 12:
                    break
            return out
        except Exception:
            return []

    def _intent_lease_due(self) -> bool:
        try:
            if self._intent_lease_fired:
                return False
            if self.tsg.q1("SELECT 1 x FROM nodes WHERE type='fact' AND ukey LIKE 'intent-lease:%' LIMIT 1"):
                return False
        except Exception:
            return False
        hist = getattr(self, "_wave_kill_hist", [])
        if len(hist) < 3 or sum(1 for k in hist if k in ("soft_kill", "hard_kill")) < 2:
            return False
        _fc = self.tsg.q1("SELECT COUNT(*) c FROM nodes WHERE type='fact'")["c"]
        _cc = self.tsg.q1("SELECT COUNT(*) c FROM nodes WHERE type='capability'")["c"]
        _base = getattr(self, "_lease_base_progress", None)
        if _base is None:
            self._lease_base_progress = (_fc, _cc)
            self._lease_base_flags = self._confirmed_flag_count()
            return False
        if self._confirmed_flag_count() > self._lease_base_flags:
            self._lease_base_progress = (_fc, _cc)
            self._lease_base_flags = self._confirmed_flag_count()
            return False
        if _fc + _cc <= _base[0] + _base[1] and not self.tsg.q1(
                "SELECT COUNT(*) c FROM nodes WHERE type='subgoal' AND state IN ('open','active')")["c"]:
            return False
        return True

    def _fire_intent_lease(self) -> None:
        self._exec_ceiling_s = CC_MAX_TIMEOUT * 2
        self._intent_lease_fired = True
        try:
            self.tsg.upsert_node("fact", f"intent-lease:{self.host_ukey}",
                                 title=f"intent-lease used at wave {self._cur_wave} (2x ceiling granted once)",
                                 provenance="control")
            log(f"[loop] {self._tag} 意图续租触发:近 3 波两次墙钟切∧有进展∧旗未动 → 本波单会话 2×ceiling"
                f"({self._exec_ceiling_s}s),跳过 DECIDE 换向,端到端一次做完(每题一次)")
        except Exception:
            pass

    def _cred_remap_hint(self) -> bool:
        if getattr(self, "_recent_new_nets", None) and self._critical_creds():
            self._recent_new_nets = None
            return True
        return False

    def _cred_job_hint(self, wave: int) -> bool:
        if wave < 2:
            return False
        try:
            surf = self.tsg.q1("SELECT COUNT(*) c FROM nodes WHERE type='fact' AND ("
                               "lower(title) LIKE '%login%' OR lower(title) LIKE '%ssh%' "
                               "OR lower(title) LIKE '%auth%')" )["c"]
            cred = self.tsg.q1("SELECT COUNT(*) c FROM nodes WHERE verified=1 AND type='capability' AND ("
                               "lower(title) LIKE '%cred%' OR lower(title) LIKE '%password%' "
                               "OR lower(title) LIKE '%login%' OR lower(title) LIKE '%auth%')")["c"]
            return bool(surf) and surf > cred
        except Exception:
            return False

    def _slow_relay_hint(self) -> bool:
        import re as _re
        try:
            rows = self.tsg.q("SELECT title FROM nodes WHERE type='tried' ORDER BY created_ts DESC LIMIT 24")
        except Exception:
            return False
        _rx = _re.compile(r"(rsh\.|proxy\.php|webshell|sh\.php\?|cmd=|ssrf).{0,80}(login|passwd|password|ssh|hydra|brute|auth)", _re.I)
        return sum(1 for r in rows if _rx.search(r["title"] or "")) >= 8

    def _vision_hint(self) -> bool:
        import re as _re
        blob = (self._recent_obs or "")[-6000:]
        return bool(_re.search(r"captcha|\.bmp|\.png(?!tone)|verify[_-]?code|\.gif\b|\bimage\b", blob, _re.I)) \
            or bool(getattr(self, "_last_net_cmd", "") and _re.search(r"\.bmp|captcha|\.png", self._last_net_cmd, _re.I))

    def _rce_held(self) -> bool:
        try:
            r = self.tsg.q1("SELECT COUNT(*) c FROM nodes WHERE type='capability' AND ("
                            "lower(title) LIKE '%rce%' OR lower(title) LIKE '%shell%' "
                            "OR lower(title) LIKE '%root%' OR lower(extra) LIKE '%\"access\": \"rce\"%')")["c"]
            return bool(r)
        except Exception:
            return False

    def _promote_candidate_routes(self, nets_added: list) -> None:
        import json as _jn
        import ipaddress as _ipa
        if not nets_added:
            return
        _nets = []
        for c in nets_added:
            try:
                _nets.append(_ipa.ip_network(str(c), strict=False))
            except ValueError:
                continue
        for r in self.tsg.q("SELECT ukey, extra FROM nodes WHERE type='route' AND (verified IS NULL OR verified=0)"):
            try:
                ex = _jn.loads(r["extra"] or "{}")
            except (TypeError, ValueError):
                continue
            dst = str(ex.get("dst") or "")
            try:
                a = _ipa.ip_address(dst.split("/")[0])
            except ValueError:
                continue
            if any(a in n for n in _nets) and self._ws_referenced(str(ex.get("instrument") or "")):
                self.tsg.upsert_node("route", r["ukey"], title=r["ukey"], verified=True,
                                     provenance="promoted-after-learn", extra=ex)
                log(f"[loop] {self._tag} route 晋升 verified(段已实证): {dst}")

    def _apply_decisions(self, d: dict, wave: int) -> None:
        for title in d.get("add_subgoal", []):
            if self._is_leverage_sg(title):
                _ex = self.tsg.q1("SELECT state FROM nodes WHERE type='subgoal' AND title=?", (title,))
                if _ex and _ex["state"] in ("unproductive", "achieved"):
                    continue
            if not self._obj_targets_legal(title):
                log(f"[loop] {self._tag} 拒绝子目标(私网地址未证实:非宣布主机∧未学段): {title[:80]}")
                continue
            SG.add_subgoal(self.tsg, title, wave, expects=self._infer_model_expects(title))
        for title in d.get("achieve_subgoal", []):
            _exact = self.tsg.q1("SELECT id, extra FROM nodes WHERE type='subgoal' AND ukey=?", (title,))
            _rows = [_exact] if _exact else self.tsg.q(
                "SELECT id, extra FROM nodes WHERE type='subgoal' AND title LIKE ? ESCAPE '\\'", (_like_prefix(title),))
            for r in _rows:
                if r and SG.deliverable_met(self.tsg, SG.expects_of(r["extra"]), got_progress=True):
                    SG.achieve_subgoal(self.tsg, r["id"])
        for title in d.get("abandon_subgoal", []):
            self.tsg.upsert_node("subgoal", title, title=title, state="abandoned")
        for title in d.get("add_step", []):
            self.tsg.upsert_node("step", title, title=title, state="open")
        for title in d.get("drop_step", []):
            for r in self.tsg.q(
                    "SELECT ukey FROM nodes WHERE type='step' AND state='open' AND title LIKE ? ESCAPE '\\'",
                    (_like_prefix(title),)):
                self.tsg.upsert_node("step", r["ukey"], title=r["ukey"], state="dropped")
        for deliverable in d.get("satisfy", []):
            self.tsg.upsert_node("goal", deliverable[:80], title=deliverable,
                                 state="satisfied", provenance="assertion")
        for spec in d.get("add_route", []):
            m = re.match(r"(.+?)\s+via\s+(.+)", spec, re.I)
            if not m:
                continue
            dst, instrument = m.group(1).strip()[:80], m.group(2).strip()[:80]
            if self._dst_in_own_net(dst):
                log(f"[loop] {self._tag} 拒绝 route(指向解题容器自身网段): {dst}")
                continue
            _promotable = self._obj_targets_legal(dst)
            grounded = self._ws_referenced(instrument) and _promotable
            if self._ws_referenced(instrument) and not _promotable:
                log(f"[loop] {self._tag} route 候选保留但暂缓转正(目标段未学/未宣布,待 round-trip 证实): {dst}")
            self._add_verified_route(dst, via=self.host_ukey, instrument=instrument, verified=grounded,
                                     provenance="decide-add_route" + ("+grounded" if grounded else ""))

    _VULN_RAG_CACHE: list = []

    def _vuln_rag_entries(self) -> list:
        import os
        if self._VULN_RAG_CACHE:
            return self._VULN_RAG_CACHE
        cd = os.environ.get("HXCTF_CVE_CORPUS", "")
        if not cd:
            return []
        try:
            from engine.vulnrag import entries_from_corpus
            EngineLoop._VULN_RAG_CACHE = entries_from_corpus(cd)
            return self._VULN_RAG_CACHE
        except Exception:
            return []

    def _triadic_confirm(self, vulnclass: str, summary: str, evidence_text: str, cve: str = "") -> tuple:
        from engine.adjudicate import confirm_with_g3a, majority_vote, enrich_with_epss
        votes = [("CONFIRMED" if confirm_with_g3a(vuln_hit=True, benign_hit=False,
                                                 patched_hit=False) == "CONFIRMED" else "NOT_CONFIRMED", 0.9)]
        try:
            from engine.vulnrag import retrieve as _vr, cause_and_not_fix
            ents = self._vuln_rag_entries()
            if ents:
                top = _vr(f"{vulnclass} {summary}", ents, top_k=1)
                if top:
                    r = cause_and_not_fix(top[0], (evidence_text or "")[:800] + " " + summary)
                    if r != "NO_MATCH":
                        votes.append(("CONFIRMED" if r == "VULNERABLE" else "NOT_CONFIRMED", 0.6))
        except Exception:
            pass
        try:
            from engine.providers import role_overridden as _ro, resolve_role as _rr
            if _ro("judge"):
                j = _rr("judge")
                from engine.cc import run_claude, collect_text
                _evq = (f"Vulnerability claim review. Class: {vulnclass}.\nSummary: {summary[:300]}\n"
                        f"Evidence: {(evidence_text or '')[:500]}\n"
                        "Reply with exactly one word CONFIRMED or REJECTED (is this real exploitable evidence?).")
                evts = list(run_claude(_evq, tools=False, max_turns=1, timeout=120,
                                       provider=j["provider"], model=j["model"],
                                       api_key=j["key"], custom_base_url=j["base_url"]))
                jt = (collect_text(evts) or "").strip().upper()
                if "CONFIRM" in jt and "REJECT" not in jt:
                    votes.append(("CONFIRMED", 0.7))
                elif "REJECT" in jt:
                    votes.append(("NOT_CONFIRMED", 0.7))
                else:
                    votes.append(("ERROR", 0.0))
        except Exception as e:
            log(f"[loop] {self._tag} judge 复核 non-fatal: {e!r}")
        verdict, _conf = majority_vote(votes)
        risk_meta: dict = {}
        if cve:
            try:
                from engine import riskdata
                rm = enrich_with_epss({"cve": cve}, riskdata.load_epss(), riskdata.load_kev())
                risk_meta.update({k: rm[k] for k in ("epss", "epss_percentile", "kev") if k in rm})
            except Exception:
                pass
        risk_meta["votes"] = [list(v) for v in votes]
        return verdict, votes, risk_meta

    def _register_finding(self, vulnclass: str, *, summary: str, verified: bool,
                          evidence_text: str = "") -> None:
        import hashlib
        from engine.classify import is_exclusion_finding
        if is_exclusion_finding(summary or ""):
            self.tsg.upsert_node("insight", f"refuted:{hashlib.sha256(summary.encode()).hexdigest()[:12]}",
                                 title=f"[ruled out] {(summary or '')[:150]}",
                                 state="refuted", provenance="exclusion-gate")
            return
        full = summary or ""
        summary = full[:200]
        sig = hashlib.sha256(f"{vulnclass}\x00{self.host_ukey}\x00{full}".encode()).hexdigest()
        key = (vulnclass, self.host_ukey, sig[:16])
        with self._find_lock:
            prev = self._findings_seen.get(key)
            if prev is True:
                return
            if prev is False and not verified:
                return
            self._findings_seen[key] = verified
            ev_ref = None
            if evidence_text:
                ev_ref = self.tsg.add_evidence(self.host_id, "observation", evidence_text)
            verdict, tier, risk_meta = None, None, {}
            if verified:
                verdict, votes, risk_meta = self._triadic_confirm(vulnclass, summary, evidence_text)
                if verdict != "CONFIRMED":
                    verified = False
                    self._findings_seen[key] = False
                from engine.adjudicate import verification_tier
                tier = verification_tier(getattr(self.profile, "name", "finding-live"),
                                         confirmed=verified,
                                         kev_or_active=bool(risk_meta.get("kev")),
                                         epss=float(risk_meta.get("epss") or 0.0))
            fid = "f" + sig[:15]
            self.tsg.add_finding(vulnclass, summary=summary, verified=verified,
                                 node_id=self.host_id, evidence_ref=ev_ref,
                                 asset_ids=[self.host_id], fid=fid,
                                 verdict=verdict, tier=tier, risk_meta=risk_meta,
                                 extra={"session_id": self._session_id or "unknown",
                                        "wave": self._cur_wave})

    def _withdraw_l1mark(self, cap_ukey: str, counter: dict, tag: str, cap: int = 4) -> None:
        if counter.get(cap_ukey, 0) >= cap:
            return
        counter[cap_ukey] = counter.get(cap_ukey, 0) + 1
        try:
            with self.tsg._lock:
                self.tsg.conn.execute("DELETE FROM nodes WHERE type='l1mark' AND ukey=?", (cap_ukey,))
                self.tsg.conn.commit()
            self._l1_attempted.discard(cap_ukey)
            log(f"[loop] {self._tag} {tag} → 撤 l1mark 保留重交(第 {counter[cap_ukey]} 次,上限 {cap})")
        except Exception as _e:
            log(f"[loop] {self._tag} 撤 l1mark({tag}, non-fatal): {_e!r}")

    def _verify_finding_pick(self, fid, fukey, ftitle, ex) -> None:
        import time
        if self.deadline is not None and (self.deadline - time.time()) < WAVE_FLOOR_S:
            return
        _vexec = self.execute_fn
        if self._exec_takes_timeout:
            _vto = self._op_timeout(self.deadline, CC_MAX_TIMEOUT, floor=WAVE_FLOOR_S)
            if _vto is None:
                return
            _vexec = lambda p, _t=_vto: self.execute_fn(p, timeout=_t)
        self._l1_attempted.add(fukey)
        self.tsg.upsert_node("l1mark", fukey, title=fukey)
        from engine import verify as V
        _vc = (ex.get("vulnclass") or "").lower()
        try:
            if _vc in V.EXTRACTION_CLASSES:
                verdict, detail = V.verify_extraction(_vexec, _vc, ex.get("recipe", ftitle))
            else:
                verdict, detail = V.verify_differential(_vexec, ex.get("recipe", ftitle), vulnclass=_vc)
        except Exception as e:
            log(f"[loop] {self._tag} diff-verify error: {e!r}")
            return
        log(f"[loop] {self._tag} diff-verify {ex.get('vulnclass')} -> {verdict} "
            f"(diff_lines={len(detail.get('diff') or [])}, "
            f"extracted_lines={len([l for l in (detail.get('extracted') or '').splitlines() if len(l.strip()) >= 4])})")
        effect_verdict = None
        if verdict == "confirmed":
            if "extracted" in detail:
                ev_kind, ev_content = "extraction", detail["extracted"]
            else:
                ev_kind = "differential"
                ev_content = (f"BASELINE:\n{detail.get('baseline', '')}\n\n"
                              f"PROOF:\n{detail.get('proof', '')}")
            _substantive = [ln for ln in ev_content.splitlines() if len(ln.strip()) >= 4]
            if not _substantive:
                import json as _json
                with self.tsg._lock:
                    self.tsg.conn.execute("UPDATE findings SET extra=? WHERE id=?",
                                          (_json.dumps({"rechecked": 1, "vacuous_evidence": 1,
                                                        "session_id": self._session_id or "unknown",
                                                        "wave": self._cur_wave}), fid))
                    self.tsg.conn.commit()
                log(f"[loop] {self._tag} finding {fid} confirmed 但证据零实质行 → 保持 candidate(vacuous evidence)")
                return
            ev_id = self.tsg.add_evidence(self.host_id, ev_kind, ev_content)
            try:
                tv, _, _ = self._triadic_confirm(ex.get("vulnclass", "unknown"),
                                                 f"[{ev_kind}] {ftitle[:180]}",
                                                 ev_content[:1200])
            except Exception:
                tv = None
            if tv != "CONFIRMED":
                import json as _json
                with self.tsg._lock:
                    self.tsg.conn.execute("UPDATE findings SET extra=? WHERE id=?",
                                          (_json.dumps({"rechecked": 1, "triadic": tv,
                                                        "session_id": self._session_id or "unknown",
                                                        "wave": self._cur_wave}), fid))
                    self.tsg.conn.commit()
                log(f"[loop] {self._tag} finding {fid} diff-confirmed 但 triadic={tv} → 保持 candidate(rechecked)")
                return
            effect = detail.get("effect") or {}
            if effect and hasattr(self.profile, "verify_effect"):
                try:
                    effect_verdict = self.profile.verify_effect(effect["type"], **effect.get("kwargs", {}))
                except Exception:
                    effect_verdict = None
            import json as _json
            with self.tsg._lock:
                self.tsg.conn.execute(
                    "UPDATE findings SET verified=1, evidence_ref=?, extra=? WHERE id=?",
                    (ev_id, _json.dumps({"rechecked": 1, "effect": effect.get("type"),
                                         "effect_verdict": effect_verdict,
                                         "session_id": self._session_id or "unknown",
                                         "wave": self._cur_wave}), fid))
                self.tsg.conn.commit()
            log(f"[loop] {self._tag} finding {fid} CONFIRMED by differential"
                + (f" + E4 {effect['type']}={effect_verdict}" if effect else ""))
            return
        if verdict == "refuted":
            import json as _json
            with self.tsg._lock:
                self.tsg.conn.execute("UPDATE findings SET extra=? WHERE id=?",
                                      (_json.dumps({"rechecked": 1,
                                                    "session_id": self._session_id or "unknown",
                                                    "wave": self._cur_wave}), fid))
                self.tsg.conn.commit()
            log(f"[loop] {self._tag} finding {fid} refuted by differential(rechecked;尊重结论)")

    def _koh_hold_probe_cmds(self) -> list[str]:
        import json as _pj, re as _pr
        cmds = []
        _paths = []
        _own = self.tsg.q1("SELECT extra FROM nodes WHERE type='fact' AND ukey=?", 
                           (f"ownership:{self.host_ukey}",))
        if _own:
            try:
                _v = _pj.loads(_own["extra"] or "{}")
                _v = _pj.loads(_v) if isinstance(_v, str) else _v
                _paths.extend(a for a in _v.get("artifacts", []) if "/" in a)
            except Exception:
                pass
        for r in self.tsg.q("SELECT title, extra FROM nodes WHERE type IN ('foothold','foothold_host') "
                            "AND verified=1 AND ukey LIKE ? LIMIT 3", (f"%{self.host_ukey}%",)):
            try:
                _ex = _pj.loads(r["extra"] or "{}")
                _ex = _pj.loads(_ex) if isinstance(_ex, str) else _ex
                _payload = _ex.get("payload") or _ex.get("path") or ""
                for m in _pr.findall(r"/[\w./-]{4,120}", _payload):
                    _paths.append(m)
            except Exception:
                pass
        _paths = list(dict.fromkeys(_paths))[:3]
        if _paths:
            for pth in _paths:
                if pth.endswith(".php") or "shell" in pth.lower():
                    cmds.append(f"curl -s -o /dev/null -w '%{{http_code}}' "
                                f"http://{self.host_ukey}{pth}?ping=koh --max-time 5")
                else:
                    cmds.append(f"test -f {pth} && echo KOH-ALIVE || echo KOH-FAIL")
        if not cmds:
            cmds.append(f"curl -s -o /dev/null -w '%{{http_code}}' http://{self.host_ukey}/ --max-time 5")
        return cmds[:3]

    def _koh_hold_cycle(self) -> None:
        if not getattr(self.profile, 'is_koh', False):
            return
        try:
            from engine import koh as _K
            import time as _tm
            _now = float(_tm.time())
            _hp = f"_hold_probe:{self.host_ukey}"

            _fresh = self.tsg.q1(
                "SELECT 1 FROM nodes WHERE verified=1 AND updated_ts > ? AND (type IN "
                "('foothold','foothold_host') OR type='capability') LIMIT 1", (_now - 1800,))
            _seq_sent = self.tsg.q1("SELECT 1 FROM nodes WHERE ukey=?", (f"koh-seq:{self.host_ukey}",))
            if _fresh and not _seq_sent:
                from engine import subgoal as _SG5
                _ent = _K.post_capture_sequence()[0][1] + (" After the channel works, declare it: echo "
                        "'declare-ownership: <full-artifact-path> OWNED-CHANNEL registered'.")
                _clear = _K.clear_seed_with_ownership(self.tsg, self.host_ukey)
                _lock = _K.lock_seed_with_arbitration(self.tsg, self.host_ukey)
                for _title in (_ent, _clear, _lock):
                    _SG5.add_subgoal(self.tsg, _title, self._cur_wave or 1,
                                     expects={"kind": "capability", "host": self.host_ukey})
                self.tsg.upsert_node("fact", f"koh-seq:{self.host_ukey}",
                                     title=f"post-capture sequence dispatched @{self.host_ukey}",
                                     provenance="koh")
                log(f"[loop] {self._tag} KOH 清场序列派生(entrench→clear→lock)")

            if _fresh and self.tsg.q1("SELECT 1 FROM nodes WHERE type='fact' AND ukey LIKE ?",
                                      (f"hold_lost:{self.host_ukey}:%",)):
                with self.tsg._lock:
                    self.tsg.conn.execute("DELETE FROM nodes WHERE type='fact' AND ukey LIKE ?",
                                          (f"hold_lost:{self.host_ukey}:%",))
                    self.tsg.conn.commit()
                log(f"[loop] {self._tag} KOH 重拿成功:清本 host 失守标记")
                return

            _ever_held = self.tsg.q1(
                "SELECT 1 FROM nodes WHERE type IN ('foothold','foothold_host') "
                "AND ukey LIKE ? LIMIT 1", (f"%{self.host_ukey}%",))
            if not _ever_held:
                return
            _holding = self.tsg.q1(
                "SELECT 1 FROM nodes WHERE type IN ('foothold','foothold_host') AND verified=1 "
                "AND updated_ts > ? AND ukey LIKE ? LIMIT 1", (_now - 1800, f"%{self.host_ukey}%"))
            if _holding:
                return
            _probe_row = self.tsg.q1("SELECT extra FROM nodes WHERE type='fact' AND ukey=? LIMIT 1", (_hp,))
            _p1 = _p2 = None
            if _probe_row:
                import json as _pj
                try:
                    _pv = _pj.loads(_probe_row["extra"] or "{}")
                    if isinstance(_pv, str):
                        _pv = _pj.loads(_pv)
                    _p1, _p2 = _pv.get("probe1"), _pv.get("probe2")
                except Exception:
                    pass
            if _p1 is None:
                from engine import subgoal as _SG6
                _cmds = self._koh_hold_probe_cmds()
                if _cmds:
                    _SG6.add_subgoal(self.tsg,
                                     "KOH hold probe (verify each persistence channel still answers; "
                                     "report per-channel OK/FAIL): " + " && ".join(_cmds),
                                     self._cur_wave or 1,
                                     expects={"kind": "capability", "host": self.host_ukey})
                return
            if _K.confirm_hold_lost(probe1_fail=bool(_p1), probe2_fail=bool(_p2)):
                _reason = _K.classify_hold_loss(auth_fail=(_p1 == "auth"), payload_gone=(_p1 == "404"),
                                               exploit_dead=(_p1 == "silent"))
                _we_killed = bool(self.tsg.q1(
                    "SELECT 1 FROM nodes WHERE type='capability' AND verified=1 "
                    "AND (title LIKE '%crash%' OR extra LIKE '%crash%' OR extra LIKE '%segfault%') "
                    "AND updated_ts > strftime('%s','now')-900"))
                if _K.sla_priority(we_killed_it=_we_killed) == "repair-first":
                    from engine import subgoal as _SG9
                    _SG9.add_subgoal(self.tsg,
                                     f"SERVICE DOWN (likely our crash primitive): REPAIR the target service "
                                     f"FIRST before any further exploitation — restore it (restart/rollback/"
                                     f"gentle payload), verify it answers, THEN resume. Target uptime = "
                                     f"continuous scoring source.",
                                     self._cur_wave or 1,
                                     expects={"kind": "capability", "host": self.host_ukey})
                    log(f"[loop] {self._tag} SLA: 归因我方→repair-first 方向派发")
                import hashlib as _hl
                _u = f"hold_lost:{self.host_ukey}:" + _hl.md5(f"{self.host_ukey}:{_reason}".encode(), usedforsecurity=False).hexdigest()[:10]
                self.tsg.upsert_node("fact", _u,
                                     title=f"HOLD LOST on {self.host_ukey}: {_reason} — recover it",
                                     provenance="hold-probe")
                log(f"[loop] {self._tag} HOLD LOST({_reason},探活证据)→ recover 方向前沿重拿")
            if self.tsg.q1("SELECT 1 FROM nodes WHERE type='fact' AND ukey LIKE ?", 
                           (f"flag-rotation:{self.host_ukey}",)):
                _act = _K.tick_harvest_action(flag_rotating=True)
                if _act == "re-read-and-resubmit":
                    from engine import subgoal as _SG8
                    _SG8.add_subgoal(self.tsg,
                                     f"FLAG ROTATION detected: re-read the CURRENT flag value through your "
                                     f"holding channel and resubmit it NOW (values change every tick).",
                                     self._cur_wave or 1,
                                     expects={"kind": "flag", "need": self.need_flags})
                    log(f"[loop] {self._tag} tick-harvest: flag rotating→re-read+resubmit")
        except Exception as _ke:
            log(f"[loop] {self._tag} koh-hold non-fatal: {_ke!r}")

    def _note_opponent_activity(self, text: str, cmd_text: str | None = None) -> None:
        if not getattr(self.profile, 'is_koh', False):
            return

        import re as _re2
        from engine import koh as _KO
        _own = set(_re2.findall(r"\b(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\b", cmd_text or ""))
        _own.add(self.host_ukey)
        _det = _KO.opponent_detected(text or "", own_ips=_own, own_host=self.host_ukey)
        if not _det:
            return
        _ip = _det.get("source_ip") or "unknown"
        try:
            self.tsg.upsert_node("fact", f"opponent-activity:{_ip}",
                                 title=f"opponent activity from {_ip}: {_det['evidence'][:120]}",
                                 provenance="observed")
            self.tsg.upsert_node("fact", f"opponent-intel:{_ip}",
                                 title=f"opponent intel from {_ip}: UA/pattern extracted from {_det['evidence'][:80]}",
                                 provenance="observed")
            log(f"[loop] {self._tag} opponent-activity({_ip}): {_det['evidence'][:60]}")
        except Exception as _oe:
            log(f"[loop] {self._tag} opponent-activity non-fatal: {_oe!r}")

    def _koh_offense_cycle(self) -> None:
        if not getattr(self.profile, 'is_koh', False):
            return
        try:
            from engine import koh as _KO
            from engine import subgoal as _SG7
            _rows = self.tsg.q("SELECT ukey, title FROM nodes WHERE type='fact' "
                               "AND ukey LIKE 'opponent-activity:%' LIMIT 3")
            for _r in _rows:
                _ip = (_r["ukey"].split(":", 1)[1] if ":" in _r["ukey"] else "unknown")[:20]
                _sent = self.tsg.q1("SELECT 1 FROM nodes WHERE ukey=?", (f"counter:{_ip}",))
                if _sent:
                    continue
                _SG7.add_subgoal(self.tsg, _KO.counter_strike_seed(_ip),
                                 self._cur_wave or 1,
                                 expects={"kind": "capability", "host": self.host_ukey})
                _SG7.add_subgoal(self.tsg, _KO.opponent_intel_seed(
                                     _ip, _r["title"].split("opponent activity from ")[-1][:120] or ""),
                                 self._cur_wave or 1,
                                 expects={"kind": "capability", "host": self.host_ukey})
                _SG7.add_subgoal(self.tsg, _KO.deception_seed(),
                                 self._cur_wave or 1,
                                 expects={"kind": "capability", "host": self.host_ukey})
                self.tsg.upsert_node("fact", f"counter:{_ip}",
                                     title=f"counter-strike+intel+deception dispatched vs {_ip}",
                                     provenance="koh")
                log(f"[loop] {self._tag} counter-strike+intel+deception vs {_ip}(压制+溯源+欺骗)")
        except Exception as _ce:
            log(f"[loop] {self._tag} koh-offense non-fatal: {_ce!r}")

    def _note_flag_rotation(self, text: str) -> None:
        if not getattr(self.profile, 'is_koh', False):
            return

        import re as _re
        _flags = set(_re.findall(r"flag\{([^}]{6,80})\}", text or ""))
        if len(_flags) < 2:
            return
        try:
            self.tsg.upsert_node("fact", f"flag-rotation:{self.host_ukey}",
                                 title=f"flag values rotating on {self.host_ukey} ({len(_flags)} distinct)",
                                 provenance="observed")
        except Exception:
            pass

    def _note_ownership(self, text: str) -> None:
        if not getattr(self.profile, 'is_koh', False):
            return

        import re as _re, json as _jn
        if not _re.search(r"declare-ownership|OWNED-CHANNEL|ownership.{0,10}(?:registered|declared)", text or "", _re.I):
            return
        _paths = _re.findall(r"(/[\w./-]{4,120}|[A-Za-z]:\\[\w\\.-]{4,120})", text or "")
        if not _paths:
            return
        try:
            _u = f"ownership:{self.host_ukey}"
            _row = self.tsg.q1("SELECT extra FROM nodes WHERE type='fact' AND ukey=? LIMIT 1", (_u,))
            _ex = {}
            if _row:
                try:
                    _r2 = _jn.loads(_row["extra"] or "{}")
                    _ex = _jn.loads(_r2) if isinstance(_r2, str) else _r2
                except Exception:
                    pass
            _arts = list(dict.fromkeys(list(_ex.get("artifacts", [])) + _paths[:8]))
            _ex["artifacts"] = _arts[:32]
            self.tsg.upsert_node("fact", _u, title=f"ownership ledger @{self.host_ukey}",
                                 extra=_jn.dumps(_ex))
            log(f"[loop] {self._tag} ownership 登记 +{len(_paths[:8])}(总 {len(_arts[:32])})")
        except Exception as _oe:
            log(f"[loop] {self._tag} ownership non-fatal: {_oe!r}")

    def _note_negctl(self, text: str, cmd_text: str | None) -> None:
        import re as _re, json as _jn
        if not cmd_text:
            return
        _c = (cmd_text or "") + "\n" + (text or "")
        _sent_pair = bool(_re.search(r"(?:1=['\"]?1|true['\"]?)\b.{0,120}?(?:1=['\"]?2|false['\"]?)", _c, _re.I)
                         or _re.search(r"AND\s+1\b.{0,120}?AND\s+(?:2|0)\b", _c, _re.I))
        _no_diff = bool(_re.search(r"(?:identical|same\s+respon|both\s+(?:return|200|error)|"
                                   r"no\s+differ|响应一致|无差[异分])", _c, _re.I))
        _diff = _sent_pair and _no_diff
        _stack = bool(_re.search(r";\s*(?:SELECT|INSERT|UPDATE|COPY|COPY.{0,20}FROM)\b", _c, _re.I)
                      and _re.search(r"pg_sleep|sleep\s*\(|COPY.{0,30}FROM.{0,20}(?:PROGRAM|'/)|/tmp/", _c, _re.I))
        if not (_diff or _stack):
            return
        try:
            _u = f"_sqli_negctl:{self.host_ukey}"
            _row = self.tsg.q1("SELECT extra FROM nodes WHERE type='fact' AND ukey=? LIMIT 1", (_u,))
            _ex = {}
            if _row:
                try:
                    _ex = _jn.loads(_row["extra"] or "{}")
                except Exception:
                    pass
            _ex["differential"] = bool(_ex.get("differential") or _diff)
            _ex["stacking"] = bool(_ex.get("stacking") or _stack)
            self.tsg.upsert_node("fact", _u, title=f"sqli negative-control evidence @{self.host_ukey}",
                                 extra=_jn.dumps(_ex))
        except Exception:
            pass

    def _note_hold_probe(self, text: str) -> None:
        if not getattr(self.profile, 'is_koh', False):
            return

        if "KOH-ALIVE" not in text and "ping=koh" not in text:
            return
        import json as _jn, re as _re2
        _alive = bool(_re2.search(r"KOH-ALIVE(?!\s*(?:absent|missing|not))", text)) or \
                 bool(_re2.search(r"^\s*200\s*$", text, _re2.M)) or \
                 bool(_re2.search(r"\b200\b.{0,10}(?:OK|ok|Success)", text))
        if _alive:
            _p1 = _p2 = False
        elif "404" in text:
            _p1, _p2 = "404", "404"
        elif "401" in text or "403" in text:
            _p1, _p2 = "auth", "auth"
        elif "timeout" in text.lower() or "timed out" in text.lower():
            _p1, _p2 = "silent", "silent"
        else:
            _p1, _p2 = "silent", "silent"
        try:
            self.tsg.upsert_node("fact", f"_hold_probe:{self.host_ukey}",
                                 title=f"hold probe result @{self.host_ukey}",
                                 extra=_jn.dumps({"probe1": _p1, "probe2": _p2}))
        except Exception:
            pass

    def _maybe_verify(self) -> None:
        import json
        import time
        if self.deadline is not None and (self.deadline - time.time()) < WAVE_FLOOR_S:
            return
        try:
            cands = self.profile.verify_candidates(self.tsg, self._l1_attempted)
        except Exception as e:
            log(f"[loop] {self._tag} L1 pick error: {e!r}")
            return
        if not cands:
            return
        kind, cid, cukey, ctitle, ex = cands[0]
        if kind == "finding":
            self._verify_finding_pick(cid, cukey, ctitle, ex)
            return
        cap_id, cap_ukey, cap_title, ex = cid, cukey, ctitle, ex
        access, payload = ex.get("access"), ex.get("payload", "")
        payload = (payload or "").replace("\x00", "")
        _vexec = self.execute_fn
        if self._exec_takes_timeout:
            _vto = self._op_timeout(self.deadline, CC_MAX_TIMEOUT, floor=WAVE_FLOOR_S)
            if _vto is None:
                return
            _vexec = lambda p, _t=_vto: self.execute_fn(p, timeout=_t)
        self._l1_attempted.add(cap_ukey)
        self.tsg.upsert_node("l1mark", cap_ukey, title=cap_ukey)
        try:
            confirmed, detail = self.profile.verify(_vexec, payload, recipe=self._recent_obs)
        except Exception as e:
            log(f"[loop] {self._tag} L1 verify error: {e!r}")
            return
        with self._cap_lock:
            for f in (detail.get("flags") or ()):
                if f not in self.captured and self._capture(f):
                    self._persist_candidate_flag(f)
        log(f"[loop] {self._tag} L1 verify {access} -> "
            f"{'CONFIRMED' if confirmed else 'refuted (candidate stays inferred)'}")
        if not confirmed:
            if detail.get("unreachable"):
                self._withdraw_l1mark(cap_ukey, self._l1_unreach, f"L1 {access} 目标不可达(非原语假)", cap=2)
            _reason = str(detail.get("reason") or "")[:160]
            _not_unreach = not detail.get("unreachable")
            if (_reason and _not_unreach and detail.get("stage", "gate") == "gate"
                    and getattr(self.profile, "name", "") in ("finding-source", "finding-live")):
                self._withdraw_l1mark(cap_ukey, self._gate_rejects, "gate 拒卷")
                self.tsg.upsert_node(
                    "insight", f"gate-reject:{cap_ukey[:20]}",
                    title=(f"CVE-replay gate REJECTED the submitted checker rule: {_reason} "
                           f"— the gate replays rules against a corpus of OTHER projects' bugs; "
                           f"a rule that names this target's specific identifiers will score zero "
                           f"hits there. Resubmit with the class-generic pattern."),
                    provenance="engine-gate")
            elif (_reason and _not_unreach and detail.get("stage") == "src"
                    and getattr(self.profile, "name", "") == "finding-source"):
                self._withdraw_l1mark(cap_ukey, self._src_rejects, "src 零命中拒卷")
                self.tsg.upsert_node(
                    "insight", f"src-reject:{cap_ukey[:20]}",
                    title=(f"checker rule PASSED the CVE-replay gate but matched NOTHING on THIS target's "
                           f"source tree: {_reason} — the rule's language or constructs do not fit this "
                           f"codebase. Inspect the actual source (languages, frameworks, idioms) and "
                           f"resubmit a rule that matches THIS target's real code."),
                    provenance="engine-src")
            return
        try:
            SG.consolidate_foothold(self.tsg, self.host_id, self.host_ukey,
                                    access=access, payload=payload, verified=True,
                                    attest="l1-nonce:sha256-probe")
            self._learn_internal_from_foothold("L1/OOB verified")
            triple = {k: detail[k] for k in ("nonce", "expected", "criterion", "callback_src",
                                             "replayed_cve", "src_hit") if k in detail}
            parts = [f"L1 {detail.get('criterion', 'verified')}"]
            for k in ("nonce", "expected", "callback_src", "replayed_cve", "src_hit"):
                if detail.get(k) is not None:
                    parts.append(f"{k}={detail[k]}")
            ev = self.tsg.add_evidence(self.host_id, "pov_replay", " ".join(parts), triple=triple)
            vc = detail.get("vulnclass") or _classify_vuln(payload, access) or "rce"
            full_summ = detail.get("summary") or f"L1-verified {access}"
            summ = full_summ[:200]
            sig = hashlib.sha256(f"{vc}\x00{self.host_ukey}\x00{full_summ}".encode()).hexdigest()
            with self._find_lock:
                self._findings_seen[(vc, self.host_ukey, sig[:16])] = True
            from engine.adjudicate import verification_tier
            self.tsg.add_finding(vc, summary=summ, verified=True,
                                 node_id=self.host_id, evidence_ref=ev, asset_ids=[self.host_id],
                                 fid="f" + sig[:15],
                                 verdict="CONFIRMED",
                                 tier=verification_tier(getattr(self.profile, "name", "finding-live"),
                                                        confirmed=True),
                                 risk_meta={"basis": "L1-nonce", "votes": [["CONFIRMED", 0.95]]})
        except Exception as e:
            log(f"[loop] {self._tag} L1 upgrade-persist error: {e!r}")

        try:
            from engine import subgoal as _SG4
            for _r in self.tsg.q("SELECT title, extra FROM nodes WHERE type='capability' AND verified=1 "
                                 "AND id > COALESCE((SELECT MAX(id) FROM nodes WHERE type='l1mark'), 0)"):
                _t = (_r["title"] or "").lower() + (_r["extra"] or "").lower()
                if any(k in _t for k in ("file read", "pg_read_file", "read file", "rce", "command exec", "code exec")):
                    _SG4.add_subgoal(self.tsg, _SG4.enum_seed_title(_r["title"][:60]), self._cur_wave or 1,
                                     expects={"kind": "flag", "need": self.need_flags})
                    log(f"[loop] {self._tag} enum-seed 派生(verified 原语: {_r['title'][:40]})")
                    break
        except Exception:
            pass

    def _summarize_wave(self, prev: dict, cur: dict, wave_t0: float) -> list:
        ev = []
        try:
            _REVERIFY_PFX = "re-verify the earliest ruled-out direction: "
            for r in self.tsg.q("SELECT title FROM nodes WHERE type='subgoal' "
                                "AND state IN ('achieved','abandoned') "
                                "AND updated_ts > ? ORDER BY updated_ts DESC LIMIT 3", (wave_t0,)):
                ev.append(("subgoal_done", r["title"]))
                if r["title"].startswith(_REVERIFY_PFX):
                    mark_rechecked(self.tsg, r["title"][len(_REVERIFY_PFX):].split(" — ")[0].strip())
        except Exception:
            pass
        try:
            _vp = any(cur.get(k, 0) > prev.get(k, 0) for k in _VERIF_PROGRESS_KEYS)
            if _vp:
                self._pivot_drought = 0
            else:
                self._pivot_drought = getattr(self, "_pivot_drought", 0) + 1
                if self._pivot_drought >= PIVOT_DROUGHT_WAVES:
                    ev.append(("pivot_drought",
                               f"a deliverable direction has been pursued for {self._pivot_drought} consecutive "
                               f"waves with ZERO verified capability progress (facts/recon creep does NOT count). "
                               f"The current approach is likely a dead end — derive a SUBSTANTIALLY different "
                               f"attack path (different vulnerability class, entry point, or primitive); do not "
                               f"keep refining the same one."))
                    self._pivot_drought = 0
        except Exception:
            pass
        d_facts = max(0, cur.get("insights", 0) - prev.get("insights", 0))
        if d_facts:
            ev.append(("facts", d_facts))
        d_caps = max(0, cur.get("capabilities_verified", 0) - prev.get("capabilities_verified", 0))
        if d_caps:
            ev.append(("capability", f"{d_caps} verified capability gained"))
        return ev

    def _progress_counts(self) -> dict:
        def c(sql):
            r = self.tsg.q1(sql)
            return r["c"] if r else 0

        def cp(sql, params):
            r = self.tsg.q1(sql, params)
            return r["c"] if r else 0
        return {
            "flags_confirmed": c("SELECT COUNT(*) c FROM nodes WHERE type='flag' AND state='confirmed'"),
            "insights": c("SELECT COUNT(*) c FROM nodes WHERE type='insight' "
                          "AND ukey NOT LIKE 'shared-recon:%' "
                          "AND (provenance IS NULL OR provenance != 'plan-intent')"),
            "analysis_insights": c("SELECT COUNT(*) c FROM nodes WHERE type='insight' AND ukey NOT LIKE 'obs:%' "
                                   "AND ukey NOT LIKE '%deadend%' AND ukey NOT LIKE 'denied-%' "
                                   "AND ukey NOT LIKE 'shared-recon:%' "
                                   "AND ukey NOT LIKE 'refuted:%' "
                                   "AND (provenance IS NULL OR provenance != 'plan-intent')"),
            "capabilities": c("SELECT COUNT(*) c FROM nodes WHERE type='capability'"),
            "capabilities_verified": c("SELECT COUNT(*) c FROM nodes WHERE type='capability' AND verified=1"),
            "findings_verified": c("SELECT COUNT(*) c FROM findings WHERE verified=1"),
            "deeper_verified": (c("SELECT COUNT(*) c FROM nodes WHERE type='route' AND verified=1")
                                + cp("SELECT COUNT(*) c FROM findings WHERE verified=1 AND node_id IS NOT NULL "
                                     "AND node_id != ?", (self.host_id,))),
            "findings": c("SELECT COUNT(*) c FROM findings"),
            "assets": c("SELECT COUNT(*) c FROM nodes WHERE type IN ('service','endpoint','credential')"),
            "achieved": c("SELECT COUNT(*) c FROM nodes WHERE type='subgoal' AND state='achieved'"),
        }

    def _link_fact(self, fact_id: str, subgoal_title: str) -> None:
        r = self.tsg.q1("SELECT id FROM nodes WHERE type='subgoal' AND title=?", (subgoal_title,))
        if r and not self.tsg.q1(
                "SELECT 1 FROM edges WHERE src=? AND dst=? AND rel='observed_under'", (fact_id, r["id"])):
            self.tsg.add_edge(fact_id, r["id"], "observed_under")

    def _note_flag_origin(self, text: str, cmd_target: str | None, cmd_text: str | None = None) -> None:
        if "{" not in (text or ""):
            return
        in_scope = self.scope.source_in_scope(cmd_target)
        birth = ("P_target" if cmd_target
                 else "P_derived" if self._ws_referenced(cmd_text)
                 else "P_local_strict")
        for cand in extract_candidates(text):
            self._flag_origin.setdefault(cand, in_scope)
            self._flag_birth.setdefault(cand, birth)
            if cmd_target:
                self._flag_host.setdefault(cand, cmd_target)

    def _ws_referenced(self, cmd_text: str | None) -> bool:
        if not self.workspace or not cmd_text:
            return False
        try:
            names = os.listdir(self.workspace)
        except OSError:
            return False
        return any(n and n in cmd_text for n in names)

    def local_only_of(self, cands) -> set:
        return {c for c in cands
                if self._flag_birth.get(c) == "P_local_strict" or c in self._decl_lowconf}

    def _learn_internal_from_foothold(self, reason: str) -> None:
        try:
            _learn_src = self._recent_obs + "\n" + "\n".join(self._net_obs_buf)
            learned = self.scope.learn_foothold_net(self.host_ukey, _learn_src)
            if learned:
                self._promote_candidate_routes(learned)
                self._recent_new_nets = learned
            if learned:
                self.tsg.upsert_node("foothold_host", self.host_ukey, title=self.host_ukey,
                                     verified=True, provenance="foothold-learned")
                for _cidr in learned:
                    self.tsg.upsert_node("scope_net", _cidr, title=_cidr,
                                         verified=True, provenance="foothold-learned")
                    self._add_verified_route(_cidr, via=self.host_ukey, instrument="foothold-proxy")
                if self.shared_recon is not None and not self.scope.is_reserved_host(self.host_ukey):
                    self.shared_recon.contribute(self.host_ukey, [], [], existence=True)
                log(f"[loop] {self._tag} foothold ({reason}) → learned internal net(s) into scope: {learned}")
        except Exception as e:
            log(f"[loop] {self._tag} scope learn error (non-fatal): {e!r}")

    def _verify_creds_on_confirm(self) -> None:
        confirmed = (self._confirmed_foothold
                     or self.tsg.q1("SELECT 1 FROM nodes WHERE type IN ('foothold','foothold_host') "
                                    "AND verified=1 AND ukey=?", (self.host_ukey,))
                     or self.tsg.q1("SELECT 1 FROM nodes WHERE type='flag' AND state='confirmed'"))
        if not confirmed:
            return
        import json as _json
        for r in self.tsg.q("SELECT n.id,n.ukey,n.title,n.extra FROM nodes n JOIN edges e ON e.src=n.id "
                            "WHERE n.type='credential' AND n.verified=0 AND e.rel='authenticates_to' AND e.dst=?",
                            (self.host_id,)):
            try:
                ex = _json.loads(r["extra"]) if r["extra"] else {}
            except (TypeError, _json.JSONDecodeError):
                ex = {}
            from engine.ekb import credential_plausible as _cred_ok, _cred_user_secret as _cred_us
            _cu, _cs = _cred_us(ex)
            if _cu is not None and not _cred_ok(_cu, _cs):
                continue
            ex["verified"] = True
            self.tsg.upsert_node("credential", r["ukey"], title=r["title"], verified=True,
                                 provenance="foothold-confirmed", extra=ex)
            log(f"[loop] {self._tag} cred 验证桥:{r['title']} 随机检确认 foothold 升 verified(→EKB cred-hypothesis)")

    def _wave_invariants(self, wave: int) -> list:
        _achieved = self.profile.is_achieved(self)
        active = [(r["ukey"], SG.expects_of(r["extra"]))
                  for r in self.tsg.q("SELECT ukey, extra FROM nodes WHERE type='subgoal' AND state IN ('open','active')")]
        achieved_targets = [(r["ukey"], SG.expects_of(r["extra"]))
                            for r in self.tsg.q("SELECT ukey, extra FROM nodes WHERE type='subgoal' AND state='achieved'")]
        unexp = [] if _achieved else self.scope.unexploited_surface()
        route_unmet = [] if _achieved else self._unmet_route_faces()
        vios = INV.check(self.tsg, achieved=_achieved, unexploited=unexp,
                         active=active, achieved_targets=achieved_targets, route_unmet_faces=route_unmet)
        for v in vios:
            log(f"[inv] {self._tag} wave {wave}: {v}")
        return vios

    def _active_subgoals(self) -> list[str]:
        rows = self.tsg.conn.execute(
            "SELECT title FROM nodes WHERE type='subgoal' AND state IN ('open','active') ORDER BY created_ts").fetchall()
        return [r["title"] for r in rows]

    def _confirmed_flag_count(self) -> int:
        r = self.tsg.q1("SELECT COUNT(*) c FROM nodes WHERE type='flag' AND state='confirmed'")
        return r["c"] if r else 0

    def _unmet_route_faces(self) -> list:
        import json as _json
        out = []
        for r in self.tsg.q("SELECT extra FROM nodes WHERE type='route' AND verified=1"):
            try:
                ex = _json.loads(r["extra"] or "{}")
            except (TypeError, _json.JSONDecodeError):
                ex = {}
            dst = ex.get("dst")
            if (dst and ex.get("health", "ok") == "ok" and dst not in out
                    and not SG.deliverable_met(self.tsg, {"kind": "flag", "face": dst}, got_progress=False)):
                out.append(dst)
        return out

    def _has_unmet_pivot_route(self) -> bool:
        return bool(self._unmet_route_faces())

    def _drought_progressed(self, prev: dict, cur: dict) -> bool:
        return _face_anchored_progressed(prev, cur, self._has_unmet_pivot_route())

    @staticmethod
    def _is_leverage_sg(title: str) -> bool:
        return bool(_LEVERAGE_SG_RX.search(title or ""))

    @staticmethod
    def _infer_model_expects(title: str) -> dict | None:
        t = title or ""
        if _DELIVERABLE_INTENT_RX.search(t) or _LEVERAGE_SG_RX.search(t):
            e = {"kind": "flag"}
            import re as _re3
            m = _re3.search(r"\b(\d+|two|three|four|five|six|seven|eight|nine|ten)\s+(?:more\s+)?flags?\b"
                            r"|(两|三|四|五|六|七|八|九|十|\d+)\s*个", t, _re3.I)
            if m:
                _w2n = {"two": 2, "three": 3, "four": 4, "five": 5, "six": 6,
                        "seven": 7, "eight": 8, "nine": 9, "ten": 10,
                        "两": 2, "三": 3, "四": 4, "五": 5, "六": 6, "七": 7, "八": 8, "九": 9, "十": 10}
                raw = (m.group(1) or m.group(2) or "").strip()
                e["count"] = _w2n.get(raw.lower()) or (int(raw) if raw.isdigit() else 1)
            return e
        return None

    def _ensure_frontier(self, wave: int) -> list[str]:
        frontier = self._active_subgoals()
        if (frontier
                and self._confirmed_flag_count() < self.need_flags
                and all(self._is_leverage_sg(t) for t in frontier)
                and wave - self._last_flag_wave >= FRONTIER_STALE_WAVES):
            import json as _json
            for t in frontier:
                for _r in self.tsg.q("SELECT ukey, extra FROM nodes WHERE type='subgoal' AND title=? "
                                     "AND state IN ('open','active')", (t,)):
                    self.tsg.upsert_node("subgoal", _r["ukey"], title=t, state="unproductive",
                                         extra=_json.loads(_r["extra"] or "{}"))
            log(f"[loop] {self._tag} 前沿刷新:{len(frontier)} 个泛化 leverage 子目标 "
                f"{wave - self._last_flag_wave} 波零 flag(缺口 {self.need_flags - self._confirmed_flag_count()}) → unproductive")
            self._free_fix_wave = wave
        if not self.profile.is_achieved(self):
            self._ensure_deliverable_pivot(wave)
        frontier = self._order_frontier(self._active_subgoals())
        if frontier:
            return frontier
        _rs = self.shared_recon.summary_line(self.host_ukey, exclude_ports=self.scope.reserved_ports_on(self.host_ukey)) \
            if self.shared_recon is not None else ""
        _hl = self.tsg.q1("SELECT title FROM nodes WHERE type='fact' AND ukey LIKE 'hold_lost:%' LIMIT 1")
        if _hl:
            SG.add_subgoal(self.tsg, _hl["title"][:200], wave,
                           expects={"kind": "flag", "need": self.need_flags})
            return self._order_frontier(self._active_subgoals())
        _sd = self.tsg.q1("SELECT title FROM nodes WHERE type=? AND ukey LIKE ? "
                          "AND (extra IS NULL OR extra NOT LIKE ?) LIMIT 1",
                          ("fact", "source-distribution:%", '%"audited"%'))
        if _sd:
            _dist = (_sd["title"].split("source-distribution: ", 1) or ["", ""])[1][:80]
            SG.add_subgoal(self.tsg, SG.source_seed_title(_dist), wave,
                           expects={"kind": "flag", "need": self.need_flags})
            import json as _jj
            try:
                _frow = self.tsg.q1("SELECT id, extra FROM nodes WHERE type='fact' AND ukey LIKE 'source-distribution:%' LIMIT 1")
                if _frow:
                    _ex = _jj.loads(_frow["extra"] or "{}")
                    _ex["audited"] = 1
                    with self.tsg._lock:
                        self.tsg.conn.execute("UPDATE nodes SET extra=? WHERE id=?",
                                              (_jj.dumps(_ex), _frow["id"]))
                        self.tsg.conn.commit()
            except Exception:
                pass
            return self._order_frontier(self._active_subgoals())
        SG.add_subgoal(self.tsg, SG.recon_seed_title(_rs), wave,
                       expects={"kind": "flag", "need": self.need_flags})
        return self._order_frontier(self._active_subgoals())

    def _ensure_deliverable_pivot(self, wave: int) -> None:
        if self._confirmed_flag_count() >= self.need_flags:
            return
        faces = self._pivotable_faces()
        if not faces:
            return
        self._free_fix_wave = self._cur_wave
        for target in faces:
            self._derive_face_direction(target, wave)

    def _pivotable_faces(self) -> list[str]:
        import json
        faces = set(self.scope.unexploited_surface())
        for r in self.tsg.q("SELECT extra FROM nodes WHERE type='route' AND verified=1"):
            try:
                ex = json.loads(r["extra"] or "{}")
            except (TypeError, ValueError):
                ex = {}
            if ex.get("dst") and ex.get("health", "ok") == "ok":
                faces.add(ex["dst"])
        return sorted(faces)

    def _derive_face_direction(self, target: str, wave: int) -> None:
        route = self._route_to(target)
        if route:
            SG.add_subgoal(self.tsg, f"pivot to {target} via the established foothold and capture its flags",
                           wave, expects={"kind": "flag", "face": target})
            return
        if self._has_active_deadend(target):
            SG.add_subgoal(self.tsg, f"reach {target} via a pivot route through an already-compromised host "
                           f"(direct access failed) and capture its flags", wave, expects={"kind": "flag", "face": target})
            return
        SG.add_subgoal(self.tsg, f"break into {target}: authorized surface not yet exploited, capture its flags", wave,
                       expects={"kind": "flag", "face": target})

    def _order_frontier(self, titles: list) -> list:
        def _flag_first(t):
            r = self.tsg.q1("SELECT extra FROM nodes WHERE type='subgoal' AND title=?", (t,))
            return 0 if SG.expects_of(r["extra"] if r else None).get("kind") == "flag" else 1
        return sorted(titles, key=_flag_first)

    def _deliverable_direction_open(self, sg: str) -> bool:
        r = self.tsg.q1("SELECT extra FROM nodes WHERE type='subgoal' AND title=?", (sg,))
        e = SG.expects_of(r["extra"] if r else None)
        if e.get("kind") != "flag":
            return False
        if e.get("face"):
            return self._confirmed_flag_count() < self.need_flags
        return not SG.deliverable_met(self.tsg, e, got_progress=False)

    def _route_to(self, dst: str) -> dict | None:
        import json as _json
        for r in self.tsg.q("SELECT extra FROM nodes WHERE type='route' AND verified=1"):
            try:
                ex = _json.loads(r["extra"]) if r["extra"] else {}
            except (TypeError, _json.JSONDecodeError):
                ex = {}
            if SG.net_match(ex.get("dst"), dst) and ex.get("health", "ok") == "ok":
                return ex
        return None

    def _add_verified_route(self, dst: str, via: str, instrument: str, *,
                            verified: bool = True, provenance: str = "foothold-learned") -> None:
        self.tsg.upsert_node("route", f"{dst} via {instrument}", title=f"route to {dst} via {instrument}",
                             verified=verified, provenance=provenance,
                             extra={"dst": dst, "via": via, "instrument": instrument, "health": "ok"})
        if verified:
            self._supersede_deadend(dst)
            if not self._pivot_recipe and self._last_net_cmd:
                self._pivot_recipe = self._last_net_cmd

    def _note_ssrf_reach(self, cmd_text: str, obs_text: str) -> None:
        if not cmd_text or not obs_text:
            return
        _thost = (self.host_ukey or "")
        if _thost and _thost not in cmd_text:
            return
        if is_unreachable(obs_text) or not _SSRF_OK_RX.search(obs_text):
            return
        for dst in set(_SSRF_DST_RX.findall(cmd_text)):
            learned = self.scope.learn_reachable_dst(dst, verified=True)
            if learned:
                self._promote_candidate_routes(learned)
                self._recent_new_nets = learned
            for cidr in learned:
                self.tsg.upsert_node("scope_net", cidr, title=cidr, verified=True, provenance="ssrf-reach")
                self._add_verified_route(cidr, via=self.host_ukey, instrument="ssrf-pivot")
                log(f"[loop] {self._tag} SSRF round-trip 机检可达 {dst} → 学内网面 {cidr} + 建 route(ssrf-pivot)")
            if (self.shared_recon is not None and self.scope.is_in_scope(dst)
                    and not self.scope.is_reserved_host(dst)):
                _rp = self.scope.reserved_ports_on(dst)
                _ports = [int(pm.group(1)) for pm in re.finditer(r"://" + re.escape(dst) + r":(\d{1,5})\b", cmd_text)
                          if 1 <= int(pm.group(1)) <= 65535]
                _ports = [p for p in (_ports or [_ssrf_url_port(cmd_text, dst)]) if p not in _rp]
                if _ports:
                    self.shared_recon.contribute(dst, _ports, [])
                    self._materialize_shared_host(dst)

    def _note_cred_disproven(self, cmd_text: str, obs_text: str, target: str | None) -> None:
        if not cmd_text or not obs_text:
            return
        if _CRED_BRUTE_RX.search(cmd_text):
            return
        failed = channel_state(obs_text) == "auth_fail" or bool(_CRED_FAIL_RX.search(obs_text))
        if not failed or _CRED_OK_RX.search(obs_text):
            return
        m = _CRED_SINGLE_RX.search(cmd_text)
        cred = next((g for g in m.groups() if g), None) if m else None
        if not cred:
            return
        tgt = target or self.host_ukey or "target"
        self.tsg.upsert_node("insight", f"cred-fail:{cred}@{tgt}",
                             title=f"CRED-DISPROVEN: 口令 '{cred}' 在 {tgt} 认证失败——勿在该靶重试该口令(换口令/用户名或换面)",
                             provenance="observation")
        if self.ekb is not None:
            try:
                self.ekb.record_cred_hit(cred, str(tgt), hit=False)
            except Exception:
                pass

    def _note_stale_port(self, obs_text: str, cmd_target: str | None) -> None:
        if not obs_text or not cmd_target or self.shared_recon is None:
            return
        if channel_state(obs_text) != "refused":
            return
        if _HTTP_2XX_RX.search(obs_text):
            return
        host, _, port = str(cmd_target).partition(":")
        if host and port.isdigit() and self.shared_recon.evict_port(host, int(port)):
            log(f"[loop] {self._tag} {cmd_target} connection refused → 从共享侦察缓存驱逐陈旧开放端口")

    def _note_deadend(self, text: str) -> None:
        if not text or channel_state(text) not in ("refused", "timeout", "reset", "conn_broken"):
            return
        for cidr in set(_CIDR_RX.findall(text)):
            r = self.tsg.q1("SELECT state FROM nodes WHERE type='deadend' AND ukey=?", (cidr,))
            if r and r["state"] == "superseded":
                continue
            self.tsg.upsert_node("deadend", cidr, title=f"{cidr} not directly reachable from current vantage",
                                 state="active", provenance="observation")

    def _note_self_inflicted(self, cmd_text: str, obs_text: str) -> None:
        if not cmd_text or not obs_text:
            return
        m = _SELF_DESTRUCT_RX.search(cmd_text)
        if not m or not is_unreachable(obs_text):
            return
        act = m.group(0).strip(" ;&|\t").lower()[:24]
        self.tsg.upsert_node("insight", f"self-inflicted-deadend:{act}",
                             title=f"DEADEND(self-inflicted): 命令 '{act}' 后目标不可达——疑自毁了服务,勿重复该动作,改走其它路径",
                             provenance="observation")

    def _note_server_degraded(self, text: str, cmd_target: str | None) -> None:
        if not text or not cmd_target:
            return
        if _SERVER_5XX_RX.search(text) and not _HTTP_2XX_RX.search(text):
            with self._obs_lock:
                _streak = self._5xx_streak[cmd_target] = self._5xx_streak.get(cmd_target, 0) + 1
            if _streak >= SERVER_DEGRADE_STREAK:
                self.tsg.upsert_node(
                    "insight", f"degraded-deadend:{cmd_target}",
                    title=f"DEADEND(degraded): {cmd_target} 持续返回 5xx——服务已劣化/过载(常因高并发请求打饱和)。"
                          f"停止猛怼该服务,退避等其恢复或**降低并发/速率**;转向其它面/主机推进,勿陷'抢救服务'空转",
                    provenance="observation")
        else:
            self._5xx_streak.pop(cmd_target, None)

    def _note_artifact(self, cmd_text: str) -> None:
        if not cmd_text:
            return
        m = _ARTIFACT_BUILD_RX.search(cmd_text)
        if not m:
            return
        name = (m.group(1) or m.group(2) or m.group(3) or m.group(4) or "").split("/")[-1][:60]
        if not name:
            return
        um = _ARTIFACT_USAGE_RX.search(cmd_text)
        usage = um.group(1).strip()[:100] if um else ""
        try:
            import json as _json
            _prev = self.tsg.q1("SELECT extra FROM nodes WHERE type='artifact' AND ukey=?", (f"artifact:{name}",))
            _ex = _json.loads(_prev["extra"] or "{}") if _prev else {}
            if not _prev:
                self._artifact_new_flag = True
            if usage:
                _ex["usage"] = usage
            _ex.setdefault("wave", self._last_flag_wave)
            self.tsg.upsert_node("artifact", f"artifact:{name}", title=name, extra=_ex)
        except Exception as _e:
            log(f"[loop] {self._tag} artifact 记录 non-fatal: {_e!r}")

    def _kb_prefetch(self, ep: dict) -> list:
        try:
            from engine.vulnrag import retrieve as _vrag_retrieve
            _ctx = " ".join(str(v) for v in (ep.get("recent_facts") or [])[:5])
            if _ctx:
                _hits = _vrag_retrieve(_ctx, self._vuln_rag_entries() or [], top_k=2)
                if _hits:
                    log(f"[loop] {self._tag} Vul-RAG: {len(_hits)} 条知识匹配(增强)")
        except Exception:
            pass
        idx = _kb_index()
        if not idx:
            return []
        texts = list(ep.get("confirmed_facts") or []) + list(ep.get("recent_facts") or []) + list(ep.get("fact_index") or [])
        try:
            return KB.relevant_refs(idx, texts, limit=6)
        except Exception as _e:
            log(f"[loop] {self._tag} kb 预取 non-fatal: {_e!r}")
            return []

    def _persist_attack_surface(self, obs_raw: str) -> None:
        if not obs_raw:
            return
        try:
            for cat in KB.detect_attack_surface([obs_raw]):
                self.tsg.upsert_node("attack_surface", cat, title=cat, provenance="observation")
        except Exception as _e:
            log(f"[loop] {self._tag} 攻击面持久化 non-fatal: {_e!r}")

    def _gather_attack_surface_cats(self, texts: list) -> list:
        cats: list = [r["ukey"] for r in self.tsg.q(
            "SELECT ukey FROM nodes WHERE type='attack_surface' ORDER BY created_ts")]
        for c in KB.detect_attack_surface([t for t in texts if t]):
            if c not in cats:
                cats.append(c)
        return cats

    def _attack_surface_prefetch(self, proj: dict) -> list:
        idx = _kb_index()
        if not idx:
            return []
        texts = [self._recent_obs or ""]
        texts += [str(f) for f in (proj.get("recent_facts") or [])]
        texts += [str(s) for s in (proj.get("unexploited_surface") or [])]
        try:
            return KB.refs_for_categories(idx, self._gather_attack_surface_cats(texts), limit=6)
        except Exception as _e:
            log(f"[loop] {self._tag} 攻击面预取 non-fatal: {_e!r}")
            return []

    def _exposed_service_prefetch(self) -> list:
        idx = _kb_index()
        if not idx:
            return []
        import json as _json
        ports = set()
        for r in self.tsg.q("SELECT extra FROM nodes WHERE type='service'"):
            try:
                _p = _json.loads(r["extra"] or "{}").get("port")
                if _p:
                    ports.add(int(_p))
            except (TypeError, ValueError, _json.JSONDecodeError):
                continue
        if not ports:
            return []
        try:
            return KB.exposed_service_refs(idx, sorted(ports), limit=6)
        except Exception as _e:
            log(f"[loop] {self._tag} 暴露服务预取 non-fatal: {_e!r}")
            return []

    def _scan_ws_artifacts(self) -> None:
        import time as _tm
        if not self.workspace or not os.path.isdir(self.workspace):
            return
        try:
            last = getattr(self, "_ws_scan_t0", None)
            now = _tm.time()
            found = []
            for root, dirs, files in os.walk(self.workspace):
                dirs[:] = [d for d in dirs if not d.startswith(".")]
                for fn in files:
                    p = os.path.join(root, fn)
                    try:
                        st = os.stat(p)
                    except OSError:
                        continue
                    if st.st_size > 64 * 1024 * 1024 or fn.startswith("."):
                        continue
                    if last is None or st.st_mtime > last:
                        found.append((st.st_mtime, fn, st.st_size))
            found.sort(reverse=True)
            import json as _json
            for _mt, fn, sz in found[:80]:
                if not re.fullmatch(r"[\w.,+=\-]{1,60}", fn):
                    continue
                ukey = f"artifact:{fn}"
                if self.tsg.q1("SELECT 1 x FROM nodes WHERE type='artifact' AND ukey=?", (ukey,)):
                    continue
                self.tsg.upsert_node("artifact", ukey, title=fn,
                                     extra={"source": "ws-scan", "size": sz})
            self._ws_scan_t0 = now
        except Exception as _e:
            log(f"[loop] {self._tag} ws-scan non-fatal: {_e!r}")

    def _project_artifacts(self) -> list:
        out = []
        recent = self._recent_obs or ""
        for r in self.tsg.q("SELECT title, extra FROM nodes WHERE type='artifact' ORDER BY updated_ts DESC LIMIT 30"):
            import json as _json
            nm = r["title"] or ""
            try:
                ex = _json.loads(r["extra"] or "{}")
            except (TypeError, ValueError):
                ex = {}
            health = ""
            _stem = nm.rsplit(".", 1)[0] if "." in nm else nm
            _pos = recent.find(nm) if nm and nm in recent else (recent.find(_stem) if _stem and _stem in recent else -1)
            if _pos >= 0:
                _win = recent[max(0, _pos - 40):_pos + 200]
                if re.search(r"socks|traceback|\berror\b|refused|timed?\s*out|\\x05\\x05|exception|denied|fail", _win, re.I):
                    health = "上次运行出错(近期观察含错误签名)——复用前先核实,可能是死工具"
            out.append({"name": nm, "usage": ex.get("usage", ""), "health": health})
        return out

    def _note_denied_userlist(self, text: str) -> None:
        if not text or channel_state(text) != "denied_userlist":
            return
        self.tsg.upsert_node("insight", "denied-userlist",
                             title="DENIED-USERLIST: 用户名被服务黑名单拒绝(530 Permission denied,如 vsftpd ftpusers)——"
                                   "该用户名恒失败,勿继续爆它,换用户名或改用已知/hint 凭据",
                             provenance="observation")

    def _supersede_deadend(self, dst: str) -> None:
        if self.tsg.q1("SELECT 1 FROM nodes WHERE type='deadend' AND ukey=?", (dst,)):
            self.tsg.upsert_node("deadend", dst, title=f"{dst} reachable via route (direct-unreachable superseded)",
                                 state="superseded", provenance="route-superseded")

    def _has_active_deadend(self, dst: str) -> bool:
        r = self.tsg.q1("SELECT 1 FROM nodes WHERE type='deadend' AND ukey=? AND state='active'", (dst,))
        return r is not None

    def _write_ammo(self, ws: str | None = None) -> None:
        _ws = ws or self.workspace
        if not _ws:
            return
        try:
            from engine import ammo
            ekb_creds = []
            if self.ekb is not None:
                for c in (self.ekb.cred_hypotheses() or []):
                    pw = (c.get("extra") or {}).get("secret")
                    if pw:
                        ekb_creds.append(pw)
            _prod_src = [r["title"] for r in self.tsg.q(
                "SELECT title FROM nodes WHERE type IN ('insight','service') "
                "AND title IS NOT NULL ORDER BY created_ts DESC LIMIT 40")]
            cands = ammo.build_candidates(self._recent_obs, hint_text=self._hint_text,
                                          ekb_creds=ekb_creds, product_tokens=_prod_src)
            if not cands:
                return
            import os as _os
            _dir = _os.path.join(_ws, "candidates")
            _os.makedirs(_dir, exist_ok=True)
            with open(_os.path.join(_dir, "creds.txt"), "w", encoding="utf-8") as f:
                f.write("\n".join(cands) + "\n")
        except Exception as e:
            log(f"[loop] {self._tag} ammo 生成 non-fatal: {e!r}")

    _NOTES_SECTIONS = (
        ("当前目标", "SELECT title FROM nodes WHERE type='subgoal' AND state IN ('open','active') ORDER BY created_ts LIMIT 5", 180),
        ("已验证能力", "SELECT title FROM nodes WHERE type='capability' AND verified=1 ORDER BY created_ts LIMIT 8", 120),
        ("已知关键事实/契约(勿重推)", "SELECT title FROM nodes WHERE type IN ('insight','finding','service','endpoint') AND title IS NOT NULL AND (provenance IS NULL OR provenance != 'plan-intent') ORDER BY created_ts DESC LIMIT 14", 180),
        ("已建工具(复用,勿改名重建)", "SELECT title FROM nodes WHERE type='artifact' ORDER BY created_ts DESC LIMIT 10", 120),
        ("已试过(勿重跑同批)", "SELECT title FROM nodes WHERE type='tried' ORDER BY created_ts DESC LIMIT 12", 120),
        ("下一步(规划器据证据派生)", "SELECT title FROM nodes WHERE type='step' AND state='open' ORDER BY created_ts DESC LIMIT 6", 180),
    )

    def _write_notes(self, ws: str | None = None) -> None:
        _ws = ws or self.workspace
        if not _ws:
            return
        try:
            import os as _os
            nflag = (self.tsg.q1("SELECT COUNT(*) c FROM nodes WHERE type='flag' AND verified=1") or {"c": 0})["c"]
            parts = [f"# NOTES(引擎每波维护,wave {self._cur_wave})——持久工作记忆,新窗口先读、在此基础前进,勿重推已知/重扫已试。",
                     f"已验证 flag:{nflag}"]
            for heading, sql, width in self._NOTES_SECTIONS:
                rows = [r["title"].replace("\n", " ")[:width] for r in self.tsg.q(sql)
                        if r["title"] and not _CAND_FLAG_RX.search(r["title"])]
                if rows:
                    parts.append(f"## {heading}\n" + "\n".join(f"- {x}" for x in rows))
            _notes_text = "\n".join(_ENGINE_NOTE_PREFIX + _ln for _ln in "\n\n".join(parts).splitlines())
            try:
                with open(_os.path.join(_ws, "CLAUDE.md"), "w", encoding="utf-8") as f:
                    f.write(_notes_text + "\n")
            except OSError:
                pass
            with open(_os.path.join(_ws, "NOTES.md"), "w", encoding="utf-8") as f:
                f.write(_notes_text + "\n")
        except Exception as e:
            log(f"[loop] {self._tag} _write_notes non-fatal: {e!r}")

    def _note_convention(self, text: str) -> None:
        if not text or not _CAND_FLAG_RX.search(text):
            return
        for path in set(_FLAGPATH_RX.findall(text)):
            norm = re.sub(r"flag\d+", "flagN", path, flags=re.I)
            self.tsg.upsert_node("convention", f"flag-path:{norm}", title=f"flag file convention: {norm}",
                                 verified=True, provenance="observation")


    def _note_source_dist(self, text: str) -> None:
        m = _SRC_DIST_RX_C.search(text or "")
        m = _SRC_DIST_RX_C.search(text or "")
        if not m:
            return
        dist = m.group(0)[:160]
        try:
            self.tsg.upsert_node("fact", f"source-distribution:{self.host_ukey}",
                                 title=f"source-distribution: {dist}", provenance="observed")
            log(f"[loop] {self._tag} source-distribution: {dist[:80]}(白盒优先种子触发)")
        except Exception as _e:
            log(f"[loop] {self._tag} source-dist non-fatal: {_e!r}")


    def _note_waf_rule(self, text: str, cmd_text: str | None) -> None:
        import re as _re, json as _json
        _t = text or ""
        _structured = bool(_re.search(r'action["\s:]*["\s]*deny', _t, _re.I)
                           or _re.search(r'BLOCK\[', _t)
                           or _re.search(r'x-waf|x-block', _t, _re.I)
                           or ("403" in _t and _re.search(r'"rule"\s*:', _t)))
        if not _structured:
            return
        m = _WAF_DENY_RX_C.search(_t)
        if not m:
            return
        rule = m.group(1)
        d = _re.search(r"[ (](\d+\.\d+)(?:ms|s)?[)\s]", text or "")
        try:
            self.tsg.upsert_node("waf_rule", f"waf:{self.host_ukey}:{rule}",
                                 title=f"waf_rule {rule} @ {self.host_ukey}",
                                 extra={"matched_sample": (cmd_text or "")[:200],
                                        "delay_s": float(d.group(1)) if d else None,
                                        "status": 403})
            try:
                from engine.verify import variant_matrix as _VM
                from engine import subgoal as _SG2
                _cnt = self.tsg.q1("SELECT COUNT(*) c FROM nodes WHERE ukey LIKE ?", (f"bypass:{rule}:%",))["c"]
                if _cnt < 2:
                    _vm = _VM(cmd_text or "", vulnclass="sqli" if "sleep" in (cmd_text or "").lower()
                              or "select" in (cmd_text or "").lower() else "cmdi")
                    _SG2.add_subgoal(self.tsg, _SG2.bypass_seed_title(rule, (cmd_text or "")[:80],
                                       " | ".join(_vm[:6])), self._cur_wave or 1,
                           expects={"kind": "flag", "need": self.need_flags}) if hasattr(self, "_cur_wave") else None
                    self.tsg.upsert_node("subgoal", f"bypass:{rule}:{_cnt}",
                                         title=f"bypass dispatch #{_cnt} for {rule}", state="achieved",
                                         provenance="seed-counter")
                    log(f"[loop] {self._tag} bypass-variant 派生(rule={rule},#{_cnt+1}/2)")
            except Exception as _be:
                log(f"[loop] {self._tag} bypass-seed non-fatal: {_be!r}")
        except Exception as _e:
            log(f"[loop] {self._tag} waf_rule non-fatal: {_e!r}")

    def _note_waf_pass(self, text: str, cmd_text: str | None) -> None:
        import re as _re
        if not cmd_text:
            return
        c = cmd_text.lower()
        if not any(k in c for k in ("select", "sleep", "case", "'", "%27", "||")):
            return
        t = text or ""
        status_ok = bool(_re.search(r"HTTP/1\.[01] 2\d\d", t)
                         or _re.search(r"^\s*2\d\d\s*$", t, _re.M)
                         or _re.search(r"\b2\d\d\s+(?:OK|ok|Success)", t)
                         or _re.search(r"\[200\]|status[=:\s]{0,4}200\b", t)
                         or _re.search(r"<Response \[2\d\d\]", t)
                         or _re.search(r"http_code[=:\s]{0,4}2\d\d", t))
        if not status_ok:
            return
        tm = _re.search(r"(?:dt|time_total|elapsed|time)[=:\s]\s*(\d+(?:\.\d+)?)s?", t, _re.I) \
            or _re.search(r"(?:^|\s)(\d+(?:\.\d+)?)s(?:\s|$|elapsed)", t, _re.M) \
            or _re.search(r"[ (](\d+(?:\.\d+)?)s[)\s]", t) \
            or _re.search(r"(?:^|\s)([1-9]\d*(?:\.\d+)?)\s*$", t, _re.M)
        slow_ok = tm and float(tm.group(1)) >= 1.5
        data_ok = '"results":' in t and "[]" not in t.split('"results"')[1][:6]
        if not (slow_ok or data_ok):
            return
        import json as _j
        form = "CASE WHEN wrapper" if "case when" in c else "encoded quote"
        try:
            self.tsg.upsert_node("fact", f"waf-pass:{self.host_ukey}:{form}",
                                 title=f"waf-pass: {form} passed @ {self.host_ukey}",
                                 extra={"pass_sample": (cmd_text or "")[:200]})
            log(f"[loop] {self._tag} waf-pass {form}(通过形态入图,可复用情报)")
        except Exception as _e:
            log(f"[loop] {self._tag} waf-pass non-fatal: {_e!r}")

    def _note_refuted_technique(self, text: str, cmd_text: str | None) -> None:
        import re as _re
        if not cmd_text:
            return
        if "403" not in (text or "") and "blocked" not in (text or "").lower():
            return
        m = _WAF_DENY_RX_C.search(text or "")
        if not m:
            return
        rule = m.group(1)
        import json as _jg
        _neg = self.tsg.q1("SELECT extra FROM nodes WHERE type='fact' AND ukey=? LIMIT 1",
                           (f"_sqli_negctl:{self.host_ukey}",))
        _diff_done = _stack_done = False
        if _neg:
            try:
                _kv = _jg.loads(_neg["extra"] or "{}")
                _diff_done, _stack_done = bool(_kv.get("differential")), bool(_kv.get("stacking"))
            except Exception:
                pass
        from engine.verify import no_sqli_conclusion_gate as _gate
        _gate_ok = _gate(differential_done=_diff_done, stacking_checked=_stack_done)
        try:
            if self.ekb is not None:
                from engine.ekb import disprove_technique as _dt
                _dt(self.ekb, self.label or self.host_ukey, technique=(cmd_text or "")[:120],
                    host=self.host_ukey, rule=rule)
        except Exception:
            pass
        try:
            _uk = f"refuted-technique:{rule}:{self.host_ukey}"[:60]
            _new = self.tsg.q1("SELECT 1 x FROM nodes WHERE type='insight' AND ukey=? LIMIT 1", (_uk,)) is None
            self.tsg.upsert_node("insight", _uk,
                                 title=f"refuted-technique: blocked by {rule} @ {self.host_ukey}",
                                 provenance="observed",
                                 extra={"rule": rule, "host": self.host_ukey,
                                        "negative_control_passed": _gate_ok})
            if _new:
                log(f"[loop] {self._tag} refuted-technique(blocked by {rule} @ this instance)")
        except Exception as _e:
            log(f"[loop] {self._tag} refuted-technique non-fatal: {_e!r}")

    def _note_access_capability(self, text: str, cmd_text: str | None) -> None:
        if not cmd_text or not _PROOF_RX.search(text):
            return
        am = _ACCESS_RX.search((cmd_text or "") + " " + text)
        access = am.group(1).lower() if am else "access"
        try:
            with self._cap_lock:
                SG.consolidate_foothold(self.tsg, self.host_id, self.host_ukey,
                                        access=access, payload=cmd_text[:2000], verified=False,
                                        attest="machine-observed:proof-rx")
                vc = _classify_vuln(cmd_text + " " + text, access)
                if vc:
                    self._register_finding(vc, summary=f"{access} evidenced by command output"[:200],
                                           verified=False, evidence_text=(cmd_text or "")[:2000])
        except Exception as _e:
            log(f"[loop] {self._tag} obs-derived capability non-fatal: {_e!r}")

    def _note_crash_primitive(self, text: str, cmd_text: str | None) -> None:
        if not cmd_text:
            return
        from engine.verify import _EXPLOIT_RUN_RX, _CRASH_ANOMALY_RX
        _m_crash = _CRASH_ANOMALY_RX.search(text)
        if not (_EXPLOIT_RUN_RX.search(cmd_text) and _m_crash):
            return
        try:
            title = f"crash primitive vs {self.host_ukey} ({_m_crash.group(0)[:40]})"
            evidence = f"$ {cmd_text[:300]}\n→ {_m_crash.group(0)}"
            with self._cap_lock:
                SG.consolidate_foothold(self.tsg, self.host_id, self.host_ukey,
                                        access="crash-primitive", payload=evidence[:2000],
                                        verified=True, attest="machine-observed:crash-primitive")
                self._register_finding("rce", summary=f"crash primitive: {title}"[:200],
                                       verified=True, evidence_text=evidence[:2000])
                log(f"[loop] {self._tag} crash-primitive L1: {title[:80]}")
        except Exception as _e:
            log(f"[loop] {self._tag} crash-primitive non-fatal: {_e!r}")

    def _mangled_flag(self, flag: str) -> bool:
        m = re.search(r"\{([^}\r\n]{1,})\}", flag or "")
        if not m:
            return False
        inner = m.group(1)
        if re.search(r"random_suffix|placeholder|<[^>]+>", inner, re.I):
            return True
        if len(inner) >= 6:
            for r in self.tsg.q("SELECT title FROM nodes WHERE type='flag' AND state='confirmed'"):
                cm = re.search(r"\{([^}\r\n]{1,})\}", r["title"] or "")
                if cm and cm.group(1).startswith(inner):
                    return True
        return False

    def _capture(self, flag: str) -> bool:
        if flag in self.known_wrong:
            return False
        if self._mangled_flag(flag):
            return False
        if self._flag_origin.get(flag, True) is False:
            return False
        self.captured.add(flag)
        return True

    def _persist_candidate_flag(self, flag: str) -> None:
        row = self.tsg.q1("SELECT state FROM nodes WHERE type='flag' AND ukey=?", (flag,))
        if row and row["state"] in ("confirmed", "refuted"):
            return
        self.tsg.upsert_node("flag", flag, title=flag, verified=False,
                             state="candidate", provenance="observation")

    def _confirm_flag(self, flag: str) -> None:
        with self._cap_lock:
            self.captured.add(flag)
            self._flag_origin.setdefault(flag, True)
            self.known_wrong.discard(flag)
        self.tsg.upsert_node("flag", flag, title=flag, verified=True,
                             state="confirmed", provenance="oracle",
                             extra={"origin": self._flag_host.get(flag)})
        if not self._confirmed_foothold:
            self._confirmed_foothold = True
        self._learn_internal_from_foothold("oracle-confirmed flag")

    def _refute_flag(self, flag: str) -> None:
        row = self.tsg.q1("SELECT state FROM nodes WHERE type='flag' AND ukey=?", (flag,))
        if row and row["state"] == "confirmed":
            log(f"[loop] {self._tag} ignore late 'wrong' verdict on already-confirmed flag (monotone)")
            return
        with self._cap_lock:
            self.known_wrong.add(flag)
            self.captured.discard(flag)
        self.tsg.upsert_node("flag", flag, title=flag, verified=False,
                             state="refuted", provenance="oracle")

    def _apply_verdict(self, verdict) -> None:
        if not isinstance(verdict, dict):
            return
        conf = verdict.get("confirmed") or ()
        wrong = verdict.get("wrong") or ()
        for f in (conf if hasattr(conf, "__iter__") else ()):
            self._confirm_flag(f)
        for f in (wrong if hasattr(wrong, "__iter__") else ()):
            self._refute_flag(f)
            try:
                from engine import subgoal as _SG3
                _SG3.add_subgoal(self.tsg, _SG3.decoy_seed_title(str(f)), self._cur_wave or 1,
                                 expects={"kind": "flag", "need": self.need_flags})
                log(f"[loop] {self._tag} decoy→schema-enum seed({str(f)[:40]})")
            except Exception:
                pass

    def _op_timeout(self, deadline: float | None, ceiling: float, floor: float = 0.0) -> int | None:
        if deadline is None:
            return int(ceiling)
        import time
        remaining = deadline - time.time()
        if remaining <= 0 or remaining < floor:
            return None
        return int(min(ceiling, remaining))

    def _wave_can_start(self) -> bool:
        return self._op_timeout(self.deadline, CC_MAX_TIMEOUT, floor=WAVE_FLOOR_S) is not None

    def _call_execute(self, prompt: str, *, workspace: str | None = None,
                      resume_session_id: str | None = None, fork_session: bool = False):
        kw: dict = {}
        if self._exec_takes_timeout:
            kw["timeout"] = self._op_timeout(self.deadline, getattr(self, "_exec_ceiling_s", CC_MAX_TIMEOUT))
        if self._exec_takes_resume:
            kw["resume_session_id"] = self._session_id if resume_session_id is None else resume_session_id
        if workspace is not None and self._exec_takes_workspace:
            kw["workspace"] = workspace
        if fork_session and self._exec_takes_fork:
            kw["fork_session"] = True
        return self.execute_fn(prompt, **kw)

    def _target_portscheme(self) -> tuple[int, str]:
        t = str(self.target or "")
        scheme = "https" if t.lower().startswith("https") else "http"
        m = re.search(r"://[^/]*?:(\d{1,5})", t)
        port = int(m.group(1)) if m else (443 if scheme == "https" else 80)
        return port, scheme

    def _ingest_assets(self, obs_joined: str) -> int:
        if not obs_joined:
            return 0
        host = self.host_ukey
        tport, tscheme = self._target_portscheme()
        made = 0
        svc_by_port: dict[int, str] = {}
        _resv = self.scope.reserved_ports_on(host)

        def _svc(port: int, name: str = "") -> str | None:
            nonlocal made
            if port in _resv:
                return None
            sid = svc_by_port.get(port)
            if sid is None:
                ukey = f"{host}:{port}"
                sid = self.tsg.upsert_node("service", ukey, title=(f"{ukey} {name}".strip())[:120],
                                           provenance="observation", verified=False,
                                           extra={"port": port, "name": name[:40]} if name else {"port": port})
                self.tsg.add_edge(self.host_id, sid, "exposes")
                svc_by_port[port] = sid
                made += 1
            return sid

        fps: list[str] = []
        n = 0
        for m in _SVC_NMAP_RX.finditer(obs_joined):
            if n >= 20:
                break
            port = int(m.group(1))
            if 1 <= port <= 65535:
                _svc(port, m.group(2)[:40]); n += 1
        for fm in _SVC_HDR_RX.finditer(obs_joined):
            fp = fm.group(1).strip()[:80]
            fps.append(fp)
            _svc(tport, fp)
            if len(fps) >= 8:
                break

        eps: list[tuple[int, str]] = []
        for m in _URL_RX.finditer(obs_joined):
            if m.group(2).lower() != host.lower():
                continue
            port = int(m.group(3)) if m.group(3) else (443 if m.group(1).lower() == "https" else 80)
            path = (m.group(4) or "/").split("#")[0].split("?")[0][:120] or "/"
            eps.append((port, path))
        for rx in (_REQLINE_RX, _LOCATION_RX):
            for m in rx.finditer(obs_joined):
                path = m.group(1).split("#")[0].split("?")[0][:120] or "/"
                eps.append((tport, path))
        seen_ep: set = set(); n = 0
        for port, path in eps:
            if n >= 40:
                break
            npath = _normalize_volatile(path)
            if (port, npath) in seen_ep:
                continue
            seen_ep.add((port, npath))
            sid = _svc(port, tscheme if port in (80, 443, tport) else "")
            if not sid:
                continue
            eid = self.tsg.upsert_node("endpoint", f"{host}:{port}{npath}", title=path[:120],
                                       provenance="observation", verified=False)
            self.tsg.add_edge(sid, eid, "contains")
            made += 1; n += 1

        creds: list[tuple[str, str]] = []
        for m in _URLCRED_RX.finditer(obs_joined):
            creds.append((m.group(1), m.group(2)))
        for m in _AUTHHDR_RX.finditer(obs_joined):
            creds.append((m.group(1).lower(), m.group(2)))
        for m in _USERPASS_RX.finditer(obs_joined):
            creds.append((m.group(1), m.group(2)))
        n = 0
        for user, secret in creds:
            if n >= 20:
                break
            pw = _password_from_secret(secret)
            if pw is None:
                continue
            sh = hashlib.sha256(pw.encode("utf-8", "replace")).hexdigest()[:8]
            cid = self.tsg.upsert_node("credential", f"{host}:{user}:{sh}", title=f"{user}:***",
                                       provenance="observation", verified=False,
                                       extra={"user": user, "secret": pw[:120]})
            self.tsg.add_edge(cid, self.host_id, "authenticates_to")
            made += 1; n += 1

        if self.shared_recon is not None:
            try:
                _pb = _svcbanners_by_hostport_from_scan(obs_joined, host)
                def _contrib(_h: str) -> None:
                    _rp = self.scope.reserved_ports_on(_h)
                    _ports = [p for p in _ports_by_host_from_scan(obs_joined, host).get(_h, []) if p not in _rp]
                    _bn = [b for p, b in _pb.get(_h, {}).items() if p not in _rp]
                    if _h == host:
                        _ports = [p for p in svc_by_port.keys() if p not in _rp]
                        _bn = (list(fps) + _bn) if not _rp else _bn
                    if _ports or _bn:
                        self.shared_recon.contribute(_h, _ports, _bn)
                        _l = self.shared_recon.summary_line(_h, exclude_ports=_rp)
                        if _l:
                            self.tsg.upsert_node("insight", f"shared-recon:{_h}", title=_l[:400], provenance="inferred")
                _contrib(host)
                for _h in _ports_by_host_from_scan(obs_joined, host):
                    if _h == host or not self.scope.is_in_scope(_h) or self.scope.is_reserved_host(_h):
                        continue
                    _contrib(_h)
                    self._materialize_shared_host(_h)
                self._contribute_internal_from_obs(obs_joined)
            except Exception as e:
                log(f"[loop] {self._tag} shared-recon(contribute) error (non-fatal): {e!r}")
        return made

    def _materialize_shared_host(self, ih: str) -> None:
        if self.shared_recon is None or not ih:
            return
        if self.scope.is_reserved_host(ih) and ih != self.host_ukey:
            return
        _rp = self.scope.reserved_ports_on(ih)
        k = self.shared_recon.known(ih, exclude_ports=_rp)
        _line = self.shared_recon.summary_line(ih, exclude_ports=_rp)
        if not k["ports"] and not k["fps"] and not _line:
            return
        if _line:
            self.tsg.upsert_node("insight", f"shared-recon:{ih}", title=_line[:400], provenance="inferred")
        hid = self.tsg.upsert_node("host", ih, title=ih, provenance="inferred", verified=False)
        for _p in k["ports"]:
            sid = self.tsg.upsert_node("service", f"{ih}:{_p}", title=f"{ih}:{_p}",
                                       provenance="inferred", verified=False, extra={"port": _p})
            self.tsg.add_edge(hid, sid, "exposes")

    def _contribute_internal_from_obs(self, obs: str) -> None:
        if self.shared_recon is None or not obs:
            return
        try:
            seen: set = set()
            for m in _RFC1918_ANY_RX.finditer(obs):
                ip = m.group(0)
                if ip in seen:
                    continue
                seen.add(ip)
                if (ip == self.host_ukey or not self.scope.is_in_scope(ip)
                        or self.scope.is_reserved_host(ip)):
                    continue
                _nearby = obs[max(0, m.start() - 90):m.end() + 90]
                if _CONN_FAIL_RX.search(_nearby):
                    continue
                _rp = self.scope.reserved_ports_on(ip)
                _ports = []
                for pm in re.finditer(re.escape(ip) + r":(\d{1,5})\b", obs):
                    _p = int(pm.group(1))
                    if 1 <= _p <= 65535 and _p not in _rp:
                        _ports.append(_p)
                self.shared_recon.contribute(ip, _ports, [], existence=True)
                self._materialize_shared_host(ip)
        except Exception as e:
            log(f"[loop] {self._tag} internal-existence contribute error (non-fatal): {e!r}")

    def _pull_shared_recon(self) -> None:
        if self.shared_recon is None:
            return
        try:
            _cands = []
            _seen: set = set()
            for _net in list(self.scope.nets):
                for _ih in self.shared_recon.hosts_in(str(_net)):
                    if _ih in _seen:
                        continue
                    _seen.add(_ih)
                    _k = self.shared_recon.known(_ih, exclude_ports=self.scope.reserved_ports_on(_ih))
                    _cands.append((len(_k.get("ports") or []) + len(_k.get("fps") or []), _ih))
            _cands.sort(key=lambda t: (-t[0], t[1]))
            for _score, _ih in _cands[:SHARED_RECON_PULL_CAP]:
                self._materialize_shared_host(_ih)
        except Exception as e:
            log(f"[loop] {self._tag} shared-recon(pull) error (non-fatal): {e!r}")

    @staticmethod
    def _classify_exec_stop(meta: dict) -> str:
        err = meta.get("err")
        turns = meta.get("turns")
        detail = meta.get("detail")
        reason = meta.get("reason")
        if err and detail:
            return "real_error"
        if err and turns is not None:
            return "soft_kill"
        if turns is None and reason is None:
            return "hard_kill"
        return "ok"

    _RESUMABLE_STOPS = frozenset({"ok", "soft_kill", "stall_cut"})

    def _execute_one(self, subgoal_title: str) -> None:
        try:
            self._execute_body(subgoal_title)
        except Exception as e:
            log(f"[loop] execute error on subgoal {subgoal_title[:40]!r}: {e!r}")
            self._sg_progress[subgoal_title] = False
            self._sg_sigs.setdefault(subgoal_title, []).append(f"ERROR:{e!r}"[:80])

    def _lease_grant(self, sg: str, wave: int, worker: int) -> bool:
        ukey = f"lease:{hashlib.md5(sg.encode(), usedforsecurity=False).hexdigest()[:12]}"
        viol = bool(self.tsg.q1("SELECT 1 FROM nodes WHERE type='lease' AND ukey=? AND state='open'", (ukey,)))
        if viol:
            log(f"[loop] {self._tag} [LEASE-VIOLATION] sg={sg[:40]!r} 已有未释放租约又授予(检查分发串行性)")
        self.tsg.upsert_node("lease", ukey, title=f"wave={wave} worker={worker}",
                             state="open", provenance="lease")
        return viol

    def _lease_release(self, sg: str) -> None:
        ukey = f"lease:{hashlib.md5(sg.encode(), usedforsecurity=False).hexdigest()[:12]}"
        self.tsg.upsert_node("lease", ukey, title="released", state="closed", provenance="lease")

    def _preserve_winner_session(self, winner_ws: str | None) -> None:
        import os as _os
        import shutil as _sh
        if not (winner_ws and self.workspace):
            return
        src = _os.path.join(winner_ws, ".claude", "projects")
        if not _os.path.isdir(src):
            return
        dst_dir = _os.path.join(self.workspace, ".claude", "projects",
                                _os.path.realpath(self.workspace).replace("/", "-"))
        _os.makedirs(dst_dir, exist_ok=True)
        for root, _dirs, files in _os.walk(src):
            for f in files:
                if f.endswith(".jsonl"):
                    try:
                        _sh.move(_os.path.join(root, f), _os.path.join(dst_dir, f))
                    except OSError:
                        pass

    def _ingest_stale(self, bundle: dict, cur_wave: int) -> bool:
        bw = bundle.get("wave")
        return bw is not None and int(bw) < int(cur_wave)

    def _execute_batch(self, batch: list, wave: int, collaborative: bool = False) -> None:
        batch = list(dict.fromkeys(batch))
        if not collaborative or self.concurrency <= 1 or not self._exec_takes_workspace or len(batch) <= 1:
            for sg in batch:
                self._execute_one(sg)
            return
        import os
        import shutil
        ws_map = {sg: (os.path.join(self.workspace, f".worker_w{wave}_{i}") if self.workspace else None)
                  for i, sg in enumerate(batch)}
        for _w in ws_map.values():
            if _w:
                try:
                    os.makedirs(_w, exist_ok=True)
                except OSError:
                    pass

        from engine.intent_lease import WorkClaimTable
        _claims = WorkClaimTable(ttl_s=1800.0)

        def _work(sg):
            _wid = f"w-{batch.index(sg)}"
            _dup = not _claims.claim(sg, _wid)
            try:
                if _dup:
                    log(f"[loop] {self._tag} 协作波方向撞车(语义同向已领取,仍执行观测): sg={sg[:40]!r}")
                _sibs = [x for x in batch if x != sg]
                _vi = self._lease_grant(sg, wave, batch.index(sg))
                _b = self._run_session(sg, isolate=True, workspace=ws_map.get(sg), siblings=_sibs)
                _b["wave"] = wave
                return (sg, _b, None)
            except Exception as e:
                return (sg, None, e)
            finally:
                _claims.release(sg, _wid)
        log(f"[loop] {self._tag} 协作并行 wave {wave + 1}: N={len(batch)} 子目标={[s[:24] for s in batch]}")
        ex = ThreadPoolExecutor(max_workers=len(batch))
        try:
            futs = {ex.submit(_work, sg): sg for sg in batch}
            done, _not_done = _cf_wait(set(futs), timeout=COLLAB_WORKER_HANG_CAP_S)
            results = []
            for fut, sg in futs.items():
                if fut in done:
                    try:
                        results.append(fut.result())
                    except Exception as e:
                        results.append((sg, None, e))
                else:
                    log(f"[loop] {self._tag} 协作 worker 超波墙钟挂死未返回(放弃,不阻塞整波): sg={sg[:40]!r}")
                    results.append((sg, None, TimeoutError("collab worker hang-cap exceeded")))
        finally:
            ex.shutdown(wait=False, cancel_futures=True)
        for sg, bundle, err in results:
            if err is not None or bundle is None:
                log(f"[loop] 协作 worker error sg={sg[:40]!r}: {err!r}")
                self._sg_progress[sg] = False
                self._sg_sigs.setdefault(sg, []).append(f"ERROR:{err!r}"[:80])
                continue
            try:
                if self._ingest_stale(bundle, wave):
                    log(f"[loop] 协作 worker stale bundle sg={sg[:40]!r} (wave 落后,标 stale)")
                    bundle = {**bundle, "stale": True}
                self._ingest_session(sg, bundle)
            except Exception as e:
                log(f"[loop] 协作 worker ingest error sg={sg[:40]!r}: {e!r}")
                self._sg_progress[sg] = False
        _ranked = sorted(((sg, b) for sg, b, _e in results if b is not None),
                         key=lambda t: len(t[1].get("obs_texts") or ()), reverse=True)
        _pick = next(((sg, b) for sg, b in _ranked
                      if b.get("sid_local")
                      and (self._classify_exec_stop(b.get("result_meta") or {}) in self._RESUMABLE_STOPS)),
                     None)
        if _pick is not None:
            self._session_id = _pick[1]["sid_local"]
            self._preserve_winner_session(ws_map.get(_pick[0]))
        else:
            self._session_id = ""
        self._resume_waves = 0
        for sg in batch:
            self._lease_release(sg)
        for _w in ws_map.values():
            if _w:
                try:
                    shutil.rmtree(_w, ignore_errors=True)
                except OSError:
                    pass

    def _should_parallel_hypotheses(self, stall: int, frontier: list) -> bool:
        return (self.high_effort
                and stall >= PARALLEL_STALL_WAVES
                and len(frontier) >= 2
                and self._parallel_waves_used < PARALLEL_WAVES_CAP
                and self._exec_takes_workspace)

    def _run_session(self, subgoal_title: str, *, isolate: bool = False, workspace: str | None = None,
                     intent_lease: bool = False,
                     siblings: list | None = None) -> dict:
        import hashlib
        caps = SG.unconsumed_capabilities(self.tsg)
        scope_list = self.scope.boundary()
        _sid_local = ""
        _tn_local = self._typed_norm
        _tn_delta = ""
        self._write_ammo(workspace)
        self._write_notes(workspace)
        _ep = self.tsg.read_locked(F.execute_projection)
        prior = _ep["recent_facts"]
        _steps = [r["title"] for r in self.tsg.q(
            "SELECT title FROM nodes WHERE type='step' AND state='open' "
            "GROUP BY title ORDER BY MAX(created_ts) DESC LIMIT 8")]
        _tried = [r["title"][7:] for r in self.tsg.q(
            "SELECT title FROM nodes WHERE type='tried' ORDER BY created_ts DESC LIMIT 24")]
        _ro_rows = self.tsg.q(
            "SELECT title, extra FROM nodes WHERE type='insight' AND ukey LIKE 'refuted:%' ORDER BY created_ts DESC")
        _ro_total = len(_ro_rows)
        _ruled_out = []
        import json as _json
        for _r in _ro_rows[:12]:
            try:
                _e = _json.loads(_r["extra"]) if _r["extra"] else {}
            except Exception:
                _e = {}
            _ruled_out.append((_r["title"], _e.get("scope") or ""))
        _ei = None
        if self.ekb is not None:
            try:
                _ei = self.ekb.project(exclude_challenge=self.label or None,
                                       for_challenge=self.label or None)
                _flat = [n for lst in _ei.values() for n in lst]
                if _flat and self.label:
                    self.ekb.record_inject(self.label, [n.get("ukey", "") for n in _flat])
            except Exception as _ee:
                log(f"[loop] {self._tag} EKB 注入 non-fatal: {_ee!r}")
                _ei = None
        prompt = render_execute(subgoal_title, self.target, self.task,
                                capabilities=caps, scope=scope_list, insights=prior,
                                fact_index=_ep["fact_index"], confirmed_facts=_ep["confirmed_facts"],
                                plans=_ep["plans"], reserved=self.scope.reserved_list(),
                                steps=_steps, captured_count=self._confirmed_flag_count(), need_count=self.need_flags,
                                tried=_tried, engagement_intel=_ei, platform_hint=self._hint_text,
                                refocus=(self._prev_wave_timeout_killed
                                         and self._session_new_obs < DEEP_MODE_MIN_OBS),
                                refocus_cmds=(self._interrupt_cmds if self._prev_wave_timeout_killed else None),
                                loot_continue=(getattr(self, '_loot_pending', None) if self._prev_wave_timeout_killed else None),
                                rejected=sorted(self.known_wrong)[:20],
                                pivot_recipe=self._pivot_recipe,
                                artifacts=self._project_artifacts(),
                                revived=self._revived,
                                has_foothold=self._confirmed_foothold,
                                kb_hits=(self._exposed_service_prefetch() + self._kb_prefetch(_ep)),
                                ruled_out=_ruled_out,
                                collab_siblings=siblings,
                                critical_creds=self._critical_creds(),
                                rce_held=self._rce_held(),
                                vision_hint=self._vision_hint(),
                                slow_relay_hint=self._slow_relay_hint(),
                                cred_remap_hint=self._cred_remap_hint(),
                                intent_lease=intent_lease,
                                cred_job_hint=self._cred_job_hint(self._cur_wave))
        import time as _t
        _exec_t0 = _t.time()
        _tool_calls = 0
        _reasoning_chars = 0
        _result_meta: dict = {}
        if isolate:
            events = self._call_execute(prompt, workspace=workspace,
                                        resume_session_id=self._session_id,
                                        fork_session=bool(self._session_id))
        else:
            events = self._call_execute(prompt)

        j = Judge()
        obs_texts, all_text = [], []
        say_texts: list = []
        echoed: set[str] = set()
        last_cmd_target: str | None = None
        last_cmd_targets: list[str] = []
        last_cmd_text: str | None = None
        _tried_this_wave: list = []
        _stall_unprod = 0
        _ledger_stall = 0
        _wave_obs_sigs: set = set()
        _stall_cut = False
        _wave_flag_decls = 0
        _last_flag_tc = -10 ** 9
        _pivot_phase = bool(self.tsg.q("SELECT 1 FROM nodes WHERE type='route' AND verified=1 LIMIT 1"))
        _eff_ledger = _effective_ledger(
            wave=self._cur_wave, pivot=_pivot_phase,
            profile_name=getattr(self.profile, "name", ""),
            has_submit=bool(self._confirmed_flag_count() > 0 or self._sg_wave),
            has_new_obs=bool(self._recent_obs))
        _stall_kind = ""
        _gclose = getattr(events, "close", None)
        try:
            for ev in events:
                if isinstance(ev, dict) and ev.get("session_id"):
                    if isolate:
                        _sid_local = ev["session_id"]
                    else:
                        self._session_id = ev["session_id"]
                if isinstance(ev, dict) and ev.get("type") == "result":
                    _result_meta = {"turns": ev.get("num_turns"), "reason": ev.get("subtype") or ev.get("stop_reason"),
                                    "err": ev.get("is_error"),
                                    "detail": ev.get("result") or ev.get("error")}
                    _u = ev.get("usage") or {}
                    _ut = self.usage_total
                    _ut["input_tokens"] += int(_u.get("input_tokens") or 0)
                    _ut["output_tokens"] += int(_u.get("output_tokens") or 0)
                    _ut["cache_read_tokens"] += int(_u.get("cache_read_input_tokens") or 0)
                    _ut["cache_creation_tokens"] += int(_u.get("cache_creation_input_tokens") or 0)
                    _ut["llm_requests"] += 1
                    _ut["estimated_cost_usd"] += float(ev.get("total_cost_usd") or 0.0)
                    _ut["api_latency_s"] += float(ev.get("duration_api_ms") or 0) / 1000.0
                if isinstance(ev, dict) and ev.get("type") == "assistant":
                    for _blk in (ev.get("message", {}).get("content") or []):
                        if isinstance(_blk, dict) and _blk.get("type") == "thinking":
                            _reasoning_chars += len(_blk.get("thinking", "") or "")
                tu = tool_use_text(ev)
                if tu:
                    _tool_calls += 1
                    _stall_unprod += 1
                    _ledger_stall += 1
                    self._exec_ok = True
                    _tried_this_wave.append(tu)
                    self._note_artifact(tu)
                    _ntu = _normalize_typed(tu)
                    _tn_local = (_tn_local + " " + _ntu)[-200000:]
                    _tn_delta = (_tn_delta + " " + _ntu)[-200000:]
                    if not isolate:
                        self._typed_norm = _tn_local
                    last_cmd_text = tu
                    if _PIVOT_DEPLOY_RX.search(tu):
                        self._pivot_recipe = tu.strip()[:400]
                    t = _cmd_target(tu)
                    if t is not None:
                        last_cmd_target = t
                        last_cmd_targets = _cmd_targets(tu)
                        self._last_net_cmd = tu.strip()[:400]
                txt, ch = text_of_event(ev)
                if ch == "observation" and txt:
                    txt = _strip_engine_notes(txt)
                    if not txt.strip():
                        txt = "[engine notes replay]"
                if not txt:
                    continue
                all_text.append(txt)
                if ch != "observation":
                    say_texts.append(txt)
                    if _PROGRESS_DECL_RX.search(txt):
                        _ledger_stall = 0
                    if getattr(self, "_artifact_new_flag", False):
                        _ledger_stall = 0
                        self._artifact_new_flag = False
                    if _FLAG_DECL_RX.search(txt):
                        _wave_flag_decls += 1
                        _last_flag_tc = _tool_calls
                if ch == "observation":
                    self._exec_ok = True
                    obs_texts.append(txt)
                    _osig = _obs_signature(txt)
                    if _osig not in _wave_obs_sigs:
                        _wave_obs_sigs.add(_osig)
                        _stall_unprod = 0
                        self._session_new_obs += 1
                        _bad = re.search(r"\b(50[0234]|bad gateway|service unavailable|gateway timeout|connection refused)\b", txt, re.I)
                        _th = self.host_ukey.split(":")[0]
                        _tfirst = bool(last_cmd_targets and last_cmd_targets[0].split(":")[0] == _th)
                        _ttouch = any(t.split(":")[0] == _th for t in last_cmd_targets)
                        _tall = bool(last_cmd_targets) and all(t.split(":")[0] == _th for t in last_cmd_targets)
                        if _bad and _ttouch:
                            self._wave_bad_seen = True
                        if _bad and _tfirst:
                            self._target_bad_streak = getattr(self, "_target_bad_streak", 0) + 1
                        else:
                            self._wave_new_facts = True
                            if (not _bad) and _tall:
                                self._target_bad_streak = 0
                    if "{" in txt:
                        echoed |= _typed_echo(extract_candidates(txt), _tn_local)
                    with self._obs_lock:
                        self._recent_obs = (self._recent_obs + "\n" + txt)[-8000:]
                        if re.search(r"\binet\b|\b\d{1,3}(?:\.\d{1,3}){3}/\d{1,2}\b", txt):
                            self._net_obs_buf = (self._net_obs_buf + [txt[:400]])[-40:]
                    if self._confirmed_foothold:
                        self._learn_internal_from_foothold("oracle-confirmed flag")
                    self._note_flag_origin(txt, last_cmd_target, last_cmd_text)
                    self._note_ssrf_reach(last_cmd_text, txt)
                    self._note_deadend(txt)
                    self._note_self_inflicted(last_cmd_text, txt)
                    self._note_server_degraded(txt, last_cmd_target)
                    self._note_cred_disproven(last_cmd_text, txt, last_cmd_target)
                    self._note_stale_port(txt, last_cmd_target)
                    self._note_denied_userlist(txt)
                    self._note_convention(txt)
                    self._note_access_capability(txt, last_cmd_text)
                    self._note_source_dist(txt)
                    self._note_hold_probe(txt)
                    self._note_negctl(txt, last_cmd_text)
                    if getattr(self.profile, 'is_koh', False):
                        self._note_ownership(txt)
                        self._note_opponent_activity(txt, last_cmd_text)
                        self._note_flag_rotation(txt)
                    self._note_waf_rule(txt, last_cmd_text)
                    self._note_waf_pass(txt, last_cmd_text)
                    self._note_refuted_technique(txt, last_cmd_text)
                    self._note_crash_primitive(txt, last_cmd_text)
                    if _PROOF_RX.search(txt):
                        _ledger_stall = 0
                j.observe(txt, ch)
                if last_cmd_target and self._5xx_streak.get(last_cmd_target, 0) >= SERVER_DEGRADE_STREAK:
                    _stall_cut = True
                    _stall_kind = "degraded"
                    break
                if _stall_unprod >= STALL_CUT_CALLS:
                    _stall_cut = True
                    _stall_kind = "obs"
                    break
                if getattr(self, "_artifact_new_flag", False):
                    _ledger_stall = 0
                    self._artifact_new_flag = False
                if _ledger_stall >= _eff_ledger:
                    _stall_cut = True
                    _stall_kind = "ledger"
                    break
                _deep_mode = self._session_new_obs >= DEEP_MODE_MIN_OBS
                if _deep_mode:
                    self._session_new_obs = 0
                elif _wave_flag_decls >= 1 and (_tool_calls - _last_flag_tc) >= FLAG_GRACE_CALLS:
                    _stall_cut = True
                    _stall_kind = "deliverable"
                    break
        finally:
            if callable(_gclose):
                _gclose()
        joined = "\n".join(all_text)
        obs_joined = "\n".join(obs_texts)
        return {
            "joined": joined, "obs_joined": obs_joined, "all_text": all_text, "obs_texts": obs_texts,
            "say_texts": say_texts, "j": j, "tried_this_wave": _tried_this_wave, "result_meta": _result_meta,
            "tool_calls": _tool_calls, "reasoning_chars": _reasoning_chars, "stall_cut": _stall_cut,
            "stall_kind": _stall_kind, "echoed": echoed, "last_cmd_target": last_cmd_target,
            "stall_unprod": _stall_unprod, "ledger_stall": _ledger_stall,
            "last_cmd_text": last_cmd_text, "wave_flag_decls": _wave_flag_decls, "last_flag_tc": _last_flag_tc,
            "exec_t0": _exec_t0,
            "prompt_chars": len(prompt),
            "isolate": isolate, "sid_local": _sid_local, "tn_local": _tn_local, "tn_delta": _tn_delta,
        }

    def _ingest_session(self, subgoal_title: str, _b: dict) -> None:
        import hashlib
        import time as _t
        joined = _b["joined"]; obs_joined = _b["obs_joined"]; all_text = _b["all_text"]; obs_texts = _b["obs_texts"]
        say_texts = _b["say_texts"]; j = _b["j"]; _tried_this_wave = _b["tried_this_wave"]
        _result_meta = _b["result_meta"]; _tool_calls = _b["tool_calls"]; _reasoning_chars = _b["reasoning_chars"]
        _stall_cut = _b["stall_cut"]; _stall_kind = _b["stall_kind"]; echoed = _b["echoed"]
        _stall_unprod = _b.get("stall_unprod", 0); _ledger_stall = _b.get("ledger_stall", 0)
        last_cmd_target = _b["last_cmd_target"]; last_cmd_text = _b["last_cmd_text"]
        _wave_flag_decls = _b["wave_flag_decls"]; _last_flag_tc = _b["last_flag_tc"]; _exec_t0 = _b["exec_t0"]
        if _b.get("isolate"):
            if _b.get("sid_local"):
                self._session_id = _b["sid_local"]
            _tn_delta = _b.get("tn_delta") or ""
            if _tn_delta:
                self._typed_norm = (self._typed_norm + " " + _tn_delta)[-200000:]
        log(f"[loop] {self._tag} exec-depth sg={subgoal_title[:36]!r} tool_calls={_tool_calls} "
            f"turns={_result_meta.get('turns')} stop={_result_meta.get('reason')} err={_result_meta.get('err')} "
            f"obs={len(obs_texts)} reasoning_chars={_reasoning_chars} pfx={_b.get('prompt_chars', 0)} "
            f"+{int(_t.time() - _exec_t0)}s")
        if _result_meta.get('reason') == 'error_during_execution':
            try:
                from engine.providers import note_main_result as _nmr
                _nmr(False)
            except Exception:
                pass
        _killstate = "stall_cut" if _stall_cut else self._classify_exec_stop(_result_meta)
        if _killstate == "stall_cut":
            if _stall_kind == "deliverable":
                log(f"[loop] {self._tag} exec-killstate: stall_cut/deliverable (submit_flag 声明后 {_tool_calls - _last_flag_tc} 次调用无新 flag "
                    f"→ 达成即切:拿到 deliverable 不再漫游找诱饵/爆破,换手;本波 flag 声明={_wave_flag_decls} tool_calls={_tool_calls})")
            elif _stall_kind == "ledger":
                log(f"[loop] {self._tag} exec-killstate: stall_cut/ledger (连续 {_ledger_stall} 次工具调用零持久进展信号[submit_*/访问证据] "
                    f"→ 忙而无功,主动早停换手,省空转墙钟;tool_calls={_tool_calls})")
            elif _stall_kind == "degraded":
                log(f"[loop] {self._tag} exec-killstate: stall_cut/degraded (target {last_cmd_target} 连续 {SERVER_DEGRADE_STREAK}+ 次 5xx 服务劣化"
                    f" → 停怼换手/给服务喘息窗口,不继续砸已过载服务(切自己波,不节流对方=守红线);tool_calls={_tool_calls})")
            else:
                log(f"[loop] {self._tag} exec-killstate: stall_cut/obs (连续 {_stall_unprod} 次工具调用零新观察产出 → 主动早停换向,"
                    f"省空转墙钟;tool_calls={_tool_calls})")
        elif _killstate == "real_error":
            log(f"[loop] {self._tag} exec-error-detail: {str(_result_meta['detail'])[:400]}")
        elif _killstate == "soft_kill":
            log(f"[loop] {self._tag} exec-killstate: soft_kill (SIGINT 软杀打断:墙钟提前收,CLI 已 flush result;非端侧报错,观察/资产已入图)")
        elif _killstate == "hard_kill":
            log(f"[loop] {self._tag} exec-killstate: hard_kill (SIGKILL 硬切:剩余墙钟不足软杀,result 丢失)")
        self._last_killstate = _killstate
        if _killstate in ("soft_kill", "hard_kill", "stall_cut"):
            self._cur_wave_timeout_killed = True
            if _tool_calls >= REFOCUS_CONTINUE_CALLS:
                self._interrupt_cmds = [subgoal_title[:80]] + [c[:120] for c in _tried_this_wave[-3:]]
            self._loot_pending = None
            if _killstate in ("soft_kill", "hard_kill") and obs_texts:
                _tail_obs = obs_texts[-1][:400]
                if re.search(r"uid=0|uid=\d+\(admin\)|root@|flag\{|password|credential|passwd|-r[-w]x", _tail_obs, re.I):
                    self._loot_pending = _tail_obs
                    log(f"[loop] {self._tag} 波尾 loot 信号在场被切 → 下一波强续读(携带观察原文)")
            try:
                _ex = self.tsg.q1("SELECT id FROM nodes WHERE type='subgoal' AND title=? "
                                  "AND state IN ('open','active') ORDER BY created_ts DESC LIMIT 1", (subgoal_title,))
                _sgn = _ex["id"] if _ex else self.tsg.upsert_node("subgoal", subgoal_title, title=subgoal_title, state="active")
                note_wave_trace(self.tsg, _sgn, subgoal_title, wave=self._cur_wave,
                                tail_obs=_tried_this_wave[-3:], stop_kind=_killstate)
            except Exception:
                pass
        if _killstate not in self._RESUMABLE_STOPS:
            self._session_id = ""
            self._resume_waves = 0
        access_claimed = bool(_PROOF_RX.search(obs_joined))

        declared_tokens: set[str] = set()
        for _d in parse_flag_declarations("\n".join(say_texts)):
            _src, _xf = _d.get("source", ""), _d.get("transform", "")
            for _tok in extract_candidates(_d["value"]):
                declared_tokens.add(_tok)
                self._declared.setdefault(_tok, {"source": _src, "transform": _xf})
                _observed = self._flag_birth.get(_tok) in ("P_target", "P_derived")
                if self._flag_birth.get(_tok) in (None, "P_local_strict"):
                    self._flag_birth[_tok] = "P_declared"
                if not _observed and roundtrip_verify(_tok, _src, _xf, enabled=True) is not True:
                    self._decl_lowconf.add(_tok)
        with self._cap_lock:
            _submit_set = list(j.submittable())
            for f in declared_tokens:
                if f not in _submit_set:
                    _submit_set.append(f)
            for f in _submit_set:
                if f in echoed and f not in declared_tokens:
                    continue
                if f not in self.captured and self._capture(f):
                    self._persist_candidate_flag(f)

        got_cap = False
        for m in _CAP_RX.finditer(joined):
            label = _clean_harvest(m.group(1).strip()[:80])
            payload = _clean_harvest(m.group(2).strip()[:4000])
            if not payload or _ECHO_MARK_RX.search(m.group(2) or ""):
                continue
            got_cap = True
            iface = _parse_capability(payload)
            am = _ACCESS_RX.search((label or "") + " " + iface["payload"])
            access = am.group(1).lower() if am else "access"
            SG.consolidate_foothold(self.tsg, self.host_id, self.host_ukey,
                                    access=access, payload=iface["payload"], verified=False,
                                    entry=iface.get("entry"), grammar=iface.get("grammar"),
                                    failures=iface.get("failures"))
            vc = _classify_vuln((label or "") + " " + payload + (" " + obs_joined if access_claimed else ""), access)
            if vc:
                self._register_finding(vc, summary=(label or "inferred access")[:200], verified=False)

        try:
            from engine.logic_oracle import scan_observation_metamorphic
            for _mv in scan_observation_metamorphic(joined)[:3]:
                _mk = f"metamorphic:{_mv['user']}→{_mv['owner']}"
                if not self.tsg.q1("SELECT id FROM nodes WHERE type='insight' AND ukey=?", (_mk,)):
                    self.tsg.upsert_node("insight", _mk,
                                         title=f"cross-boundary: {_mv['user']} creds succeeded on "
                                               f"{_mv['owner']}'s resource (status {_mv['status']}) — "
                                               f"candidate privilege boundary violation",
                                         provenance="observation")
        except Exception:
            pass
        facts_found = False
        for m in _FACT_RX.finditer(joined):
            raw_fact = _clean_harvest(m.group(1).strip())
            if not raw_fact:
                continue
            facts_found = True
            fact = raw_fact[:1500]
            for sm in _SECRET_RX.finditer(raw_fact[1500:]):
                tok = sm.group(0)[:120]
                if tok not in fact:
                    fact = (fact + " " + tok)[:2000]
            _conf = self._confirmed_flag_count()
            if _conf < self.need_flags:
                if _PROMOTE_LEAD_RX.search(fact) and not self._is_leverage_sg(fact):
                    SG.add_subgoal(self.tsg, f"pursue unfinished lead "
                                   f"({self.need_flags - _conf} flag(s) still missing): {fact[:130]}",
                                   self._cur_wave)
                if _NEGATIVE_EXHAUST_RX.search(fact):
                    SG.add_subgoal(self.tsg, "vector exhausted (no flag) — switch to a DIFFERENT attack surface / "
                                   f"vector on the in-scope target, stop hitting the dead path: {fact[:100]}",
                                   self._cur_wave)
                if _SELF_COMPLETE_RX.search(fact):
                    fact = "[DISPUTED — flags still missing, machine gap≠0] " + fact
            fid = self.tsg.upsert_node("insight", fact, title=fact, provenance="observation")
            self._link_fact(fid, subgoal_title)
            vc = _classify_vuln(fact)
            if vc:
                self._register_finding(vc, summary=fact[:200], verified=False)

        for m in _RULEDOUT_RX.finditer(joined):
            ro = _clean_harvest(m.group(1).strip())
            if not ro or ro.startswith("<"):
                continue
            ro = ro[:600]
            import re as _re23
            _reason = (ro.split("| reason:", 1)[1] if "| reason:" in ro else ro).lower()
            _net_ev = any(w in _reason for w in ("rst", "reset", "refused", "timeout", "timed out", "unreachable", "no route"))
            _ex = {"attestation": {"level": "claimed", "by": "executor-declared"}}
            if _net_ev:
                _ex["scope"] = "direct-only"
            rid = self.tsg.upsert_node("insight", "refuted:" + ro, title=ro,
                                       provenance="conjecture", extra=_ex)
            self._link_fact(rid, subgoal_title)

        for m in _PLAN_RX.finditer(joined):
            plan = _clean_harvest(m.group(1).strip())
            if not plan:
                continue
            plan = plan[:1500]
            if plan and not plan.startswith("<"):
                pid = self.tsg.upsert_node("insight", "plan:" + plan, title=plan, provenance="plan-intent")
                self._link_fact(pid, subgoal_title)

        assets_made = self._ingest_assets(obs_joined)
        if assets_made:
            log(f"[loop] {self._tag} ingested {assets_made} asset node(s) (service/endpoint/credential)")
        self._persist_attack_surface(obs_joined)

        self._pull_shared_recon()

        if not facts_found and obs_texts:
            _sgts = [r["title"] for r in self.tsg.q(
                "SELECT title FROM nodes WHERE type='subgoal' AND state='active' ORDER BY updated_ts DESC LIMIT 12")]
            digest = _salient_digest(obs_texts, sg_titles=_sgts)
            if digest:
                dk = _normalize_volatile(digest)
                ukey = "obs:" + hashlib.sha256(dk.encode("utf-8", "replace")).hexdigest()[:12]
                iid = self.tsg.upsert_node("insight", ukey, title="observed: " + digest,
                                           provenance="observation")
                self._link_fact(iid, subgoal_title)

        for _c in _tried_this_wave:
            _cn = _normalize_volatile((_c or "").strip())[:180]
            if not _cn:
                continue
            _uk = "tried:" + hashlib.sha256(_cn.encode("utf-8", "replace")).hexdigest()[:12]
            self.tsg.upsert_node("tried", _uk, title="tried: " + (_c or "").strip()[:180], provenance="tried-cmd")

        got = bool(j.submittable()) or got_cap
        self._sg_progress[subgoal_title] = got
        sig = hashlib.sha256("\n".join(obs_texts).encode("utf-8", "replace")).hexdigest()[:16]
        self._sg_sigs.setdefault(subgoal_title, []).append(sig)
        recon_progress = got or facts_found or bool(assets_made)
        _row = self.tsg.q1("SELECT id, extra FROM nodes WHERE type='subgoal' AND title=?", (subgoal_title,))
        if _row and SG.deliverable_met(self.tsg, SG.expects_of(_row["extra"]), got_progress=recon_progress):
            SG.achieve_subgoal(self.tsg, _row["id"])

    def _execute_body(self, subgoal_title: str) -> None:
        self._ingest_session(subgoal_title, self._run_session(subgoal_title))

    def _ensure_attempt_lesson(self, status: str) -> None:
        rows = self.tsg.q("SELECT COUNT(*) AS c FROM nodes WHERE type='tried' AND ukey NOT LIKE 'lesson:%'")
        n_tried = (rows[0]["c"] if rows else 0) or 0
        have = self._confirmed_flag_count()
        self.tsg.upsert_node(
            "tried", "lesson:attempt-exhausted",
            title=(f"lesson: a prior attempt ended '{status}' without breaking through "
                   f"(have {have}/{self.need_flags} flag; ~{n_tried} probe batch(es) already tried) — "
                   f"the next attempt must change vector: a different surface/parameter/technique, "
                   f"not a repeat of the tried directions"),
            provenance="engine-lesson")

    def run(self) -> RunOutcome:
        import time
        t0 = time.time()
        prev = self._progress_counts()
        self._scan_ws_artifacts()
        stall = 0
        verif_stall = 0
        wave = 0
        status = "exhausted_waves"
        if self.profile.is_achieved(self):
            return RunOutcome(self.captured, "solved", 0, prev)
        self._wave_triggers = []
        while wave < self.max_waves:
            _wave_t0 = time.time()
            if not self._wave_can_start():
                status = "exhausted_time"
                break
            self._cur_wave = wave
            _wave_t0 = time.time()
            proj = self.tsg.read_locked(F.folded_projection)
            proj["_wave"] = wave
            proj["engagement_scope"] = self.scope.boundary()
            if self._hint_text:
                proj["platform_hint"] = self._hint_text
            proj["flag_progress"] = {"have": self._confirmed_flag_count(), "need": self.need_flags}
            if not self.profile.is_achieved(self):
                _unexp = self.scope.unexploited_surface()
                if _unexp:
                    proj["unexploited_surface"] = _unexp
            if self._recall_kw:
                got = []
                for kw in self._recall_kw[:5]:
                    got += self.tsg.read_locked(F.drill_down, kw, limit=5)
                proj["recalled_facts"] = list(dict.fromkeys(got))[:12]
            proj["triggers"] = getattr(self, "_wave_triggers", [])
            _sd_row = self.tsg.q1("SELECT title FROM nodes WHERE type='fact' AND ukey LIKE 'source-distribution:%' LIMIT 1")
            if _sd_row:
                proj["source_distribution"] = _sd_row["title"].split("source-distribution: ", 1)[-1][:120]
            _waf_rows = self.tsg.q("SELECT title, extra FROM nodes WHERE type='waf_rule' ORDER BY id DESC LIMIT 5")
            _pass_row = self.tsg.q1("SELECT title FROM nodes WHERE type='fact' AND title LIKE 'waf-pass:%' LIMIT 1")
            if _waf_rows:
                import json as _pj
                def _waf_extra(row):
                    v = _pj.loads(row["extra"] or "{}")
                    return _pj.loads(v) if isinstance(v, str) else v
                proj["waf_rules"] = [
                    {"rule": (r["title"].split(" ", 2)[1] if " " in r["title"] else r["title"][:20]),
                     "blocked": (r["extra"] or "")[:60],
                     "delay_ms": ((_waf_extra(r).get("delay_s") or 0) * 1000),
                     "pass_form": (_pass_row["title"].split(": ")[1].split(" ")[0] if _pass_row else "")}
                    for r in _waf_rows]
            _ast = self._attack_surface_prefetch(proj)
            _ast = (self._exposed_service_prefetch() + _ast)
            if _ast:
                proj["attack_surface_techniques"] = _ast
            _dprompt = render_decide(proj, self.task)
            if self._intent_lease_due():
                self._fire_intent_lease()
                log(f"[loop] {self._tag} wave {wave}: 意图续租波 → 跳过 DECIDE(沿用前沿,单会话端到端)")
                decisions = {}
                frontier = list(dict.fromkeys(self._ensure_frontier(wave)))
                if not frontier:
                    frontier = [self.task[:60]]
                _sg_lease = frontier[0]
                try:
                    self._ingest_session(_sg_lease, self._run_session(_sg_lease, intent_lease=True))
                except Exception as _ie:
                    log(f"[loop] {self._tag} intent-lease session non-fatal: {_ie!r}")
                self._prev_wave_timeout_killed = self._cur_wave_timeout_killed
                self._cur_wave_timeout_killed = False
                self._wave_kill_hist = (self._wave_kill_hist + [getattr(self, "_last_killstate", "")])[-3:]
                self._exec_ceiling_s = CC_MAX_TIMEOUT
                wave += 1
                try:
                    self.profile.adjudicate(self, set(self.captured))
                except Exception:
                    pass
                continue
            _dto = self._op_timeout(self.deadline, DECIDE_CEILING_S, floor=DECIDE_CEILING_S)
            _draw = (self.decide_fn(_dprompt, timeout=_dto)
                     if self._decide_takes_timeout and _dto is not None else
                     (self.decide_fn(_dprompt) if _dto is not None else ""))
            if _dto is None:
                log(f"[loop] {self._tag} lease 剩余不足 {DECIDE_CEILING_S}s → 本波跳过 DECIDE(防 timeout 压缩致熔断误伤),沿用上波方向")
            else:
                try:
                    from engine.providers import note_role_result as _nrr
                    _nrr("decide", bool((_draw or "").strip()))
                except Exception:
                    pass
            decisions = parse_decisions(_draw)
            self._apply_decisions(decisions, wave)
            self._recall_kw = decisions.get("recall", [])[:5]

            self._wave_new_facts = False
            self._wave_bad_seen = False
            frontier = list(dict.fromkeys(self._ensure_frontier(wave)))
            _collab = self._should_parallel_hypotheses(stall, frontier)
            _eff = self.concurrency if _collab else 1
            batch = frontier[:_eff]
            for sg in batch:
                self._sg_wave.setdefault(sg, wave)
            if _collab:
                self._parallel_waves_used += 1

            log(f"[loop] {self._tag} wave {wave + 1}/{self.max_waves} +{int(time.time() - t0)}s "
                f"subgoals={len(frontier)} facts={prev['insights']} caps={prev['capabilities']} "
                f"findings={prev['findings']} flags={len(self.captured)} stall={stall}{' [COLLAB]' if _collab else ''}")

            self._execute_batch(batch, wave, collaborative=_collab)
            self._scan_ws_artifacts()
            if self._pivot_recipe:
                self.tsg.upsert_node("pivot_recipe", self.host_ukey, title=self._pivot_recipe[:400], provenance="pivot-recipe")
            if not _collab:
                self._resume_waves += 1
                if self._resume_waves >= MAX_RESUME_WAVES:
                    self._session_id = ""
                    self._resume_waves = 0
            _target_dead = getattr(self, "_target_bad_streak", 0) >= 2
            if _target_dead or (getattr(self, "_wave_bad_seen", False) and not self._wave_new_facts):
                self._infra_dead_waves = getattr(self, "_infra_dead_waves", 0) + 1
            else:
                self._infra_dead_waves = 0
            if not getattr(self, "_wave_bad_seen", False):
                self._target_bad_streak = 0
            if getattr(self, "_infra_dead_waves", 0) >= 2:
                status = "infra-dead"
                log(f"[loop] {self._tag} 连续 {self._infra_dead_waves} 波全 5xx/拒连且零新事实 → infra-dead 早停(换实例重开,不磨死靶)")
                break
            self._prev_wave_timeout_killed = self._cur_wave_timeout_killed
            self._cur_wave_timeout_killed = False
            self._wave_kill_hist = (self._wave_kill_hist + [getattr(self, "_last_killstate", "")])[-3:]
            self._exec_ceiling_s = CC_MAX_TIMEOUT
            _confirmed = self.tsg.q1("SELECT COUNT(*) c FROM nodes WHERE type='flag' AND verified=1")["c"]
            if _confirmed > self._last_flag_count:
                self._last_flag_count = _confirmed
                self._last_flag_wave = wave
            self._wave_invariants(wave)
            wave += 1

            self._maybe_verify()
            if getattr(self.profile, 'is_koh', False):
                self._koh_hold_cycle()
                self._koh_offense_cycle()
            try:
                self.profile.adjudicate(self, set(self.captured))
            except Exception as _e:
                log(f"[loop] {self._tag} adjudicate callback error (non-fatal): {_e!r}")

            if self.budget_stop is not None and self.budget_stop.is_set():
                status = "budget_exhausted"
                log(f"[loop] {self._tag} budget exhausted(错交预算死∧0 correct)→ 终止本地址剩余波(不空烧)")
                break

            self._verify_creds_on_confirm()

            if self.ekb is not None:
                try:
                    from engine.ekb import curate_from_tsg as _cft
                    _n = _cft(self.ekb, self.tsg, self.label)
                    if _n:
                        log(f"[loop] {self._tag} EKB 策展 +{_n} 条 verified 情报提升进交战库(运行中增量)")
                except Exception as _ce:
                    log(f"[loop] {self._tag} EKB 波增量策展 non-fatal: {_ce!r}")
                except Exception:
                    pass
            if self.profile.is_achieved(self):
                status = "solved"
                break

            cur = self._progress_counts()
            progressed = any(cur[k] > prev.get(k, 0) for k in cur)
            verif_progressed = any(cur[k] > prev.get(k, 0) for k in _VERIF_PROGRESS_KEYS)
            _rep_new_flags = max(0, cur["flags_confirmed"] - prev.get("flags_confirmed", 0))
            _rep_have = cur["flags_confirmed"]
            _rep_progress = self._drought_progressed(prev, cur)
            _py = 1.0 if _rep_new_flags > 0 else min(
                1.0,
                0.5 * max(0, cur.get("capabilities_verified", 0) - prev.get("capabilities_verified", 0))
                + 0.2 * max(0, cur.get("analysis_insights", 0) - prev.get("analysis_insights", 0)))
            self._wave_triggers = self._summarize_wave(prev, cur, _wave_t0)
            try:
                from engine import fold as _F
                _members = _F.cold_block(self.tsg)
                if _members:
                    _F.compact_cold(self.tsg, _members)
                    log(f"[loop] {self._tag} cold-fold: {len(_members)} recon notes → digest(投影 pfx 减负)")
            except Exception:
                pass
            try:
                _en = self.profile.enrich(self.tsg, scope_check=self.scope.is_in_scope)
                if _en:
                    log(f"[loop] {self._tag} engine-enrich: {_en} endpoint(s) DNS/HTTP 补全(executor 下一波直接见)")
            except Exception:
                pass
            prev = cur
            stall = 0 if progressed else stall + 1
            verif_stall = 0 if verif_progressed else verif_stall + 1

            _drought = verif_stall >= BRIDGE_STUCK_WAVES
            if _drought:
                _earliest = earliest_unrechecked(self.tsg)
                if _earliest:
                    import hashlib as _hl
                    _rv_ukey = "reverify:" + _hl.md5(_earliest["title"].encode(), usedforsecurity=False).hexdigest()[:10]
                    if not self.tsg.q1("SELECT 1 FROM nodes WHERE ukey=?", (_rv_ukey,)):
                        self.tsg.upsert_node(
                            "subgoal", _rv_ukey,
                            title=f"re-verify the earliest ruled-out direction: {_earliest['title'][:80]} — "
                                  "that conclusion may rest on a misread (a direct-connect failure is NOT proof "
                                  "a service is unreachable; attack it via a DIFFERENT hop: the web app, a proxy, "
                                  "an SSRF endpoint, another protocol)",
                            state="open")
                        log(f"[loop] {self._tag} 派发复访子目标(最早 ruled-out 可能是误判封路): {_earliest['title'][:60]}")
            if self._hint_wanted is not None and not self.profile.is_achieved(self):
                _ff_grant = (self._free_fix_wave == self._cur_wave)
                _wave_report = {
                    "progress_y": _py,
                    "new_flags": _rep_new_flags,
                    "have": _rep_have,
                    "need": self.need_flags,
                    "progress": _rep_progress,
                    "wall_s": max(0.0, time.time() - _wave_t0),
                    "kill": bool(self._prev_wave_timeout_killed),
                    "free_fix": _ff_grant,
                    "deep_harvest_pending": self._has_unmet_pivot_route(),
                }
                try:
                    _want, _why = self._hint_wanted(_wave_report)
                except Exception:
                    _want, _why = (False, "hint_wanted error")
                if _want and not self._hint_pulled and self.hint_fn is not None:
                    self._hint_pulled = True
                    try:
                        _h = self.hint_fn()
                        if _h and str(_h).strip():
                            self._hint_text = str(_h).strip()
                            self._recent_obs = ((self._recent_obs or "") + "\n[platform hint] " + self._hint_text)[-8000:]
                            log(f"[loop] {self._tag} 平台 hint 已取({_why};扣分,每题一次)→ 注入投影+弹药")
                    except Exception as _he:
                        log(f"[loop] {self._tag} 平台 hint 取用失败(non-fatal): {_he!r}")
            for sg in batch:
                if _drought or SG.is_stuck(self._sg_sigs.get(sg, [])):
                    row = self.tsg.q1("SELECT id FROM nodes WHERE type='subgoal' AND title=?", (sg,))
                    if row:
                        SG.bridge_step(self.tsg, row["id"],
                                       state_context=(f"{verif_stall} waves without machine-verified progress"
                                                      if _drought else "no new observation vs last attempt"),
                                       milestone_gap="activity but no verified capability/flag" if _drought
                                       else "current approach exhausted",
                                       action_correction="change vector / try a different surface")
                if self._deliverable_direction_open(sg):
                    continue
                if SG.can_abandon(self._sg_wave.get(sg, wave - 1), wave - 1, refuted=False):
                    self.tsg.upsert_node("subgoal", sg, title=sg, state="abandoned")

            if stall >= self.patience:
                status = "parked"
                break

        if status != "solved" and wave > 0 and not self._exec_ok:
            status = "executor_failed"
        if status not in ("solved", "executor_failed") and wave > 0 and self._confirmed_flag_count() < self.need_flags:
            try:
                self._ensure_attempt_lesson(status)
            except Exception as _le:
                log(f"[loop] {self._tag} attempt-lesson non-fatal: {_le!r}")
        try:
            self.profile.adjudicate(self, set(self.captured))
        except Exception as _fe:
            log(f"[loop] {self._tag} final-flush adjudicate non-fatal: {_fe!r}")
        log(f"[loop] {self._tag} DONE status={status} waves={wave} "
            f"flags={len(self.captured)} +{int(time.time() - t0)}s")
        return RunOutcome(self.captured, status, wave, prev, frozenset(self.local_only_of(self.captured)))


def solve_challenge(target: str, task: str, *, provider: str = "deepseek",
                    model: str = "deepseek-flash", api_key: str = "", db_path: str = "",
                    max_waves: int = 4, concurrency: int = 3, patience: int = PATIENCE,
                    deadline: float | None = None, need_flags: int = 1, profile=None,
                    decide_fn=None, execute_fn=None, tsg: TSG | None = None,
                    shared_recon=None, label: str = "", known_wrong=None, known_correct=None,
                    workspace: str | None = None, on_wave=None, reserved=None, ekb=None,
                    hint_fn=None, hint_wanted=None, initial_hint=None, revived: bool = False,
                    high_effort: bool = False, authorized: list[str] | None = None,
                    extra_targets: list[str] | None = None,
                    budget_stop=None) -> tuple[RunOutcome, TSG]:
    if tsg is None and not db_path:
        import os
        import tempfile
        import time
        from pathlib import Path
        authority = target.split("//")[-1].split("/")[0]
        safe = "".join(c if (c.isalnum() or c in ".-") else "_" for c in authority)[:60] or "target"
        d = Path(tempfile.gettempdir()) / "hxctf"
        d.mkdir(mode=0o700, exist_ok=True)
        try:
            os.chmod(d, 0o700)
        except OSError:
            pass
        db_path = str(d / f"{safe}-{os.getpid()}-{int(time.time() * 1000) % 1_000_000}.db")
    tsg = tsg or TSG(db_path)
    def _role_kw(role: str) -> dict:
        _d = role_llm_params(provider, model, api_key, role)
        if workspace:
            _d["workspace"] = workspace
        return _d

    loop = EngineLoop(
        tsg, target, task,
        decide_fn=decide_fn or _default_cc_decide(**_role_kw("decide")),
        execute_fn=execute_fn or _default_cc_execute(**_role_kw("execute_high" if high_effort else "execute")),
        max_waves=max_waves, concurrency=concurrency, patience=patience, deadline=deadline,
        need_flags=need_flags, profile=profile, shared_recon=shared_recon, label=label,
        known_wrong=known_wrong, known_correct=known_correct, on_wave=on_wave, reserved=reserved, ekb=ekb,
        workspace=workspace, hint_fn=hint_fn,
        hint_wanted=hint_wanted, initial_hint=initial_hint,
        revived=revived,
        high_effort=high_effort,
        authorized=authorized,
        extra_targets=extra_targets,
        budget_stop=budget_stop)
    return loop.run(), tsg
