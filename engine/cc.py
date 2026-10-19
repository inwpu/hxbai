from __future__ import annotations

import ctypes
import ctypes.util
import json
import os
import re
import sys
import shutil
import signal
import subprocess
import tempfile
import queue as _queue
import threading
import time
from collections.abc import Iterator

from engine.providers import cc_env

_PR_SET_CHILD_SUBREAPER = 36


def _enable_subreaper() -> None:
    try:
        libc = ctypes.CDLL(ctypes.util.find_library("c") or "libc.so.6", use_errno=True)
        libc.prctl(_PR_SET_CHILD_SUBREAPER, 1, 0, 0, 0)
    except Exception:
        pass


_LIVE_CLAUDE: set[int] = set()
_LIVE_LOCK = threading.Lock()
_SWEEPER_STARTED = False


def _proc_child_map() -> tuple[dict[int, list[int]], dict[int, str]]:
    try:
        entries = [int(e) for e in os.listdir("/proc") if e.isdigit()]
    except OSError:
        return {}, {}
    children: dict[int, list[int]] = {}
    starttime: dict[int, str] = {}
    for pid in entries:
        try:
            ppid, st = _stat_fields(pid)
        except (OSError, ValueError, IndexError):
            continue
        children.setdefault(ppid, []).append(pid)
        starttime[pid] = st
    return children, starttime


def _direct_children(pid: int) -> list[int]:
    return list(_proc_child_map()[0].get(pid, []))


def _sweep_orphans() -> None:
    me = os.getpid()
    with _LIVE_LOCK:
        live = set(_LIVE_CLAUDE)
    for pid in _direct_children(me):
        if pid in live:
            continue
        for cpid, _st in _descendants(pid):
            try:
                os.kill(cpid, signal.SIGKILL)
            except OSError:
                pass
        try:
            os.kill(pid, signal.SIGKILL)
        except OSError:
            pass
    try:
        while True:
            _pid, _ = os.waitpid(-1, os.WNOHANG)
            if _pid <= 0:
                break
    except (ChildProcessError, OSError):
        pass


def start_orphan_sweeper(interval: float = 5.0) -> None:
    global _SWEEPER_STARTED
    with _LIVE_LOCK:
        if _SWEEPER_STARTED:
            return
        _SWEEPER_STARTED = True
    _enable_subreaper()

    def _loop():
        while True:
            time.sleep(interval)
            try:
                _sweep_orphans()
            except Exception:
                pass
    threading.Thread(target=_loop, daemon=True).start()

_EXEC_TOOLS = ("Bash", "Read", "Write", "Edit", "Grep", "Glob", "WebSearch", "WebFetch",
               "Task", "NotebookEdit")


def _stat_fields(pid: int):
    with open(f"/proc/{pid}/stat", encoding="utf-8", errors="replace") as f:
        data = f.read()
    after = data[data.rindex(")") + 1:].split()
    return int(after[1]), after[19]


def _descendants(root_pid: int) -> list[tuple[int, str]]:
    children, starttime = _proc_child_map()
    out, stack = [], list(children.get(root_pid, []))
    while stack:
        p = stack.pop()
        out.append((p, starttime.get(p, "")))
        stack.extend(children.get(p, []))
    return out


class _SessionReaper:

    def __init__(self, root_pid: int, interval: float = 2.0):
        self.root_pid = root_pid
        self.interval = interval
        self._seen: dict[int, str] = {}
        self._lock = threading.Lock()
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._sample_loop, daemon=True)

    def start(self) -> None:
        self._thread.start()

    def _absorb(self) -> None:
        for pid, st in _descendants(self.root_pid):
            with self._lock:
                self._seen.setdefault(pid, st)

    def _sample_loop(self) -> None:
        while not self._stop.is_set():
            self._absorb()
            self._stop.wait(self.interval)

    def reap(self, sig=signal.SIGKILL) -> int:
        self._stop.set()
        self._absorb()
        with self._lock:
            tracked = dict(self._seen)
        n = 0
        for pid, st0 in tracked.items():
            try:
                if _stat_fields(pid)[1] != st0:
                    continue
                os.kill(pid, sig)
                n += 1
            except (ProcessLookupError, PermissionError, OSError, ValueError, IndexError):
                pass
        return n


_EXEC_UID = int(os.environ.get("HXCTF_EXEC_UID", "61000"))
_EXEC_GID = int(os.environ.get("HXCTF_EXEC_GID", "61000"))
_SETPRIV = shutil.which("setpriv")

_EXEC_ENV_PASSTHROUGH = ("PATH", "LANG", "LANGUAGE", "LC_ALL", "LC_CTYPE", "TERM", "TZ")


def _build_exec_env(provider: str, model: str, *, api_key: str = "", custom_base_url: str = "",
                    thinking_budget: int | None = None) -> dict:
    env = {k: os.environ[k] for k in _EXEC_ENV_PASSTHROUGH if k in os.environ}
    env.setdefault("PATH", "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin")
    env.update(cc_env(provider, model, api_key=api_key, custom_base_url=custom_base_url))
    return env


_TOOL_PROBE = ["nmap", "gobuster", "ffuf", "nikto", "curl", "wget", "sqlmap", "hydra", "sshpass",
               "chisel", "socat", "proxychains4", "impacket-secretsdump", "python3", "nc", "ssh", "git", "gdb",
               "expsearch"]
_ROCKYOU_PATH = "/usr/share/wordlists/rockyou.txt"

def _dir_fact(path, fact):
    return (lambda: os.path.isdir(path), fact)


def _any_dir_fact(paths, fact_tmpl):
    def _probe():
        for p in paths:
            if os.path.isdir(p):
                return p
        return None
    return (_probe, fact_tmpl)


def _bin_fact(name_or_path, fact):
    return (lambda: bool(shutil.which(name_or_path) or os.path.exists(name_or_path)), fact)


def _file_fact(path, fact):
    return (lambda: os.path.exists(path), fact)


_LOCAL_KB_REGISTRY = [
    _file_fact(_ROCKYOU_PATH, f"# Password wordlist present: {_ROCKYOU_PATH}"),
    _dir_fact("/opt/kb",
              "# Offline exploit/vuln KB at /opt/kb (vulhub reproductions, PayloadsAllTheThings, awesome-poc, "
              "exphub, and extra/ technique packs). You have NO internet — search THIS first for a "
              "product/CVE/technique: grep -ri <kw> /opt/kb, cat /opt/kb/INDEX.txt, ls /opt/kb/vulhub/<product>/."),
    _bin_fact("expsearch",
              "# expsearch — offline MSF-module vuln-fact lookup: `expsearch <product-or-keyword>`."),
    _any_dir_fact(["/root/nuclei-templates", "/opt/nuclei-templates"],
                  "# nuclei templates (per-year CVE yaml) under {p} — offline CVE fingerprints."),
    _bin_fact("xform-solve",
              "# xform-solve — byte-transform constraint solver for reverse/crypto: given a ciphertext blob + key + "
              "known plaintext prefix, recovers the transform (`xform-solve --blob <hex> --key <hex>`). Use when a "
              "binary/VM encodes a secret it never prints — extract blob+key statically, then solve offline."),
]


def _seed_tools_md(ws: str) -> None:
    try:
        p = os.path.join(ws, "TOOLS.md")
        if os.path.exists(p):
            return
        avail = [t for t in _TOOL_PROBE if shutil.which(t)]
        lines = ["# Tools available in this environment — existence facts (what you HAVE).",
                 "# NOT instructions and NOT a methodology: decide your own approach. `<tool> --help` for usage.",
                 "", " ".join(avail) if avail else "(probe found none)"]
        kb_facts = []
        for probe, fact in _LOCAL_KB_REGISTRY:
            hit = probe()
            if hit:
                kb_facts.append(fact.format(p=hit) if "{p}" in fact else fact)
        if kb_facts:
            lines.append("")
            lines += kb_facts
        lines.append("")
        lines.append("# Common flag/secret file locations in CTF & lab targets (CANDIDATES — read to VERIFY, "
                     "never assume): /flag  /flag.txt  /root/flag.txt  /challenge/flag.txt  /home/*/flag.txt  "
                     "/var/www/flag*  — the MOMENT you gain arbitrary file read (LFI / path traversal), try these "
                     "ABSOLUTE paths (traverse up past the web root), not only files under the web directory.")
        lines.append("")
        lines.append("# Scratch & isolation (existence fact): THIS directory is your PRIVATE per-task workspace — "
                     "your $HOME, $PWD and $TMPDIR all point here. Keep EVERY file you create here (not in /tmp). "
                     "`/tmp` is SHARED with other tasks running concurrently in this container: scripts, dumps, DB "
                     "exports and — critically — any flag strings or UUID tokens you find under /tmp were produced by "
                     "OTHER tasks against OTHER targets. They are NOT this target's answer: do not analyze them and "
                     "never submit them. Treat only evidence you obtained from THIS target as yours.")
        with open(p, "w", encoding="utf-8") as f:
            f.write("\n".join(lines) + "\n")
    except Exception:
        pass


_SETPRIV_OK: bool | None = None


def _setpriv_usable() -> bool:
    global _SETPRIV_OK
    if _SETPRIV_OK is not None:
        return _SETPRIV_OK
    _SETPRIV_OK = False
    if _SETPRIV and hasattr(os, "geteuid") and os.geteuid() == 0:
        try:
            # nosem 抑制说明:setpriv 降权**探针**(跑 /bin/true 验能力),参数全是模块常量,非外部输入
            _r = subprocess.run([_SETPRIV, "--reuid", str(_EXEC_UID), "--regid", str(_EXEC_GID),  # nosem: python.lang.security.audit.dangerous-subprocess-use-tainted-env-args.dangerous-subprocess-use-tainted-env-args
                                 "--clear-groups", "--", "/bin/true"],
                                capture_output=True, timeout=10)
            _SETPRIV_OK = (_r.returncode == 0)
        except Exception:
            _SETPRIV_OK = False
    if not _SETPRIV_OK and _SETPRIV and hasattr(os, "geteuid") and os.geteuid() == 0:
        sys.stderr.write("[cc] ⚠ setpriv 降权探针失败(平台容器 CAP_SETUID 被夺?)→ 执行器以当前 uid "
                         "运行:uid 隔离降级,可用性优先(一次性告警)\n")
    return _SETPRIV_OK


def _exec_wrap(cmd: list, env: dict, workspace: str | None = None) -> tuple[list, dict, str, bool]:
    owned = not workspace
    if workspace:
        ws = workspace
        os.makedirs(ws, exist_ok=True)
    else:
        ws = tempfile.mkdtemp(prefix="hxexec-")
    _seed_tools_md(ws)
    env = {**env, "HOME": ws, "TMPDIR": ws}
    env.setdefault("IS_SANDBOX", "1")
    if _setpriv_usable():
        try:
            os.chown(ws, _EXEC_UID, _EXEC_GID)
            wrapped = [_SETPRIV, "--reuid", str(_EXEC_UID), "--regid", str(_EXEC_GID),
                       "--clear-groups", "--"] + cmd
            return wrapped, env, ws, owned
        except OSError:
            pass
    return cmd, env, ws, owned


def _release_workspace(ws: str, *, owned: bool) -> None:
    if owned:
        shutil.rmtree(ws, ignore_errors=True)


_DIAG_MAX = 60


def _diag(msg: str) -> None:
    try:
        sys.stderr.write(f"[cc-diag] {msg}\n")
        sys.stderr.flush()
    except Exception:
        pass


_BENIGN_DIAG_RX = re.compile(r"unrecognized_model")


def _parse_stream(lines, on_nonjson):
    for line in lines:
        line = line.strip()
        if not line:
            continue
        try:
            yield json.loads(line)
        except json.JSONDecodeError:
            if _BENIGN_DIAG_RX.search(line):
                continue
            on_nonjson(line[:500])


def run_claude(prompt: str, *, provider: str = "deepseek", model: str = "deepseek-flash",
               api_key: str = "", custom_base_url: str = "", tools: bool = True,
               max_turns: int = 40, timeout: int = 900,
               no_internet_tools: bool = True, workspace: str | None = None,
               resume_session_id: str = "", fork_session: bool = False,
               thinking_budget: int | None = None) -> Iterator[dict]:
    env = _build_exec_env(provider, model, api_key=api_key, custom_base_url=custom_base_url,
                          thinking_budget=thinking_budget)
    cmd = ["claude", "-p", prompt, "--output-format", "stream-json", "--verbose",
           "--dangerously-skip-permissions", "--max-turns", str(max_turns),
           "--autocompact", "100000"]
    if resume_session_id:
        cmd += ["--resume", resume_session_id]
        if fork_session:
            cmd += ["--fork-session"]
    if not tools:
        cmd += ["--disallowed-tools", *_EXEC_TOOLS]
    elif no_internet_tools:
        cmd += ["--disallowed-tools", "WebSearch", "WebFetch"]
    if tools:
        start_orphan_sweeper()
    cmd, env, _ws, _ws_owned = _exec_wrap(cmd, env, workspace=workspace)
    proc = subprocess.Popen(cmd, env=env, cwd=_ws, stdout=subprocess.PIPE, stderr=subprocess.STDOUT,
                            text=True, bufsize=1, start_new_session=True)
    try:
        root_start = _stat_fields(proc.pid)[1]
    except (OSError, ValueError, IndexError):
        root_start = None
    with _LIVE_LOCK:
        _LIVE_CLAUDE.add(proc.pid)
    reaper = _SessionReaper(proc.pid, interval=0.5) if tools else None
    if reaper:
        reaper.start()

    def _teardown(sig=signal.SIGKILL):
        alive_same = False
        try:
            alive_same = (root_start is not None and _stat_fields(proc.pid)[1] == root_start)
        except (OSError, ValueError, IndexError):
            alive_same = False
        if alive_same:
            try:
                os.killpg(proc.pid, sig)
            except (ProcessLookupError, PermissionError):
                pass
            except Exception:
                try:
                    proc.kill()
                except Exception:
                    pass
        if reaper:
            reaper.reap(sig)

    SOFT_KILL_LEAD_S = 60
    _soft = None
    if timeout > SOFT_KILL_LEAD_S + 10:
        _soft = threading.Timer(timeout - SOFT_KILL_LEAD_S, lambda: _teardown(signal.SIGINT))
        _soft.daemon = True
        _soft.start()
    watchdog = threading.Timer(timeout, _teardown)
    watchdog.daemon = True
    watchdog.start()
    DRAIN_GRACE_S = 15
    _q: "_queue.Queue" = _queue.Queue(maxsize=10000)
    _DRAIN_END = object()

    def _drain():
        try:
            for _ln in proc.stdout:
                _q.put(_ln)
        except Exception:
            pass
        finally:
            try:
                _q.put(_DRAIN_END)
            except Exception:
                pass
    _drain_th = threading.Thread(target=_drain, daemon=True)
    _drain_th.start()

    def _lines():
        _deadline = time.time() + timeout + DRAIN_GRACE_S
        while True:
            _rem = _deadline - time.time()
            if _rem <= 0:
                return
            try:
                _item = _q.get(timeout=min(_rem, 1.0))
            except _queue.Empty:
                continue
            if _item is _DRAIN_END:
                return
            yield _item
    _diag_buf: list[str] = []
    def _collect(ln: str) -> None:
        if len(_diag_buf) < _DIAG_MAX:
            _diag_buf.append(ln)
    try:
        from engine.providers import note_main_result as _nmr, resolve_active as _ra, main_rotation as _mrot
        _count_health = provider == _ra()["provider"]
    except Exception:
        _count_health = False
    import re as _re
    _TRANSPORT_RX = _re.compile(
        r"refused|reset by peer|timed? ?out|timeout|ECONNREFUSED|ETIMEDOUT|ECONNRESET|overloaded|50[0234]|529", _re.I)

    def _health(ev: dict) -> str:
        if not _count_health:
            return ""
        try:
            if isinstance(ev, dict):
                if ev.get("type") == "system" and ev.get("subtype") == "api_retry":
                    _nmr(False, transport=True)
                elif ev.get("is_error") or ev.get("type") == "error":
                    _txt = str(ev.get("result") or ev.get("error") or "")
                    _nmr(False, transport=bool(_TRANSPORT_RX.search(_txt)))
                elif ev.get("type") == "assistant":
                    _nmr(True)
            _rot = _mrot()
            if _rot and _rot.get("failed_provider") == provider:
                return "rotated"
        except Exception:
            pass
        return ""

    try:
        for _ev in _parse_stream(_lines(), _collect):
            if _health(_ev) == "rotated":
                return
            yield _ev
    finally:
        if _diag_buf:
            _diag(f"pid={proc.pid} session emitted {len(_diag_buf)} non-JSON line(s) "
                  f"(likely error_during_execution 真因):")
            for _l in _diag_buf:
                _diag(f"pid={proc.pid} | {_l}")
        if _soft is not None:
            _soft.cancel()
        watchdog.cancel()
        if reaper:
            reaper._absorb()
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except OSError:
            pass
        _teardown()
        try:
            proc.wait(timeout=10)
        except Exception:
            pass
        with _LIVE_LOCK:
            _LIVE_CLAUDE.discard(proc.pid)
        _sweep_orphans()
        _release_workspace(_ws, owned=_ws_owned)


def collect_text(events: list[dict]) -> str:
    from engine.judge import text_of_event
    return "\n".join(t for t, ch in (text_of_event(e) for e in events) if t)
