from __future__ import annotations

import hashlib
import os
import sys
import threading
import time
from contextlib import nullcontext
from pathlib import Path

from tsec_benchmark import (TSecBenchmark, DuplicateSubmit, InvalidState, VpnCheckError,
                            TSecError, TSecConnectionError)

from engine.judge import (_flagishness, FLAGISH_FLOOR, confident_flags, extract_candidates,
                          _printable_inner, natural_language_inner, _INNER_OF)
from engine.scheduler import Attempt, Budget, Scheduler
from engine import pacing
from engine.loop import solve_challenge, CC_MAX_TIMEOUT
from engine.shared_recon import SharedReconCache
from engine.kb_search import EXPOSED_SERVICE_PORTS as _SERVICE_PORTS
from engine.ekb import EKB
from engine.timebox import call_with_timeout, CallTimeout

CHALLENGE_CONCURRENCY = 3
PLATFORM_CALL_TIMEOUT_S = 180
ENGINE_EXEC_CONCURRENCY = 6
MAX_WAVES = 4
MAX_WRONG_SUBMITS = 5
DROUGHT_WORK_S = 35 * 60
HINT_WALL_FUSE_S = 10 * 60
DROUGHT_K_REF = 0.35
SOFT_KILL_CAP_S = 840
FREE_FIX_CAP_HINT = 2
DEEP_HARVEST_CAP_HINT = 4
HC_ESCAPE_MAX = 2
LOW_CONF_BUDGET = 1

_session_dead = threading.Event()

_stop_requested = threading.Event()
_summary_done = threading.Event()


def _is_session_ended(err) -> bool:
    return "already finished" in str(err).lower()
SECOND_WIND_MAX = 3
PER_ATTEMPT_CAP_S = int(2 * (CC_MAX_TIMEOUT + 60) / 1.5)
from engine.providers import resolve_active as _resolve_active, resolve_key as _resolve_key, PROVIDERS as _PROVIDERS, probe_reasoning as _probe_reasoning, _exec_runtime_tuning as _exec_tuning
_ACTIVE = _resolve_active()
PROVIDER = _ACTIVE["provider"]
MODEL = _ACTIVE["model"]
LOG_ROOT = os.environ.get("HXCTF_LOG_ROOT", "/var/lib/hxctf/bench")
WS_ROOT = os.environ.get("HXCTF_WS_ROOT", "/var/lib/hxctf/ws")
ARCHIVE_ROOT = os.environ.get("HXCTF_ARCHIVE_ROOT", "/tmp/hxctf-bench")
WS_FREE_WATERMARK_BYTES = 4 * 1024 ** 3


def _ws_disk_pressure() -> bool:
    import shutil
    try:
        return shutil.disk_usage(WS_ROOT).free < WS_FREE_WATERMARK_BYTES
    except OSError:
        return False

_lock = threading.RLock()


def log(msg: str) -> None:
    with _lock:
        sys.stdout.write(msg + "\n")
        sys.stdout.flush()


def _addr_alive_tcp(addr: str, timeout: float = 3.0) -> bool:
    import socket as _socket, re as _re
    try:
        s = _re.sub(r"^\w+://", "", str(addr).strip()).split("#", 1)[0].split("/", 1)[0]
        if ":" in s:
            host, _, p = s.rpartition(":")
        else:
            host, p = s, ""
        host = host.strip("[]") or s
        port = int(p) if p.isdigit() else 80
        if not host:
            return False
        with _socket.create_connection((host, port), timeout=timeout):
            return True
    except Exception:
        return False


_addr_probe = _addr_alive_tcp


_PORTSCAN_SEM = threading.Semaphore(1)
_PORTSCAN_SATURATION_RATIO = 0.5
_PORTSCAN_SATURATION_ABS = 512


def _portscan_saturated(n_open: int, n_scanned: int) -> bool:
    return n_scanned >= 64 and (n_open > _PORTSCAN_SATURATION_RATIO * n_scanned
                                or n_open > _PORTSCAN_SATURATION_ABS)
_COMMON_SERVICE_PORTS = (
    21, 22, 23, 25, 53, 80, 110, 143, 443, 445, 465, 587, 993, 995,
    1433, 1521, 3306, 5432, 6379, 9042, 11211, 27017,
    2049, 2375, 2379, 5000, 5601, 8500, 9200, 9300, 15672, 50000,
    3000, 5900, 7860, 8000, 8008, 8080, 8081, 8088, 8443, 8888, 9000, 9090, 9091, 9100, 9443,
    3389, 6443, 502, 1880, 389, 636,
    8100, 8118, 8161, 8188, 8200, 8501, 8686, 8983, 9001, 9998, 5984, 2181, 7001, 7077,
)


def _scan_port_order(hi=_COMMON_SERVICE_PORTS, full_max: int = 65535) -> list[int]:
    seen = set()
    order: list[int] = []
    for p in hi:
        if 1 <= p <= full_max and p not in seen:
            seen.add(p); order.append(p)
    for p in range(1, full_max + 1):
        if p not in seen:
            order.append(p)
    return order


def _app_layer_alive(host: str, port: int, timeout: float = 2.0) -> bool:
    import socket as _socket
    try:
        s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        s.settimeout(timeout)
        if s.connect_ex((host, port)) != 0:
            s.close()
            return False
    except OSError:
        return False
    try:
        s.settimeout(min(1.5, timeout))
        try:
            if s.recv(64):
                return True
        except (_socket.timeout, OSError):
            pass
        try:
            s.sendall(b"GET / HTTP/1.0\r\nHost: x\r\n\r\n")
            return bool(s.recv(64))
        except OSError:
            return False
    finally:
        try:
            s.close()
        except Exception:
            pass


def _app_probe_ports(host: str, ports, *, budget_s: float = 20.0, workers: int = 32) -> list[int]:
    from concurrent.futures import ThreadPoolExecutor
    _t0 = time.time()
    alive: list[int] = []
    def _one(p):
        if time.time() - _t0 > budget_s:
            return None
        return p if _app_layer_alive(host, p) else None
    try:
        with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
            for r in ex.map(_one, list(ports)):
                if r is not None:
                    alive.append(r)
                if time.time() - _t0 > budget_s:
                    break
    except Exception as _e:
        log(f"[engine] {host} app-layer probe non-fatal: {_e!r}")
    return sorted(alive)


def _disambiguate_addrs(addrs: list, *, timeout: float = 6.0) -> list:
    import urllib.request as _ureq
    import urllib.error as _uerr

    def _rank(addr: str) -> tuple:
        url = addr if str(addr).startswith("http") else f"http://{addr}/"
        try:
            req = _ureq.Request(url, method="GET", headers={"User-Agent": "hxctf-probe"})
            with _ureq.urlopen(req, timeout=timeout) as r:
                body = r.read(4096) or b""
                ct = (r.headers.get("content-type") or "").lower()
                biz = (len(body) > 200 and ("html" in ct or "json" in ct or b"<" in body[:512]))
                default_err = (r.status in (502, 503, 504)) or (b"nginx" in body[:200] and len(body) < 400)
                return (0 if (biz and not default_err) else (1 if r.status < 500 else 2), -len(body))
        except _uerr.HTTPError as e:
            return (1 if e.code < 500 else 2, 0)
        except Exception:
            return (3, 0)
    try:
        scored = sorted(range(len(addrs)), key=lambda i: _rank(addrs[i]))
        ranked = [addrs[i] for i in scored]
        if ranked != list(addrs):
            log(f"[engine] 多地址消歧: {[str(a) for a in addrs]} → {[str(a) for a in ranked]}(业务面在前)")
        return ranked
    except Exception:
        return list(addrs)


def _control_plane_portscan(host: str, *, budget_s: float = 40.0, workers: int = 128, timeout: float = 1.0,
                            ports=None) -> list[int]:
    import socket as _socket
    from concurrent.futures import ThreadPoolExecutor
    _host = _re.sub(r"^\w+://", "", str(host).strip()).split("#", 1)[0].split("/", 1)[0].rpartition(":")[0] or host
    _host = _host.strip("[]")
    if not _host:
        return []
    ports = list(ports) if ports is not None else _scan_port_order()
    open_ports: list[int] = []
    _t0 = time.time()
    _emfile = {"n": 0}
    def _probe1(p: int):
        if time.time() - _t0 > budget_s:
            return None
        try:
            s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
        except OSError:
            _emfile["n"] += 1
            return None
        try:
            s.settimeout(timeout)
            return p if s.connect_ex((_host, p)) == 0 else None
        except Exception:
            return None
        finally:
            try:
                s.close()
            except Exception:
                pass
    try:
        with _PORTSCAN_SEM:
            with ThreadPoolExecutor(max_workers=max(1, workers)) as ex:
                for r in ex.map(_probe1, ports):
                    if r is not None:
                        open_ports.append(r)
                    if time.time() - _t0 > budget_s:
                        break
    except Exception as _e:
        log(f"[engine] {_host} control-plane portscan non-fatal: {_e!r}")
    if _emfile["n"]:
        log(f"[engine] {_host} portscan FD-exhaustion on {_emfile['n']} ports (INCOMPLETE — 降级,执行器自扫补;调高 ulimit 可修)")
    _scanned = len(ports)
    if _portscan_saturated(len(open_ports), _scanned):
        _cands = [p for p in _COMMON_SERVICE_PORTS if p <= 65535]
        _real = _app_probe_ports(_host, _cands, budget_s=min(20.0, budget_s))
        _svc_open = sorted(set(open_ports) & _SERVICE_PORTS)
        if len(_real) > _PORTSCAN_SATURATION_RATIO * len(_cands):
            log(f"[engine] {_host} portscan SATURATED: {len(open_ports)}/{_scanned} connect-open + 应用层探活仍 {len(_real)}/{len(_cands)} 饱和"
                f"(代理转发全部端口)→ 丢弃洪水,仅保留标准服务口 {_svc_open}(→exposed_service_refs 原生协议 nudge)")
            return _svc_open
        log(f"[engine] {_host} portscan SATURATED: {len(open_ports)}/{_scanned} connect-open(accept-all/tarpit 伪影)→ "
            f"应用层探活得真服务口 {_real} + 标准服务口豁免 {_svc_open}(tarpit 洪水已滤)→ shared_recon")
        return sorted(set(_real) | set(_svc_open))
    _open_set = set(open_ports)
    _missed_hi = [p for p in _COMMON_SERVICE_PORTS if 1 <= p <= 65535 and p not in _open_set]
    if _missed_hi:
        def _confirm(p, tries: int = 3, to: float = 2.5, gap: float = 0.5):
            for _i in range(tries):
                try:
                    s = _socket.socket(_socket.AF_INET, _socket.SOCK_STREAM)
                    s.settimeout(to)
                    rc = s.connect_ex((_host, p))
                    s.close()
                    if rc == 0:
                        return p
                except OSError:
                    pass
                if _i < tries - 1:
                    time.sleep(gap)
            return None
        try:
            with _PORTSCAN_SEM:
                with ThreadPoolExecutor(max_workers=min(len(_missed_hi), 64)) as ex:
                    _recovered = [r for r in ex.map(_confirm, _missed_hi) if r is not None]
        except Exception as _e:
            log(f"[engine] {_host} portscan hi-value confirm non-fatal: {_e!r}")
            _recovered = []
        if _recovered:
            if len(_recovered) > _PORTSCAN_SATURATION_RATIO * len(_missed_hi):
                _svc_rec = [p for p in _recovered if p in _SERVICE_PORTS and p not in _open_set]
                log(f"[engine] {_host} portscan confirm 命中 {len(_recovered)}/{len(_missed_hi)} 高价值口 > 饱和阈"
                    f"(accept-all/mesh 伪影)→ 丢弃洪水,仅保留标准服务口 {sorted(_svc_rec)}")
                open_ports.extend(_svc_rec)
            else:
                log(f"[engine] {_host} portscan 瞬时抖动恢复高价值服务口 {sorted(_recovered)}"
                    f"(单探漏报→重试确认;治 a-18 :9000 型'一次 flap 静默藏掉整题唯一端口')→ shared_recon")
                open_ports.extend(p for p in _recovered if p not in _open_set)
    return sorted(open_ports)


def _find_iptables():
    import shutil as _sh
    return (_sh.which("iptables")
            or next((c for c in ("/usr/sbin/iptables", "/sbin/iptables", "/usr/bin/iptables") if os.path.exists(c)), None))


_IPTABLES = _find_iptables()


def _detect_mesh_sidecar() -> str | None:
    import subprocess as _sp
    import socket as _s
    hits = []
    if _IPTABLES:
        try:
            r = _sp.run([_IPTABLES, "-t", "nat", "-S", "ISTIO_OUTPUT"], capture_output=True, timeout=5, text=True)
            if r.returncode == 0 and r.stdout.strip():
                hits.append("ISTIO_OUTPUT")
        except Exception:
            pass
    for _p, _name in ((15001, "envoy-out"), (15006, "envoy-in"), (15020, "pilot-agent"), (15090, "envoy-stats")):
        try:
            _c = _s.create_connection(("127.0.0.1", _p), timeout=1)
            _c.close()
            hits.append(f"127.0.0.1:{_p}({_name})")
        except Exception:
            pass
    return " + ".join(hits) if hits else None


def _apply_mesh_bypass(host: str) -> bool:
    if not _IPTABLES:
        return False
    import subprocess as _sp
    h = _re.sub(r"^\w+://", "", str(host).strip()).split("#", 1)[0].split("/", 1)[0].rpartition(":")[0].strip("[]") or str(host)
    try:
        chk = _sp.run([_IPTABLES, "-t", "nat", "-S", "ISTIO_OUTPUT"], capture_output=True, timeout=5, text=True)
        if chk.returncode != 0 or not chk.stdout.strip():
            return False
        if _sp.run([_IPTABLES, "-t", "nat", "-C", "ISTIO_OUTPUT", "-d", f"{h}/32", "-j", "RETURN"],
                   capture_output=True, timeout=5).returncode == 0:
            return True
        if _sp.run([_IPTABLES, "-t", "nat", "-I", "ISTIO_OUTPUT", "1", "-d", f"{h}/32", "-j", "RETURN"],
                   capture_output=True, timeout=5).returncode == 0:
            log(f"[engine] {h} ⚠ mesh 旁路:检测到 agent-pod Istio sidecar → ISTIO_OUTPUT 插本靶标 RETURN 豁免,绕过自家 "
                f"sidecar 捕获(裸 :9000 等非-mesh 端口可直连;仅本靶标 IP,模型网关/VPN/回环/其余 mesh 路由不动)。")
            return True
    except Exception as _e:
        log(f"[engine] {h} mesh 旁路 non-fatal: {_e!r}")
    return False


def _addr_http_5xx(addr: str, timeout: float = 3.0) -> bool:
    import socket as _socket, re as _re
    try:
        s = _re.sub(r"^\w+://", "", str(addr).strip()).split("#", 1)[0].split("/", 1)[0]
        host, _, p = (s.rpartition(":") if ":" in s else (s, "", ""))
        host = (host or s).strip("[]")
        port = int(p) if p.isdigit() else 80
        with _socket.create_connection((host, port), timeout=timeout) as _c:
            _c.sendall(f"GET / HTTP/1.0\r\nHost: {host}\r\nConnection: close\r\n\r\n".encode())
            _line = _c.recv(64) or b""
        return bool(_re.match(rb"HTTP/\d\.\d 50[234]", _line.strip()))
    except Exception:
        return False


def _addr_state(addr: str, timeout: float = 3.0) -> str:
    if not _addr_probe(addr, timeout):
        return "down"
    return "sick" if _addr_http_5xx(addr, timeout) else "up"


def _addrs_alive(addrs, timeout: float = 3.0, tries: int = 3, retry_delay: float = 2.0) -> bool:
    addrs = addrs or []
    if not addrs:
        return False
    for i in range(max(1, tries)):
        if any(_addr_state(a, timeout) == "up" for a in addrs):
            return True
        if i < tries - 1:
            time.sleep(retry_delay)
    return False


def _start_with_retry(client, code: str, tries: int = 6):
    for i in range(tries):
        try:
            return call_with_timeout(client.start_challenge, code, timeout=PLATFORM_CALL_TIMEOUT_S)
        except InvalidState as e:
            if "max active" in str(e).lower() and i < tries - 1:
                log(f"[engine] {code} start retry {i + 1}(max-active 退避;平台侧计一次启动) → {min(6 * (2 ** i), 60)}s")
                time.sleep(min(6 * (2 ** i), 60))
                continue
            raise
        except (TSecConnectionError, CallTimeout):
            if i < tries - 1:
                time.sleep(6)
                continue
            raise


def _submit_with_retry(client, code: str, flag: str, tries: int = 4):
    for i in range(tries):
        try:
            return call_with_timeout(client.submit_flag, code, flag, timeout=PLATFORM_CALL_TIMEOUT_S)
        except (TSecConnectionError, CallTimeout):
            if i < tries - 1:
                time.sleep(4)
                continue
            raise


def _closedloop_broken(box: dict, res, key: str = "") -> bool:
    cum = getattr(res, "cumulative_score", None)
    if cum is None:
        return False
    lasts = box.setdefault("last", {})
    last = lasts.get(key, -1)
    broken = (last >= 0 and bool(getattr(res, "correct", False))
              and int(getattr(res, "awarded", 0) or 0) > 0 and cum <= last)
    if cum > last:
        lasts[key] = cum
        if not broken:
            box["breaks"] = 0
    if broken:
        box["breaks"] += 1
    return broken


_CLOSEDLOOP_BOX = {"last": {}, "breaks": 0}


def _close_with_retry(client, code: str, tries: int = 4) -> bool:
    _last = ""
    for i in range(tries):
        try:
            call_with_timeout(client.close_challenge, code, timeout=PLATFORM_CALL_TIMEOUT_S)
            return True
        except TSecConnectionError:
            _last = "network"
            log(f"[engine] {code} close retry {i + 1}(network;平台侧计一次关闭)")
        except CallTimeout:
            _last = "timeout"
            log(f"[engine] {code} close retry {i + 1}(timeout;平台侧计一次关闭)")
        except TSecError as e:
            _sc = getattr(e, "status_code", None)
            if _sc == 404 or getattr(e, "code", "") == "challenge_not_found":
                return True
            if _sc not in (500, 502, 503, 504):
                log(f"[engine] {code} close error (non-transient): {e}")
                return False
            _last = f"gateway {_sc}"
        except Exception as e:
            log(f"[engine] {code} close unexpected error: {e!r}")
            return False
        if i < tries - 1:
            time.sleep(3)
            continue
        log(f"[engine] {code} close failed after {tries} tries ({_last}; platform slot may leak → max-active risk)")
        return False


def _get_hint_cached(client, code: str, st: dict) -> str | None:
    if "hint" in st:
        return st["hint"]
    if st.get("closed_at"):
        log(f"[engine] {code} hint 购买被拒:靶场已关(管线纪律)")
        return None
    text = None
    for i in range(3):
        try:
            h = call_with_timeout(client.get_hint, code, timeout=PLATFORM_CALL_TIMEOUT_S)
            text = (getattr(h, "hint", None) or (h if isinstance(h, str) else None))
            break
        except (TSecConnectionError, CallTimeout):
            if i < 2:
                time.sleep(4); continue
            break
        except Exception as e:
            log(f"[engine] {code} get_hint error (non-fatal): {e!r}")
            break
    st["hint"] = (str(text).strip() if text and str(text).strip() else None)
    if st["hint"]:
        st["force_replan"] = True
        st["info_gain"] = True
        log(f"[engine] {code} 平台 hint 已取(扣分,每题一次)→ force_replan+info_gain(下一轮强制重锚∧预算缩)")
    else:
        st["force_replan"] = True
        log(f"[engine] {code} hint 不可得(None)→ force_replan(纯换面重锚,无外援信号)")
    return st["hint"]


def _work_drought_s(reports: list) -> float:
    drought = 0.0
    for r in reports:
        nf = r.get("new_flags", 0)
        if nf > 0:
            remaining_before = r.get("need", 1) - (r.get("have", nf) - nf)
            frac = nf / max(1, remaining_before)
            drought *= max(0.0, 1.0 - frac)
        elif "progress_y" in r:
            _y = max(0.0, min(1.0, float(r.get("progress_y") or 0.0)))
            if _y < DROUGHT_K_REF:
                drought += min(max(0.0, r.get("wall_s", 0.0)), SOFT_KILL_CAP_S) * (1.0 - _y / DROUGHT_K_REF)
        elif r.get("progress"):
            continue
        else:
            drought += min(max(0.0, r.get("wall_s", 0.0)), SOFT_KILL_CAP_S)
    return drought


def hint_wanted(st: dict, reports: list) -> tuple[bool, str]:
    _dr = st.get("diff_rank")
    _dying = st.get("wrong", 0) >= MAX_WRONG_SUBMITS
    if _dr not in (1.0, 0.5):
        return (False, "hint 仅限 hard/medium(easy/未知自解,取 hint 纯扣分拖累排名)")
    if _dr == 0.5 and not _dying and (not reports or st.get("attempts", 0) < 2):
        return (False, "medium 分档:整轮未解(attempts≥2 卡壳实锤)才买(首轮自解概率仍高,不付费;"
                       "1012 修:FlowLab 型 medium 卡死 62.7min 零 hint)")
    if st.get("wrong", 0) >= MAX_WRONG_SUBMITS:
        return (True, "dying:错交预算触底(方向性错误,hint 同波纠偏)")
    if not reports:
        return (False, "无 wave 数据(尚未开波)")
    drought = _work_drought_s(reports)
    if (st.get("_wall_s", 0) >= pacing.hint_wall_fuse_s() and st.get("correct", 0) == 0
            and not st.get("last_gain", False)):
        return (True, f"wall-fuse {st['_wall_s']:.0f}s 窗口零 correct 零进展(hint 早买早转向;对照:60min 晚触发=靶已死)")
    if drought < pacing.drought_work_s():
        return (False, f"drought {drought:.0f}s < {pacing.drought_work_s()}s(工作量未达/仍在健康推进)")
    r = reports[-1]
    if r.get("free_fix") and st.get("free_fix_grants", 0) < FREE_FIX_CAP_HINT:
        st["free_fix_grants"] = st.get("free_fix_grants", 0) + 1
        return (False, f"free_fix 可用(未利用授权面,先零成本转向);grants={st['free_fix_grants']}/{FREE_FIX_CAP_HINT};drought={drought:.0f}s")
    if r.get("deep_harvest_pending") and st.get("deep_harvest_grants", 0) < DEEP_HARVEST_CAP_HINT:
        st["deep_harvest_grants"] = st.get("deep_harvest_grants", 0) + 1
        return (False, f"deep_harvest 宽限(内网纵深未挖尽,先带内收割/挖凭据,非买 hint);"
                       f"grants={st['deep_harvest_grants']}/{DEEP_HARVEST_CAP_HINT};drought={drought:.0f}s")
    return (True, f"work-drought {drought:.0f}s ≥ {pacing.drought_work_s()}s(无旗∧无机检进展工时,免费手段已尽)")


def _flag_inner(f: str) -> str:
    m = _INNER_OF.search(f)
    return m.group(1) if m else ""


def _neighbor_flag_owner(flag: str, registry: dict, code: str) -> str | None:
    ci = _flag_inner(flag)
    if len(ci) < 8:
        return None
    for rf, owner in registry.items():
        if owner in (None, code):
            continue
        ri = _flag_inner(rf)
        if len(ri) >= 8 and (ci in ri or ri in ci):
            return owner
    return None


def _family_key(flag: str) -> str:
    inner = _flag_inner(flag) or flag
    return _re.sub(r"[^0-9a-z]", "", inner.casefold())


def _terminal_orphan(st: dict, need: int) -> bool:
    if st.get("correct", 0) >= max(1, need):
        return True
    return st.get("correct", 0) == 0 and st.get("wrong", 0) >= MAX_WRONG_SUBMITS


def _submit_captured(client, code: str, st: dict, need: int, captured: set,
                     registry: dict | None = None, lock: "threading.Lock | None" = None,
                     cand_seen: dict | None = None, local_only: set | None = None) -> dict:
    verdict = {"confirmed": set(), "wrong": set()}
    if st.get("closed_at"):
        log(f"[engine] {code} submit 被拒:靶场已关(管线纪律;captured={len(captured)} 丢弃)")
        return {"confirmed": set(), "wrong": set()}
    captured = set(captured)
    for c in list(captured):
        captured |= extract_candidates(c)
    captured = {c for c in captured if _printable_inner(c) and not natural_language_inner(c)}
    conf = confident_flags(captured, need)
    if cand_seen is not None:
        with (lock or nullcontext()):
            for c in captured:
                inner = _flag_inner(c)
                if inner:
                    cand_seen.setdefault(inner, set()).add(code)
            conf = {f for f in conf if len(cand_seen.get(_flag_inner(f), ())) < 2}
    if local_only:
        conf = {f for f in conf if f not in local_only}
    fam_shot_this_wave: set = set()
    order = _diverse_order(captured)
    _failed_fams = st.get("wrong_families") or set()
    order = sorted(order, key=lambda f: 1 if _family_key(f) in _failed_fams else 0)
    for flag in order:
        fk = _family_key(flag)
        if fk in fam_shot_this_wave:
            continue
        if st["correct"] >= need:
            log(f"[engine] {code} all {need} flag(s) captured; stop submitting")
            break
        if st.get("wrong_raw", 0) >= MAX_WRONG_SUBMITS + HC_ESCAPE_MAX:
            log(f"[engine] {code} raw-wrong hard cap ({MAX_WRONG_SUBMITS + HC_ESCAPE_MAX}) hit; stop (防同族变体跨波 bleed)")
            return st.get("correct", 0) > 0
        if st["wrong"] >= MAX_WRONG_SUBMITS:
            if not (flag in conf and flag not in st["submitted"] and st.get("hc_escape", 0) < HC_ESCAPE_MAX):
                log(f"[engine] {code} wrong-submit budget ({MAX_WRONG_SUBMITS}) hit; stop (防 storm)")
                return st.get("correct", 0) > 0
        if flag in st["submitted"]:
            continue
        if flag not in conf and st["low_wrong"] >= LOW_CONF_BUDGET:
            continue
        with (lock or nullcontext()):
            if registry is not None:
                _owner = registry.get(flag)
                if _owner in (None, code):
                    _owner = _neighbor_flag_owner(flag, registry, code)
                if _owner not in (None, code):
                    st["submitted"].add(flag)
                    verdict["wrong"].add(flag)
                    log(f"[engine] {code} skip {flag} — owned by {_owner} (cross-pivot contamination"
                        f"{' incl. truncated twin' if registry.get(flag) in (None, code) else ''}; not submitted)")
                    continue
            try:
                res = _submit_with_retry(client, code, flag)
            except DuplicateSubmit:
                st["submitted"].add(flag)
                if registry is not None and registry.get(flag) == code:
                    verdict["confirmed"].add(flag)
                elif flag in st["wrong_flags"]:
                    verdict["wrong"].add(flag)
                log(f"[engine] {code} {flag} duplicate")
                continue
            except TSecConnectionError as e:
                log(f"[engine] {code} submit net-error (NOT marked; retry on revive) {flag}: {e}")
                break
            except TSecError as e:
                if _is_session_ended(e):
                    _session_dead.set()
                    log(f"[engine] {code} submit 遇平台会话已结束 → 停止提交(全局止损)")
                    break
                st["submitted"].add(flag)
                log(f"[engine] {code} submit error {flag}: {e}")
                continue
            st["submitted"].add(flag)
            fam_shot_this_wave.add(fk)
            log(f"[engine] {code} submit {flag} -> correct={res.correct} awarded={res.awarded} "
                f"progress={res.correct_flag_count}/{res.total_flag_count}")
            if res.correct and _closedloop_broken(_CLOSEDLOOP_BOX, res, key=code):
                if _CLOSEDLOOP_BOX["breaks"] >= 3:
                    log(f"[engine] [SUBMIT-CLOSEDLOOP-ALARM] 连续 {_CLOSEDLOOP_BOX['breaks']} 次 correct 提交而平台累计分"
                        f"不动(cum={getattr(res, 'cumulative_score', '?')})——核查平台积分/导出侧(引擎不暂停,仅保险丝)")
                else:
                    log(f"[engine] submit closed-loop break #{_CLOSEDLOOP_BOX['breaks']}: correct 但累计分未动"
                        f"(cum={getattr(res, 'cumulative_score', '?')})")
            st["correct"] = max(st["correct"], res.correct_flag_count)
            _mfi = getattr(res, "matched_flag_index", None)
            if _mfi is not None:
                st.setdefault("matched_idx", set()).add(_mfi)
            if res.correct:
                verdict["confirmed"].add(flag)
                if registry is not None:
                    registry[flag] = code
            if not res.correct:
                verdict["wrong"].add(flag)
                st["wrong_raw"] = st.get("wrong_raw", 0) + 1
                _wf = st.setdefault("wrong_families", set())
                if fk not in _wf:
                    _wf.add(fk); st["wrong"] += 1
                if st["wrong"] > MAX_WRONG_SUBMITS:
                    st["hc_escape"] = st.get("hc_escape", 0) + 1
                st["wrong_flags"].add(flag)
                if (st.get("wrong", 0) == 1 and st.get("correct", 0) == 0
                        and st.get("rebuilds", 0) < 2 and not st.get("rebuild_pending")):
                    st["rebuild_pending"] = True
                    log(f"[engine] {code} 首次错交 → 拒绝语义分裂:下一 attempt 重建实例重取重提(非诱饵结论)"
                        f"[rebuilds={st.get('rebuilds', 0)}/2]")
                if flag not in conf:
                    st["low_wrong"] += 1
    return verdict


def _budget_dead(st: dict) -> bool:
    return (st.get("correct", 0) == 0
            and (st.get("wrong_raw", 0) >= MAX_WRONG_SUBMITS + HC_ESCAPE_MAX
                 or (st.get("wrong", 0) >= MAX_WRONG_SUBMITS
                     and st.get("hc_escape", 0) >= HC_ESCAPE_MAX)))


def _submit_captured_budget(client, code: str, st: dict, need: int, captured: set,
                            registry: dict | None = None, lock: "threading.Lock | None" = None,
                            cand_seen: dict | None = None, local_only: set | None = None,
                            stop: "threading.Event | None" = None):
    verdict = _submit_captured(client, code, st, need, captured, registry, lock, cand_seen, local_only)
    if stop is not None and _budget_dead(st):
        stop.set()
    return verdict


def _should_reuse(st: dict, alive: bool) -> bool:
    return bool(st.get("addr")) and alive and (bool(st.get("foothold")) or bool(st.get("last_gain")))


def _attempt(client, ch, budget: "Budget", state, shared=None, registry=None, submit_lock=None, ekb=None, cand_seen=None,
             breadth_remaining=None, peers=None) -> Attempt:
    code = ch.unique_code
    need = ch.flag_count or 1
    st = state.setdefault(code, {})
    for _k, _v in (("correct", 0), ("wrong", 0), ("low_wrong", 0), ("submitted", set()),
                   ("wrong_flags", set()),
                   ("reports", []),
                   ("wrong_families", set()), ("wrong_raw", 0),
                   ("free_fix_grants", 0),
                   ("deep_harvest_grants", 0),
                   ("last_gain", False)):
        st.setdefault(_k, _v)
    revived = st.get("_attempted", False)
    if st.pop("force_replan", False):
        revived = True
        log(f"[engine] {code} hint 后强制重锚(复活轮换面祈使)")
    _rebuild_round = False
    if st.pop("rebuild_pending", False):
        st["rebuilds"] = st.get("rebuilds", 0) + 1
        _rebuild_round = True
        st["rebuild_retry_flags"] = set(st.get("wrong_flags", set()))
        if st.get("addr") or st.get("slot_held"):
            _close_with_retry(client, code)
            st["slot_held"], st["addr"], st["closed_at"] = False, None, 0
        log(f"[engine] {code} 拒绝分裂:重建实例重取重提[rebuilds={st['rebuilds']}/2]")
    st["_attempted"] = True
    if _session_dead.is_set():
        return Attempt(False, {"correct": st["correct"]}, "session-dead")
    if _stop_requested.is_set():
        return Attempt(False, {"correct": st["correct"]}, "stop-requested")
    log(f"[engine] ===== ATTEMPT {code} [{ch.difficulty}] flags={ch.flag_count} "
        f"score={ch.total_score} have={st['correct']}/{need}")
    st["diff_rank"] = _diff_norm(ch)
    st["in_attempt"] = True
    st.pop("closed_at", None)
    st["_attempt_started_at"] = time.time()
    st["_win_t0"] = time.time()

    def _end_attempt_gate() -> None:
        st["in_attempt"] = False
        if st.pop("pending_close", None):
            if _close_with_retry(client, code):
                st["slot_held"], st["addr"] = False, None
                st["closed_at"] = time.time()
                log(f"[engine] {code} pending_close 消费:attempt 收尾冲刷后关场(提交先于关场)")
    if (st.get("correct", 0) == 0 and _is_high_cost(ch, st)
            and any("_attempted" not in _s for _s in list(state.values()) if isinstance(_s, dict))):
        _hc = pacing.hungry_cap_s()
        _capped = _hungry_cap_budget(budget, now=time.time(), cap_s=_hc)
        if _capped is not budget:
            budget = _capped
            log(f"[engine] {code} 饿态 cap 收紧 → {_hc // 60}min(queue 有从未启动题;0 旗 hi 题机会成本)")
    st["_attempt_deadline"] = budget.deadline
    _alive = bool(st.get("addr")) and _addrs_alive(st["addr"])
    _reuse = _should_reuse(st, _alive)
    if not _reuse and st.get("addr"):
        _why = "僵尸实例探活全不通" if not _alive else "活但未建 foothold(P2 坏实例→换新重试;无 foothold 无损失)"
        if _close_with_retry(client, code):
            st["slot_held"] = False
            st["addr"] = None
            st["foothold"] = False
            log(f"[engine] {code} {_why} → 已 close,重开新实例")
        else:
            _reuse = True
            log(f"[engine] {code} {_why} 但 close 失败 → 暂不重开(防 max-active 槽泄漏),复用等下轮")
    if _reuse:
        addrs = st["addr"]
        log(f"[engine] {code} reuse live instance {addrs}(实例持久:接着打,不重开)")
    else:
        try:
            started = _start_with_retry(client, code)
        except TSecError as e:
            if _is_session_ended(e):
                _session_dead.set()
                log(f"[engine] {code} 平台会话已结束(already finished)→ 全局止损,停止起新题/second-wind")
                _end_attempt_gate()
                return Attempt(False, {"correct": st["correct"]}, "session-dead")
            _es = str(e).lower()
            transient = (isinstance(e, TSecConnectionError) or "max active" in _es
                         or "resource_unavailable" in _es or "another operation" in _es)
            log(f"[engine] {code} start failed{' (transient → will retry/requeue)' if transient else ''}: {e}")
            st["slot_held"] = False
            _end_attempt_gate()
            return Attempt(False, {"correct": st["correct"]}, "start-failed", deferred=transient)
        st["slot_held"] = True
        addrs = (started.container_addr if started else None) or []
        if not addrs:
            if _close_with_retry(client, code):
                st["slot_held"] = False
            _end_attempt_gate()
            return Attempt(False, {"correct": st["correct"]}, "no-target")
        addrs = _disambiguate_addrs(list(addrs))
        st["addr"] = addrs

    st["attempts"] = st.get("attempts", 0) + 1
    if len(addrs) > 1:
        _rot = (st["attempts"] - 1) % len(addrs)
        if _rot:
            addrs = addrs[_rot:] + addrs[:_rot]
    captured: set[str] = set()
    local_only: set[str] = set()
    progress: dict = {}
    any_exec_ok = False
    task = ch.description or "Find and capture all flags."
    reserved_addrs = [a for c, s in state.items() if c != code for a in (s.get("addr") or [])]
    reserved_addrs += [a for c, addrs in (peers or {}).items() if c != code for a in (addrs or [])]
    reserved_addrs += [a for c, s in state.items() if c != code for a in (s.get("ghost_addr") or [])]
    try:
        for i, addr in enumerate(addrs):
            if st["correct"] + len(confident_flags(captured, need)) >= need:
                break
            target = addr if str(addr).startswith("http") else f"http://{addr}/"
            if shared is not None:
                _scanned = getattr(shared, "_cp_scanned", None)
                if _scanned is None:
                    _scanned = set(); shared._cp_scanned = _scanned
                _h = _re.sub(r"^\w+://", "", str(addr).strip()).split("#", 1)[0].split("/", 1)[0].rpartition(":")[0].strip("[]")
                if _h and _h not in _scanned:
                    _scanned.add(_h)
                    _open = _control_plane_portscan(_h)
                    if _open:
                        _resv_ports = set()
                        for _ra in reserved_addrs:
                            _rp = _re.sub(r"^\w+://", "", str(_ra).strip()).split("#", 1)[0].split("/", 1)[0]
                            _rh, _, _rpp = _rp.rpartition(":")
                            if _rh.strip("[]") == _h and _rpp.isdigit():
                                _resv_ports.add(int(_rpp))
                        _seed = [p for p in _open if p not in _resv_ports]
                        if _seed:
                            shared.contribute(_h, _seed, [])
                            log(f"[engine] {code} control-plane portscan {_h}: {len(_seed)} open ports "
                                f"(excl {len(_resv_ports)} reserved-neighbor) → shared_recon")
                    if not getattr(shared, "_mesh_probed", False):
                        shared._mesh_probed = True
                        _mesh = _detect_mesh_sidecar()
                        if _mesh:
                            log(f"[engine] {code} ⚠ Istio sidecar 探针命中({_mesh})——执行器出站可能被 REDIRECT→本地 Envoy;"
                                f"**非-mesh 端口(如裸 :9000 php-fpm)RST 很可能是 sidecar 捕获而非靶标关闭**,别据此 ruledout 真洞。"
                                f"引擎已对本靶标自动插 ISTIO_OUTPUT RETURN 豁免(_apply_mesh_bypass,焊死无旋钮)。")
                    _apply_mesh_bypass(_h)
            db = str(Path(LOG_ROOT) / _dbdir(code) / f"t{i}.tsg.db")
            Path(db).parent.mkdir(parents=True, exist_ok=True)
            if st.get("_attempted") and set(map(str, addrs)) != set(map(str, st.get("addr") or [])):
                _pn = _purge_stale_topology(db)
                if _pn:
                    log(f"[engine] {code} 实例重建换址({st.get('addr')} → {addrs})→ 清除旧拓扑节点 {_pn} 个"
                        f"(route/deadend/私网 fact;凭据 fact 保留)")
            ws = str(Path(WS_ROOT) / _wsdir(code))
            log(f"[engine] {code} solving {target} (TSG {db})")
            st["_exec_ran"] = True
            _budget_stop = threading.Event()
            outcome, tsg = solve_challenge(
                target, task, provider=PROVIDER, model=MODEL, db_path=db,
                max_waves=budget.max_waves, concurrency=ENGINE_EXEC_CONCURRENCY,
                deadline=budget.deadline, workspace=ws,
                need_flags=need,
                shared_recon=shared,
                known_wrong=(st["wrong_flags"] - st.get("rebuild_retry_flags", set())) if _rebuild_round else st["wrong_flags"],
                known_correct=(st["correct"] > 0),
                on_wave=(lambda cap, lo=None: _submit_captured_budget(client, code, st, need, cap, registry, submit_lock, cand_seen, lo, stop=_budget_stop)),
                reserved=reserved_addrs,
                label=code,
                ekb=ekb,
                hint_fn=None,
                hint_wanted=None,
                initial_hint=None,
                high_effort=_collab_effort(ch, st.get("_exec_ran", False)),
                extra_targets=[a for a in addrs if a != addr],
                budget_stop=_budget_stop,
                revived=revived)
            try:
                captured |= outcome.captured
                local_only |= set(getattr(outcome, "local_only", None) or ())
                for k, v in (outcome.progress or {}).items():
                    progress[k] = max(progress.get(k, 0), v)
                if outcome.status != "executor_failed":
                    any_exec_ok = True
                log(f"[engine] {code} t{i} -> status={outcome.status} "
                    f"waves={outcome.waves_used} flags={len(outcome.captured)}")
            finally:
                tsg.close()
    except Exception as e:
        log(f"[engine] {code} engine error: {e!r}")

    _submit_captured(client, code, st, need, captured, registry, submit_lock, cand_seen, local_only)
    progress["correct"] = st["correct"]
    progress["need"] = need
    progress["info_gain"] = bool(st.pop("info_gain", False))
    st["foothold"] = bool(st.get("foothold")) or int(progress.get("capabilities_verified", 0) or 0) > 0 or st["correct"] > 0
    st["last_gain"] = any((_k not in ("correct", "need")) and isinstance(_v, (int, float)) and _v > 0
                          for _k, _v in progress.items())
    solved = st["correct"] >= need
    if solved:
        if _close_with_retry(client, code):
            st["slot_held"] = False
        st["addr"] = None
    elif (not _is_high_cost(ch, state)) and breadth_remaining is not None and breadth_remaining():
        if _close_with_retry(client, code):
            st["slot_held"] = False
            st["addr"] = None
            st["foothold"] = False
    exec_failed = (not solved) and (not any_exec_ok)
    log(f"[engine] {code} attempt-telemetry addrs={addrs} have={st['correct']}/{need} "
        f"captured={len(captured)} submitted={len(st['submitted'])} wrong={st['wrong']}")
    log(f"[engine] {code} attempt done: correct={st['correct']}/{need} solved={solved}"
        + (" [executor-failed: no session produced output → bounded retry, not α-drop]" if exec_failed else ""))
    _end_attempt_gate()
    return Attempt(solved, progress, "solved" if solved else ("executor-failed" if exec_failed else "unsolved"),
                   executor_failed=exec_failed)


def _hungry_cap_budget(budget, *, now: float, cap_s: int):
    dl = getattr(budget, "deadline", None)
    if dl is None or dl - now <= cap_s:
        return budget
    return budget._replace(deadline=now + cap_s)


def _is_high_cost(ch, state=None) -> bool:
    if (getattr(ch, "flag_count", 1) or 1) > 1:
        return True
    return _diff_norm(ch) == 1.0


def _is_multiflag(ch) -> bool:
    return (getattr(ch, "flag_count", 1) or 1) >= 2


def _collab_effort(ch, revived: bool) -> bool:
    if _is_multiflag(ch):
        return True
    return _diff_norm(ch) == 1.0 and bool(revived)


def _hi_quota_blocks(*, is_mf: bool, is_hi: bool, mf_open: int, hi_open: int,
                     conc: int, fresh_pending: bool, hi_stalled: bool,
                     hi_zero_grind: bool = False) -> bool:
    if not fresh_pending:
        return False
    cap_mf = 2 if hi_stalled else 1
    if is_mf:
        return mf_open >= cap_mf
    return False


def _value_weight(ch) -> float:
    d = _diff_norm(ch)
    base = 2.2 if d == 1.0 else (1.5 if d == 0.5 else 1.0)
    flags = max(1, getattr(ch, "flag_count", 1) or 1)
    return base + 0.4 * (flags - 1)


def _safe(s: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in str(s))[:40]


def _dbdir(code: str) -> str:
    return f"{_safe(code)}-{hashlib.sha256(str(code).encode()).hexdigest()[:10]}"


def _purge_stale_topology(db: str) -> int:
    import re as _re, sqlite3
    try:
        from engine.loop import _CRED_SHAPE_RX_C
    except Exception:
        _CRED_SHAPE_RX_C = None
    _priv = _re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
                        r"|192\.168\.\d{1,3}\.\d{1,3})(?:/\d{1,2})?\b")
    n = 0
    try:
        con = sqlite3.connect(db)
        con.execute("DELETE FROM nodes WHERE type IN ('route','deadend')")
        n += con.total_changes
        rows = con.execute("SELECT id, type, title FROM nodes WHERE type IN ('fact','asset','service','endpoint')").fetchall()
        for _id, _ty, _ti in rows:
            t = _ti or ""
            if _priv.search(t) and not (_CRED_SHAPE_RX_C and _CRED_SHAPE_RX_C.search(t)):
                con.execute("DELETE FROM nodes WHERE id=?", (_id,))
                n += 1
        con.commit()
        con.close()
    except sqlite3.Error:
        pass
    return n


_WS_SECRET = os.urandom(16).hex()


def _wsdir(code: str) -> str:
    return hashlib.sha256((_WS_SECRET + "|" + str(code)).encode()).hexdigest()[:24]


import re as _re


def _class_key(flag: str) -> tuple:
    prefix = flag.split("{", 1)[0].lower()
    m = _re.search(r"\{(.*)\}$", flag)
    inner = m.group(1) if m else flag
    if _re.fullmatch(r"[0-9a-f]+", inner or ""):
        charset = "hex"
    elif _re.fullmatch(r"[0-9a-f-]+", inner or ""):
        charset = "uuid"
    elif (inner or "").replace("_", "").replace("-", "").isalnum():
        charset = "alnum"
    else:
        charset = "mixed"
    return (prefix, len(inner) // 8, charset)


def _dedup_by_inner(cands):
    best: dict = {}
    for c in cands:
        inner = _flag_inner(c) or c
        cur = best.get(inner)
        if cur is None or (_flagishness(c), -len(c)) > (_flagishness(cur), -len(cur)):
            best[inner] = c
    return list(best.values())


def _diverse_order(cands) -> list:
    from collections import defaultdict, deque
    cands = _dedup_by_inner(cands)
    groups: dict = defaultdict(list)
    for c in sorted(cands, key=lambda t: (-_flagishness(t), t)):
        groups[_class_key(c)].append(c)
    queues = [deque(v) for v in groups.values()]
    queues.sort(key=lambda q: -_flagishness(q[0]))
    out = []
    while queues:
        for q in queues:
            if q:
                out.append(q.popleft())
        queues = [q for q in queues if q]
    return out


_DIFF_RANK = {
    "easy": 0.0, "e": 0.0, "low": 0.0, "简单": 0.0, "低": 0.0, "初级": 0.0,
    "medium": 0.5, "m": 0.5, "mid": 0.5, "moderate": 0.5, "中": 0.5, "中级": 0.5,
    "hard": 1.0, "h": 1.0, "high": 1.0, "difficult": 1.0, "难": 1.0, "高": 1.0, "高级": 1.0,
}


def _diff_norm(ch):
    return _DIFF_RANK.get(str(getattr(ch, "difficulty", "") or "").strip().lower())


def _score_of(ch):
    import math
    v = getattr(ch, "total_score", None)
    if v is None:
        v = getattr(ch, "score", None)
    try:
        f = float(v)
    except (TypeError, ValueError):
        return None
    return f if math.isfinite(f) else None


def _flagcount_of(ch):
    try:
        n = int(getattr(ch, "flag_count", None))
        return n if n > 0 else None
    except (TypeError, ValueError):
        return None


def _pct(vals: dict, v):
    if v is None or not vals:
        return None
    lo, hi = min(vals.values()), max(vals.values())
    return (v - lo) / ((hi - lo) or 1.0)


def order_todo(todo: list) -> list:
    if len(todo) <= 1:
        return list(todo)
    scores = {id(c): _score_of(c) for c in todo if _score_of(c) is not None}
    fcs = {id(c): _flagcount_of(c) for c in todo if _flagcount_of(c) is not None}

    def cost(c):
        fc = _flagcount_of(c)
        fc = fc if fc is not None else 1
        if _is_high_cost(c):
            return (0, -fc, -(scores.get(id(c)) or 0))
        signals = [x for x in (_diff_norm(c), _pct(scores, scores.get(id(c))),
                               _pct(fcs, fcs.get(id(c)))) if x is not None]
        if not signals:
            return (1, 0.5, 0.5)
        return (1, max(signals), sum(signals))

    return sorted(todo, key=cost)


def _secure_log_root() -> None:
    try:
        os.makedirs(LOG_ROOT, exist_ok=True)
        os.chmod(LOG_ROOT, 0o700)
    except OSError:
        pass


HEARTBEAT_INTERVAL_S = 60.0

def _start_engine_heartbeat(interval_s: float = HEARTBEAT_INTERVAL_S) -> threading.Thread:
    def _beat():
        while True:
            try:
                _rss = ""
                try:
                    with open("/proc/self/status") as _f:
                        for _ln in _f:
                            if _ln.startswith("VmRSS:"):
                                _rss = _ln.split()[1]
                                break
                except OSError:
                    pass
                Path(LOG_ROOT, "heartbeat.json").write_text(f"{time.time():.0f} {os.getpid()} {_rss}\n")
            except Exception:
                pass
            time.sleep(interval_s)
    _t = threading.Thread(target=_beat, daemon=True, name="engine-heartbeat")
    _t.start()
    return _t


def _secure_ws_root() -> None:
    import shutil
    try:
        if _ws_disk_pressure():
            shutil.rmtree(WS_ROOT, ignore_errors=True)
            log("[engine] 磁盘空闲低于水位 → 清旧 ws 保可用性(溯源让位;docker cp 仍可从容器层取证)")
        os.makedirs(WS_ROOT, exist_ok=True)
        os.chmod(WS_ROOT, 0o711)
    except OSError:
        pass


def _cleanup_ws_root() -> None:
    import shutil
    if _ws_disk_pressure():
        shutil.rmtree(WS_ROOT, ignore_errors=True)
        log("[engine] workspace 根已清(磁盘空闲低于水位,溯源让位可用性)")
    else:
        log(f"[engine] workspace 保留于 {WS_ROOT}(容器内)供溯源(docker exec/cp 取执行器 transcript/NOTES/脚本;"
            f"磁盘空闲低于 {WS_FREE_WATERMARK_BYTES // (1024 ** 3)}GB 时自动清)")


def _emit_final_summary(state: dict, todo: list, reason: str = "DONE") -> None:
    if _summary_done.is_set():
        return
    _summary_done.set()
    try:
        by_code = dict(state)
    except Exception:
        try:
            by_code = {k: state[k] for k in list(state.keys())}
        except Exception:
            by_code = {}
    total = sum((v or {}).get("correct", 0) for v in by_code.values())
    solved = sum(1 for c in todo
                 if by_code.get(getattr(c, "unique_code", None), {}).get("correct", 0) >= (getattr(c, "flag_count", 1) or 1))
    log(f"\n[engine] {reason}. correct_flags={total} solved={solved}/{len(todo)}")
    for c in sorted(todo, key=lambda x: getattr(x, "unique_code", "")):
        st = by_code.get(c.unique_code, {})
        log(f"[engine]   {c.unique_code}: correct={st.get('correct', 0)}/{c.flag_count or 1} "
            f"wrong={st.get('wrong', 0)}")


def _do_drain(state: dict, todo: list, reason: str) -> None:
    _stop_requested.set()
    log(f"[engine] 收到停机信号 → {reason}:停开新题、输出终局汇总后退出")
    _emit_final_summary(state, todo, reason=reason)
    try:
        _archive_tsg()
    except Exception:
        pass


def _archive_tsg() -> None:
    import shutil
    if not ARCHIVE_ROOT or os.path.abspath(ARCHIVE_ROOT) == os.path.abspath(LOG_ROOT):
        return
    try:
        os.makedirs(ARCHIVE_ROOT, exist_ok=True)
        for name in os.listdir(LOG_ROOT):
            src = os.path.join(LOG_ROOT, name)
            dst = os.path.join(ARCHIVE_ROOT, name)
            if os.path.isdir(src):
                shutil.copytree(src, dst, dirs_exist_ok=True)
            elif name.startswith("engagement.ekb"):
                shutil.copy2(src, dst)
        log(f"[engine] TSG + EKB 已留档到 {ARCHIVE_ROOT}")
    except OSError as e:
        log(f"[engine] TSG/EKB 留档失败(不影响判定): {e!r}")


class SlotLedger:

    def __init__(self, max_active: int, max_high_cost: int = 1, clock=time.time):
        self._slots: dict = {}
        self._max_active = max(1, max_active)
        self._max_high_cost = max(1, max_high_cost)
        self._clock = clock
        self._lock = threading.Lock()

    def occupy(self, code: str, is_hi: bool) -> None:
        with self._lock:
            s = self._slots.get(code)
            if s is None:
                self._slots[code] = {"is_hi": bool(is_hi), "opened_at": self._clock(),
                                     "last_work_at": self._clock(), "working": True}
            else:
                s["is_hi"] = bool(is_hi); s["working"] = True; s["last_work_at"] = self._clock()

    def release(self, code: str) -> None:
        with self._lock:
            self._slots.pop(code, None)

    def reconcile(self, live_codes) -> int:
        live = set(live_codes)
        with self._lock:
            ghosts = [c for c in list(self._slots) if c not in live]
            for c in ghosts:
                self._slots.pop(c, None)
            return len(ghosts)

    def set_working(self, code: str, working: bool) -> None:
        with self._lock:
            s = self._slots.get(code)
            if s is not None:
                s["working"] = bool(working)
                if working:
                    s["last_work_at"] = self._clock()

    def held(self, code: str) -> bool:
        with self._lock:
            return code in self._slots

    def count(self) -> int:
        with self._lock:
            return len(self._slots)

    def count_high(self) -> int:
        with self._lock:
            return sum(1 for s in self._slots.values() if s["is_hi"])

    def can_start(self, code: str, is_hi: bool, fresh_pending: bool = True) -> bool:
        with self._lock:
            if code in self._slots:
                return True
            if len(self._slots) >= self._max_active:
                return False
            hi_cap = self._max_high_cost if fresh_pending else self._max_active
            if is_hi and sum(1 for s in self._slots.values() if s["is_hi"]) >= hi_cap:
                return False
            return True

    def has_parked(self, max_idle_s: float) -> list:
        with self._lock:
            now = self._clock()
            return [c for c, s in self._slots.items()
                    if not s["working"] and (now - s["last_work_at"]) >= max_idle_s]


def main(argv: list[str]) -> int:
    _TASK_DESC = os.environ.get("HXCTF_TASK_DESC", "")
    _secure_log_root()
    _start_engine_heartbeat()
    _secure_ws_root()
    _session_dead.clear()
    _stop_requested.clear(); _summary_done.clear()
    try:
        ekb = EKB(str(Path(LOG_ROOT) / "engagement.ekb.db"))
    except Exception as _ee:
        log(f"[engine] EKB init non-fatal, 跑分继续无 EKB: {_ee!r}")
        ekb = None
    token, base = os.environ.get("BENCHMARK_TOKEN", ""), os.environ.get("BENCHMARK_BASE_URL", "")
    if not token or not base:
        sys.exit("BENCHMARK_TOKEN / BENCHMARK_BASE_URL 未设置")
    _pa = _resolve_active()
    _prov = _pa.get("provider", "deepseek")
    if not _resolve_key(_prov, _pa.get("key", "")):
        _env = _PROVIDERS.get(_prov, ("", "SOLVER_API_KEY"))[1] or "HXCTF_LLM_API_KEY"
        sys.exit(f"LLM API key 未设置(provider={_prov}:请设 {_env} 或通用 HXCTF_LLM_API_KEY)")
    try:
        _eff = _exec_tuning().get("MAX_THINKING_TOKENS")
        _ron, _rinfo = _probe_reasoning()
        log(f"[engine][reasoning-selftest] reasoning budget 生效={_eff}(committed-on,不靠 ENV)  {_rinfo}")
        if not _ron:
            log("[engine][reasoning-selftest] ⚠ 端点未返回 thinking → 本轮 reasoning 很可能=0(云端历史病灶重演);"
                "若在云托管,请立刻查:MAX_THINKING_TOKENS 是否注入 / 网关是否透传 thinking。跑分继续(自检不阻断)。")
    except Exception as _pe:
        log(f"[engine][reasoning-selftest] 探针异常(不阻断跑分): {_pe.__class__.__name__}")
    try:
        from engine.providers import role_summary as _role_summary
        log(_role_summary())
        try:
            from engine.precheck import run_precheck
            from engine.providers import resolve_role, ROLES as _ROLES
            _probes = run_precheck(_ACTIVE, {r: resolve_role(r) for r in _ROLES})
            from engine.providers import role_configured, disable_role_runtime, resolve_role as _rr4
            _probe_map = dict(_probes or [])
            for _role in ("decide", "execute_high", "judge", "small"):
                if not role_configured(_role):
                    continue
                _ep_ok = _probe_map.get(f"{_role}-role", False)
                _sp = _rr4(_role)
                _reason_ok = _probe_map.get(f"reasoning-{_sp.get('provider')}:{_sp.get('model')}", False)
                if not _ep_ok and not _reason_ok:
                    disable_role_runtime(_role, f"precheck {_role}-role probe failed")
                    log(f"[engine] {_role.upper()} override 探活失败 → 已自愈停用(主模型接管;F4)")
                elif not _ep_ok and _reason_ok:
                    log(f"[engine] {_role.upper()} 端点轻探假 WARN 但 reasoning 穿透 PASS → 保留 override(F4 救济)")
        except Exception as _pe:
            log(f"[PRECHECK] WARN: precheck itself failed: {_pe!r}")
    except Exception:
        pass
    codes = [c for c in argv if c.strip()]
    try:
        cm = TSecBenchmark(base_url=base, token=token)
    except VpnCheckError as e:
        sys.exit(f"[engine] VPN 预检失败: {e}")

    with cm as client:
        allch = call_with_timeout(client.list_challenges, timeout=PLATFORM_CALL_TIMEOUT_S)
        pacing.PACING.start(len(allch))
        for c in allch:
            if c.container_status in ("available", "pending", "stop_pending"):
                try:
                    call_with_timeout(client.close_challenge, c.unique_code, timeout=PLATFORM_CALL_TIMEOUT_S)
                    log(f"[engine] cleanup closed stale {c.unique_code}")
                except (TSecError, CallTimeout):
                    pass
        if any(c.container_status != "stopped" for c in allch):
            allch = call_with_timeout(client.list_challenges, timeout=PLATFORM_CALL_TIMEOUT_S)
        todo = [c for c in allch if (not codes or c.unique_code in codes) and not c.is_completed]
        todo = order_todo(todo)
        log(f"[engine] {len(allch)} total; running {len(todo)} ({codes or 'ALL'}); "
            f"challenge_conc={CHALLENGE_CONCURRENCY} model={MODEL}")
        _deep = sum(1 for c in todo if (_flagcount_of(c) or 1) >= 2)
        log(f"[engine] schedule (value-depth priority: {_deep} multi-stage target(s) first, breadth-first sweep in parallel): " +
            ", ".join(f"{c.unique_code}[{getattr(c,'difficulty','?')}/{_score_of(c)}/{_flagcount_of(c) or 1}f]" for c in todo[:12]) +
            (" …" if len(todo) > 12 else ""))

        state: dict = {}
        import signal as _signal
        def _sig_drain(_num, _frame):
            try:
                _do_drain(state, todo, reason=f"DRAIN(signal {_num})")
            finally:
                os._exit(0)
        try:
            _signal.signal(_signal.SIGTERM, _sig_drain)
            _signal.signal(_signal.SIGINT, _sig_drain)
        except (ValueError, OSError):
            log("[engine] 停机处理器注册跳过(非主线程/无信号支持);外部停止将无优雅汇总")
        flag_registry: dict = {}
        cand_inner_seen: dict = {}
        submit_lock = threading.Lock()

        def _close_on_abandon(ch) -> None:
            st = state.setdefault(ch.unique_code, {})
            if st.get("in_attempt"):
                _dl = st.get("_attempt_deadline") or (st.get("_attempt_started_at", 0) + pacing.max_attempt_cap_s())
                if time.time() > _dl + pacing.max_attempt_cap_s():
                    log(f"[engine] {ch.unique_code} close 延迟超界(超本题预算+50%宽限,attempt 疑似泄漏)→ 强制关保槽(弃 flush)")
                else:
                    st["pending_close"] = True
                    log(f"[engine] {ch.unique_code} close 延迟:attempt 在跑(待 final-flush 后关,提交先于关场)")
                    return
            if _close_with_retry(client, ch.unique_code):
                st["slot_held"] = False
                st["ghost_addr"] = list(st.get("addr") or [])
                st["addr"] = None
                st.pop("needs_close", None)
                st["closed_at"] = time.time()
                log(f"[engine] {ch.unique_code} closed out-of-band after scheduler abandon/drop (freed platform slot)")
            else:
                st["needs_close"] = True
                log(f"[engine] {ch.unique_code} close failed on abandon/drop → 标记 needs_close(保留 addr;on_wedge 重试回收,防孤儿占 max-active)")

        _ch_by_code = {c.unique_code: c for c in todo}
        def _occupy(ch) -> None:
            state.setdefault(ch.unique_code, {})["slot_held"] = True
        def _open_instances() -> int:
            n = 0
            for _code, _s in list(state.items()):
                if not _s.get("slot_held"):
                    continue
                _c = _ch_by_code.get(_code)
                if _c is not None and _terminal_orphan(_s, _c.flag_count or 1):
                    continue
                n += 1
            return n
        def _open_count(pred) -> int:
            n = 0
            for _code, _s in list(state.items()):
                if not _s.get("slot_held"):
                    continue
                _c = _ch_by_code.get(_code)
                if _c is None or _terminal_orphan(_s, _c.flag_count or 1):
                    continue
                if pred(_c):
                    n += 1
            return n
        def _hi_open() -> int:
            return _open_count(_is_multiflag)
        def _hi_zero_grind() -> bool:
            codes = [_k for _k in state if state[_k].get("slot_held") and _k in _ch_by_code
                     and _is_high_cost(_ch_by_code[_k])]
            return bool(codes) and all(state[_k].get("correct", 0) == 0 for _k in codes)
        def _can_start(ch, fresh_pending: bool = True, hi_stalled: bool = False) -> bool:
            code = ch.unique_code
            if state.get(code, {}).get("slot_held"):
                return True
            if _open_instances() >= CHALLENGE_CONCURRENCY:
                return False
            if _hi_quota_blocks(is_mf=_is_multiflag(ch), is_hi=_is_high_cost(ch, state),
                                mf_open=_hi_open(), hi_open=_open_count(lambda c: _is_high_cost(c, state)),
                                conc=CHALLENGE_CONCURRENCY, fresh_pending=fresh_pending, hi_stalled=hi_stalled,
                                hi_zero_grind=_hi_zero_grind()):
                return False
            return True

        def _never_started_exists() -> bool:
            return any("_attempted" not in state.get(t.unique_code, {}) for t in todo)

        def _worth_retry(ch) -> bool:
            st = state.get(ch.unique_code, {})
            if _terminal_orphan(st, ch.flag_count or 1):
                return False
            if st.get("correct", 0) == 0 and st.get("_attempted") and _never_started_exists():
                return False
            return True

        def _reconcile_slots() -> int:
            if _session_dead.is_set():
                return 0
            try:
                live = {c.unique_code: c.container_status
                        for c in call_with_timeout(client.list_challenges, timeout=PLATFORM_CALL_TIMEOUT_S)}
            except Exception as e:
                log(f"[engine] 准入 wedge 对账 list_challenges 失败(跳过,不回收): {e!r}")
                return 0
            freed = 0
            for _code, _s in list(state.items()):
                if not _s.get("slot_held"):
                    continue
                _status = live.get(_code, "stopped")
                if _status == "stopped":
                    _s["slot_held"] = False
                    _s["addr"] = None
                    freed += 1
                    continue
                _ch = _ch_by_code.get(_code)
                _need = (_ch.flag_count or 1) if _ch is not None else 1
                _terminal = (_s.get("correct", 0) >= _need) or _s.get("needs_close")
                if _terminal and _status == "stop_pending":
                    _s["slot_held"] = False
                    _s["ghost_addr"] = list(_s.get("addr") or [])
                    _s["addr"] = None
                    _s.pop("needs_close", None)
                    freed += 1
                    log(f"[engine] {_code} 终态题平台 stop_pending(已受理关闭)→ 回收槽计数(不等 close 确认/stopped;修 34937 掉题幽灵死空窗)")
                    continue
                if _terminal and _close_with_retry(client, _code):
                    _s["slot_held"] = False
                    _s["addr"] = None
                    _s.pop("needs_close", None)
                    freed += 1
                    log(f"[engine] {_code} 终态孤儿(解出/判死)close 曾失败仍占槽 → wedge 重试 close 成功,回收槽")
            if freed:
                log(f"[engine] 准入 wedge → 平台真值对账:回收 {freed} 个占用槽(stopped 幽灵 / 终态孤儿 close 失败)")
            return freed

        sched = Scheduler(concurrency=CHALLENGE_CONCURRENCY, log=log,
                          per_attempt_cap_s=PER_ATTEMPT_CAP_S,
                          is_high_cost=lambda ch: _is_high_cost(ch, state),
                          is_breadth=lambda ch: not _is_multiflag(ch),
                          can_start=_can_start, hi_open=_hi_open,
                          on_wedge=_reconcile_slots,
                          on_dispatch=_occupy,
                          worth_backfill=_worth_retry,
                          value_weight=_value_weight, on_abandon=_close_on_abandon)
        log(f"[engine] no global deadline (platform session bounds it); per-attempt cap = base×value_weight"
            f"(difficulty/score); high-cost concurrent ≤{sched.max_high_cost} + revive")
        shared = SharedReconCache()
        _last_recon = [0.0]

        def _reconcile_progress() -> None:
            if time.time() - _last_recon[0] < 300 or _session_dead.is_set():
                return
            _last_recon[0] = time.time()
            try:
                live = {c.unique_code: c for c in
                        call_with_timeout(client.list_challenges, timeout=PLATFORM_CALL_TIMEOUT_S)}
                for _code, _c in live.items():
                    _st = state.setdefault(_code, {})
                    _cf = int(getattr(_c, "correct_flag_count", 0) or 0)
                    if _cf > _st.get("correct", 0):
                        log(f"[engine] 对账:{_code} 平台 correct={_cf} > 本地 {_st.get('correct', 0)} → 采纳真值(漏交/滞后修复)")
                        _st["correct"] = _cf
            except Exception as _e:
                log(f"[engine] 进度对账 non-fatal: {_e!r}")

        _peers = {c.unique_code: list(c.container_addr or []) for c in allch if getattr(c, "container_addr", None)}
        remaining = list(todo)
        sweep = 0
        _zero_gain_streak = 0
        while True:
            if _session_dead.is_set():
                log("[engine] 平台会话已结束 → 跳过剩余 second-wind(避免空转 already-finished 提交)")
                break
            if _stop_requested.is_set():
                log("[engine] 收到停机信号 → 停止 second-wind")
                break
            _rem_s = pacing.PACING.session_len_s() - pacing.PACING.elapsed_s()
            if _rem_s < 10 * 60:
                log(f"[engine] second-wind 收工:假设会话剩余 {_rem_s/60:.0f}min < 10min(时间尽;平台侧若仍活,"
                    f"下轮 ladder 放宽后由 InvalidState 真值收口)")
                break
            _sw_cap = SECOND_WIND_MAX if pacing.PACING.elapsed_s() < 3600 else 120
            if sweep >= _sw_cap:
                log(f"[engine] second-wind sweep 上限 {sweep}/{_sw_cap} 轮"
                    f"({'短会话轮次制' if _sw_cap == SECOND_WIND_MAX else 'sanity(时钟异常防护)'};剩余 {_rem_s/60:.0f}min)")
                break
            if sweep > 0:
                _reconcile_progress()
                remaining = [c for c in remaining if _worth_retry(c)]
                if not remaining:
                    break
                remaining.sort(key=lambda c: (state.get(c.unique_code, {}).get("attempts", 0) > 0,
                                              -((c.flag_count or 1) - state.get(c.unique_code, {}).get("correct", 0))))
                log(f"[engine] second-wind sweep {sweep}: {len(remaining)} unsolved remain → retry "
                    f"(use leftover session time; multi-flag partials first)")
            before = sum(v.get("correct", 0) for v in state.values())
            sw = Scheduler(concurrency=CHALLENGE_CONCURRENCY, log=log,
                           per_attempt_cap_s=PER_ATTEMPT_CAP_S,
                           is_high_cost=lambda ch: _is_high_cost(ch, state),
                           is_breadth=lambda ch: not _is_multiflag(ch),
                           can_start=_can_start, hi_open=_hi_open,
                           on_wedge=_reconcile_slots,
                           on_dispatch=_occupy,
                           worth_backfill=_worth_retry,
                           value_weight=_value_weight, on_abandon=_close_on_abandon)
            _breadth_left = lambda: any(state.get(c.unique_code, {}).get("attempts", 0) == 0 for c in todo)
            sw.run(remaining, lambda ch, budget: _attempt(client, ch, budget, state, shared, flag_registry, submit_lock, ekb, cand_inner_seen,
                                                          breadth_remaining=_breadth_left, peers=_peers))
            gained = sum(v.get("correct", 0) for v in state.values()) - before
            sweep += 1
            if sweep > 0 and gained == 0:
                _zero_gain_streak += 1
                log(f"[engine] second-wind sweep {sweep} gained 0(连 {_zero_gain_streak} 轮;继续扫——"
                    f"假设会话还剩 {(pacing.PACING.session_len_s() - pacing.PACING.elapsed_s())/60:.0f}min)")
            elif gained > 0:
                _zero_gain_streak = 0

        if (not _session_dead.is_set() and not _stop_requested.is_set()
                and pacing.PACING.in_endgame()):
            _reconcile_progress()
            _eg = [c for c in todo
                   if state.get(c.unique_code, {}).get("correct", 0) < (c.flag_count or 1)
                   and not state.get(c.unique_code, {}).get("_endgame_done")]
            _eg.sort(key=lambda c: (not (0 < state.get(c.unique_code, {}).get("correct", 0) < (c.flag_count or 1)),
                                    state.get(c.unique_code, {}).get("correct", 0) == 0,
                                    -((c.flag_count or 1) - state.get(c.unique_code, {}).get("correct", 0))))
            if _eg:
                log(f"[engine] 尾段回流:endgame 窗({pacing.PACING.endgame_window_s() // 60}min)内 "
                    f"{len(_eg)} 未解题各保底一窗(多旗缺口优先)")
                for _c in _eg:
                    state.setdefault(_c.unique_code, {})["_endgame_done"] = True
                sw2 = Scheduler(concurrency=CHALLENGE_CONCURRENCY, log=log,
                                per_attempt_cap_s=PER_ATTEMPT_CAP_S,
                                is_high_cost=lambda ch: _is_high_cost(ch, state),
                                is_breadth=lambda ch: not _is_multiflag(ch),
                                on_wedge=_reconcile_slots, on_dispatch=_occupy, worth_backfill=_worth_retry,
                                on_abandon=_close_on_abandon)
                sw2.run(_eg, lambda ch, budget: _attempt(client, ch, budget, state, shared, flag_registry,
                                                         submit_lock, ekb, cand_inner_seen,
                                                         breadth_remaining=_breadth_left, peers=_peers))

        for _code, _st in list(state.items()):
            if _st.get("addr") or _st.get("slot_held"):
                if _close_with_retry(client, _code):
                    _st["slot_held"] = False
                _st["addr"] = None
        _emit_final_summary(state, todo, reason="DONE")
    if ekb is not None:
        try:
            ekb.close()
        except Exception:
            pass
    _archive_tsg()
    _cleanup_ws_root()
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
