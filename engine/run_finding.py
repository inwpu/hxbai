from __future__ import annotations

import ipaddress
import os
import socket
import sys
from pathlib import Path
from urllib.parse import urlparse

from engine.loop import solve_challenge
from engine.oob import OOBListener
from engine.profile import FindingLiveProfile

LOG_ROOT = os.environ.get("HXCTF_LOG_ROOT", "/var/lib/hxctf/finding")
PROVIDER, MODEL = "deepseek", "deepseek-flash"


def log(m: str) -> None:
    sys.stdout.write(m + "\n"); sys.stdout.flush()


def _safe(s: str) -> str:
    return "".join(c if c.isalnum() else "_" for c in str(s))[:40]


def _target_ip(url: str) -> str | None:
    try:
        host = urlparse(url if "//" in url else "http://" + url).hostname
        return socket.gethostbyname(host) if host else None
    except OSError:
        return None


def _in_scope_fn(target_ip: str | None):
    def ok(ip: str) -> bool:
        try:
            if ipaddress.ip_address(ip).is_loopback:
                return False
        except ValueError:
            return False
        return bool(target_ip) and ip == target_ip
    return ok


def _secure_log_root() -> None:
    try:
        os.makedirs(LOG_ROOT, exist_ok=True)
        os.chmod(LOG_ROOT, 0o700)
    except OSError:
        pass


def main(argv: list[str]) -> int:
    _secure_log_root()
    from engine.providers import resolve_active as _ra, resolve_key as _rk, PROVIDERS as _PV
    _pa = _ra(); _pr = _pa.get("provider", "deepseek")
    if not _rk(_pr, _pa.get("key", "")):
        _ev = _PV.get(_pr, ("", "SOLVER_API_KEY"))[1] or "HXCTF_LLM_API_KEY"
        sys.exit(f"LLM API key 未设置(provider={_pr}:请设 {_ev} 或通用 HXCTF_LLM_API_KEY)")
    targets = [a for a in argv if a.strip()]
    if not targets:
        sys.exit("用法: finding-live <target-url> [more...]")
    adv = os.environ.get("HXCTF_OOB_HOST", "")
    use_oob = bool(adv) and not _is_loopback(adv)
    oob = OOBListener(advertise_host=adv) if use_oob else None
    if oob:
        log(f"[finding] OOB listener on :{oob.port} (advertise {oob.advertise_host}) — executor-independent L1")
    else:
        log("[finding] HXCTF_OOB_HOST 未设或为回环 → OOB 关闭,用 in-band L1(靶标可路由到引擎时设它以启用 OOB)")
    extra_scope = [s.strip() for s in os.environ.get("HXCTF_SCOPE", "").split(",") if s.strip()]
    if extra_scope:
        log(f"[finding] HXCTF_SCOPE 追加授权面: {extra_scope}")

    def _protocol_probe(url: str) -> dict:
        import urllib.request, ssl
        info = {"scheme": "http", "banner": "", "status": 0}
        try:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False; ctx.verify_mode = ssl.CERT_NONE
            req = urllib.request.Request(url, method="HEAD")
            with urllib.request.urlopen(req, timeout=5, context=ctx) as resp:
                info["scheme"] = "https" if resp.url.startswith("https") else "http"
                info["status"] = resp.status
                info["banner"] = resp.headers.get("Server", "") or resp.headers.get("X-Powered-By", "")
        except Exception:
            pass
        return info

    from engine.logic_oracle import extract_spec_assertions, build_protection_matrix, metamorphic_auth_test
    total = 0
    try:
        from engine.bayesearch import BayesTargeter
        _targets = [t if str(t).startswith("http") else f"http://{t}/" for t in targets]
        _bt = BayesTargeter({t: 1.0 / len(_targets) for t in _targets}, {})
        for target in _bt.rank():
            t = target
            prof = FindingLiveProfile(need_findings=None, oob=oob,
                                      in_scope=_in_scope_fn(_target_ip(target)) if oob else None)
            db = str(Path(LOG_ROOT) / _safe(target) / "finding.tsg.db")
            Path(db).parent.mkdir(parents=True, exist_ok=True)
            _ws_root = Path(os.environ.get("HXCTF_WS_ROOT", "/var/lib/hxctf/ws"))
            ws = str(_ws_root / "finding" / _safe(target))
            Path(ws).mkdir(parents=True, exist_ok=True)
            try:
                _ws_root.chmod(0o711)
                (_ws_root / "finding").chmod(0o711)
            except OSError:
                pass
            log(f"[finding] hunting {target} (TSG {db})")
            outcome, tsg = solve_challenge(
                target, (os.environ.get("HXCTF_FINDING_TASK")
                         or os.environ.get("HXCTF_TASK_DESC")
                         or "Assess this authorized target for security vulnerabilities."),
                provider=PROVIDER, model=MODEL, db_path=db, profile=prof,
                workspace=ws, max_waves=16, patience=6,
                authorized=extra_scope)
            _bt.update(target, positive=bool(outcome and outcome.captured))
            try:
                claims = prof.summary(_LoopView(tsg))["confirmed_findings"]
                log(f"[finding] {target} -> status={outcome.status} confirmed_vulns={len(claims)}")
                for c in claims:
                    log(f"[finding]   [{c['severity']}] {c['vulnclass']} ({c.get('cwe')}) — {c['summary']}")
                total += len(claims)
                try:
                    from engine.seqtest import bh_fdr_control
                    import json as _j
                    _conf = [c for c in claims if c.get("verified")]
                    if len(_conf) >= 2:
                        _pvs = []
                        for c in _conf:
                            _rm = tsg.q1("SELECT risk_meta FROM findings WHERE summary=? AND verified=1",
                                         (c.get("summary", ""),))
                            _votes = []
                            if _rm and _rm["risk_meta"]:
                                _votes = (_j.loads(_rm["risk_meta"]).get("votes") or [])
                            _pvs.append(sum(1 for v, _ in _votes if v != "CONFIRMED") / max(1, len(_votes))
                                        if _votes else 0.5)
                        _keep = set(bh_fdr_control(_pvs, alpha=0.20))
                        for i, c in enumerate(_conf):
                            if i not in _keep:
                                tsg.conn.execute("UPDATE findings SET verified=0, status='candidate', "
                                                 "tier='low-capped' WHERE summary=?", (c.get("summary", ""),))
                                tsg.conn.commit()
                                log(f"[finding] BH-FDR 降级(q>0.20): {c.get('vulnclass')} — {c.get('summary', '')[:60]}")
                        total -= (len(_conf) - len(_keep))
                except Exception as _fdr_e:
                    log(f"[finding] BH-FDR non-fatal: {_fdr_e!r}")
                try:
                    _n = _dump_findings_jsonl(tsg, target, LOG_ROOT)
                    log(f"[finding] {target}: {_n} claims -> {Path(LOG_ROOT) / 'findings.jsonl'}")
                except Exception as _jl_e:
                    log(f"[finding] findings.jsonl non-fatal: {_jl_e!r}")
            finally:
                tsg.close()
        log(f"\n[finding] DONE. confirmed vuln claims={total}")
    finally:
        if oob:
            oob.stop()
    return 0


def _dump_findings_jsonl(tsg, target: str, log_root: str) -> int:
    import json as _j
    from pathlib import Path as _P
    jl = _P(log_root) / "findings.jsonl"
    rows = [{**dict(zip(("id", "vulnclass", "cwe", "severity", "status", "verified", "summary"), r)),
             "target": target}
            for r in tsg.conn.execute(
                "SELECT id, vulnclass, cwe, severity, status, verified, summary FROM findings")]
    old: list = []
    if jl.exists():
        with open(jl, encoding="utf-8") as f:
            old = [l for l in f if l.strip() and _j.loads(l).get("target") != target]
    with open(jl, "w", encoding="utf-8") as f:
        f.writelines(old + [_j.dumps(r, ensure_ascii=False) + "\n" for r in rows])
    return len(rows)


def _is_loopback(host: str) -> bool:
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return host in ("localhost", "")


class _LoopView:
    def __init__(self, tsg): self.tsg = tsg


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
