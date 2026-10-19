from __future__ import annotations

import json
import os
import urllib.request


def _probe_endpoint(base_url: str, key: str, model: str, timeout: float = 20.0) -> str:
    import time as _t

    def _once() -> str:
        try:
            req = urllib.request.Request(
                f"{base_url.rstrip('/')}/v1/messages",
                data=json.dumps({"model": model, "max_tokens": 768,
                                 "thinking": {"type": "enabled", "budget_tokens": 512},
                                 "messages": [{"role": "user", "content": "hi"}]}).encode(),
                headers={"content-type": "application/json", "x-api-key": key,
                         "authorization": "Bearer " + key,
                         "anthropic-version": "2023-06-01"})
            with urllib.request.urlopen(req, timeout=timeout) as r:
                return "PASS" if r.status == 200 else f"WARN:http{r.status}"
        except Exception as e:
            return f"WARN:{type(e).__name__}:{str(e)[:80]}"
    for attempt in range(3):
        r = _once()
        if not (r.startswith("WARN:URLError") or r.startswith("WARN:timeout")):
            return r
        if attempt < 2:
            _t.sleep(2.0 * (attempt + 1))
    return r + "(3 attempts)"


def run_precheck(active: dict, roles: dict) -> list:
    from engine.providers import (glm_key_pool, PROVIDERS, probe_reasoning,
                                  egress_apply, load_egress_profile, resolve_egress)
    _entry = PROVIDERS.get(active.get("provider", ""), ("", ""))
    active = {"provider": active.get("provider", ""), "model": active.get("model", ""),
              "base_url": active.get("base_url") or _entry[0],
              "key": active.get("key") or os.environ.get(_entry[1], "") if len(_entry) > 1 else active.get("key", "")}
    lines, warns, probes = [], 0, []
    try:
        _eprof = load_egress_profile(resolve_egress())
    except Exception:
        _eprof = {}

    def _egr(url: str) -> str:
        try:
            return egress_apply(url, _eprof) if url else url
        except Exception:
            return url

    def mark(tag, msg):
        nonlocal warns
        bad = msg != "PASS"
        warns += bad
        probes.append((tag, not bad))
        lines.append(f"[PRECHECK] [{'WARN' if bad else 'PASS'}] {tag}: {msg}")

    def _base_of(spec):
        _e = PROVIDERS.get(spec.get("provider", ""), ("",))
        return spec.get("base_url") or (_e[0] if _e else "")

    mark("execute-endpoint", _probe_endpoint(_egr(active.get("base_url", "")),
                                             active.get("key", ""), active.get("model", "")))
    _glm_present = (active.get("provider") == "glm")
    for _role in ("decide", "execute_high", "judge", "small"):
        _s = roles.get(_role) or {}
        if not _s:
            continue
        _over = _s.get("provider") != active.get("provider") or _s.get("model") != active.get("model")
        if not _over:
            mark(f"{_role}-role", "PASS")
            continue
        if _role == "small":
            mark("small-role", _probe_endpoint(_egr(active.get("base_url", "")), active.get("key", ""), _s.get("model", "")))
            continue
        if _s.get("provider") == "glm":
            _glm_present = True
        mark(f"{_role}-role", _probe_endpoint(_egr(_base_of(_s)), _s.get("key", ""), _s.get("model", "")))
    if _glm_present:
        pool = glm_key_pool()
        lines.append(f"[PRECHECK] glm-key-pool: {len(pool)} key(s)(逐 key 探测如下)")
        _glm_base = _egr(PROVIDERS.get("glm", ("https://open.bigmodel.cn/api/anthropic",))[0])
        for i, k in enumerate(pool):
            mark(f"glm-key-{i+1}", _probe_endpoint(_glm_base, k, "glm-5.3-flash"))
    mark("execute-key", "PASS" if active.get("key") else "WARN:empty")
    _seen_models = set()
    for _spec in [active] + [roles.get(r) or {} for r in ("decide", "execute_high", "judge", "small")]:
        _p, _m, _k = _spec.get("provider"), _spec.get("model"), _spec.get("key")
        if not (_p and _m) or (_p, _m) in _seen_models:
            continue
        _seen_models.add((_p, _m))
        try:
            _on, _info = probe_reasoning(_p, _m, api_key=_k)
            bad = not _on
            warns += bad
            probes.append((f"reasoning-{_p}:{_m}", _on))
            lines.append(f"[PRECHECK] [{'WARN' if bad else 'PASS'}] reasoning-{_p}:{_m}: "
                         f"{'thinking ON(穿透)' if _on else 'thinking OFF!(网关可能剥了 thinking)'}")
        except Exception as _re:
            lines.append(f"[PRECHECK] [INFO] reasoning-{_p}:{_m} 探针异常(不阻断): {_re!r}")
    try:
        from engine.providers import failover_candidates
        _cands = failover_candidates()
        if not _cands:
            lines.append("[PRECHECK] [INFO] failover-chain: 无候选 key 在场(单厂部署;"
                         "注入 GLM_API_KEYS 即获得上游故障接棒链)")
        for _s in _cands:
            mark(f"failover-{_s['provider']}",
                 _probe_endpoint(_s["base_url"], _s["api_key"], _s["model"]))
    except Exception as _fe:
        lines.append(f"[PRECHECK] [INFO] failover-chain non-fatal: {_fe!r}")
    try:
        from engine import run_bench as _RB
        _RB._start_engine_heartbeat()
        mark("heartbeat", "PASS")
    except Exception as e:
        mark("heartbeat", f"WARN:{e!r}")
    mark("platform-cred", "PASS" if (os.environ.get("BENCHMARK_TOKEN") and os.environ.get("BENCHMARK_BASE_URL"))
         else "WARN:missing (finding 线为正常)")
    print("\n".join(lines))
    print(f"[PRECHECK] ==== SUMMARY: {'ALL PASS' if warns == 0 else f'{warns} WARN(ING) — 见上方 WARN 项'} ====")
    return probes
