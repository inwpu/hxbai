from __future__ import annotations

import json
import os
import sys
import threading
import time

PROVIDERS: dict[str, tuple[str, str]] = {
    "glm":        ("https://open.bigmodel.cn/api/anthropic",         "GLM_API_KEY"),
    "glm-api":    ("http://127.0.0.1:0/anthropic",                  "GLM_API_KEY"),
    "deepseek":   ("https://api.deepseek.com/anthropic",             "SOLVER_API_KEY"),
    "claude":     ("https://api.anthropic.com",                      "ANTHROPIC_API_KEY"),
    "kimi":       ("https://api.moonshot.cn/anthropic",              "KIMI_API_KEY"),
    "kimi2":      ("https://api.kimi.com/anthropic",                 "KIMI_API_KEY"),
    "siliconflow":("https://api.siliconflow.cn/anthropic",           "SILICONFLOW_API_KEY"),
    "hunyuan":    ("https://api.hunyuan.cloud.tencent.com/anthropic","HUNYUAN_API_KEY"),
    "tokenhub":   ("https://tokenhub.tencentmaas.com",              "TOKENHUB_API_KEY"),
    "volcengine": ("https://ark.cn-beijing.volces.com/api/anthropic","VOLCENGINE_API_KEY"),
    "minimax":    ("https://api.minimaxi.com/anthropic",            "MINIMAX_API_KEY"),
    "stepfun":    ("https://api.stepfun.com",                       "STEPFUN_API_KEY"),
    "mimo":       ("https://api.xiaomimimo.com/anthropic",          "MIMO_API_KEY"),
    "spark":      ("https://spark-api-open.xf-yun.com",             "SPARK_API_KEY"),
    "lingyi":     ("https://api.lingyiwanwu.com",                   "LINGYI_API_KEY"),
    "qianfan":    ("https://qianfan.baidubce.com/anthropic",        "QIANFAN_API_KEY"),
}
CUSTOM_KEY_ENV = "CUSTOM_API_KEY"

_OPENAI_COMPAT: dict[str, str] = {
    "glm-api": "https://open.bigmodel.cn/api/paas/v4",
}

_DEFAULTS = {"provider": "deepseek", "model": "deepseek-flash", "egress": "direct"}
_PROVIDER_DEFAULT_MODELS = {"glm": "glm-5.3", "deepseek": "deepseek-flash"}

_DEFAULT_PROFILE_DIR = os.path.join(os.path.dirname(__file__), "profiles")


def _profile_dir() -> str:
    return os.environ.get("HXCTF_LLM_PROFILE_DIR", "").strip() or _DEFAULT_PROFILE_DIR

_HYGIENE = {
    "CLAUDE_CODE_DISABLE_UNKNOWN_MODEL_WINDOW_ENFORCEMENT": "1",
    "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
    "DISABLE_TELEMETRY": "1",
    "DISABLE_ERROR_REPORTING": "1",
    "DISABLE_AUTOUPDATER": "1",
}
_MODEL_SLOTS = ("ANTHROPIC_MODEL", "ANTHROPIC_DEFAULT_OPUS_MODEL",
                "ANTHROPIC_DEFAULT_SONNET_MODEL", "ANTHROPIC_DEFAULT_HAIKU_MODEL",
                "ANTHROPIC_SMALL_FAST_MODEL", "CLAUDE_CODE_SUBAGENT_MODEL")
_FAST_SLOTS = ("ANTHROPIC_SMALL_FAST_MODEL", "CLAUDE_CODE_SUBAGENT_MODEL")


def _load_json(path: str) -> dict:
    if not path:
        return {}
    try:
        with open(path, encoding="utf-8") as f:
            d = json.load(f)
        return d if isinstance(d, dict) else {}
    except Exception:
        return {}


def _store() -> dict:
    return _load_json(os.environ.get("HXCTF_LLM_CONFIG", ""))


def _keyring() -> dict:
    return _load_json(os.environ.get("HXCTF_LLM_KEYRING", ""))


def _store_active() -> dict:
    a = _store().get("active") or {}
    if a and all(isinstance(v, dict) for v in a.values()):
        return a.get("solver") or a.get("default") or next(iter(a.values()), {})
    return a if isinstance(a, dict) else {}


def _store_provider_entry(pid: str) -> dict:
    for e in _store().get("providers") or []:
        if isinstance(e, dict) and e.get("id") == pid:
            return e
    return {}


def resolve_egress() -> str:
    return (_store_active().get("egress")
            or os.environ.get("HXCTF_LLM_EGRESS", "").strip()
            or _DEFAULTS["egress"])


def load_egress_profile(name: str) -> dict:
    if not name or name == "direct":
        return {}
    return _load_json(os.path.join(_profile_dir(), name + ".json"))


def egress_apply(url: str, profile: dict) -> str:
    if not profile or not isinstance(url, str) or "://" not in url:
        return url
    from urllib.parse import urlsplit, urlunsplit
    try:
        parts = urlsplit(url)
        host = parts.hostname or ""
        if not host:
            return url
        try:
            port = parts.port
        except ValueError:
            port = None
        rw = profile.get("rewrite") or {}
        suffix = rw.get("host_suffix") or ""
        if suffix and host.endswith(suffix):
            return url
        allow = profile.get("allow_domains")
        if allow and host not in allow:
            print(f"[providers] egress 白名单告警:{host} 不在 allow_domains(仍放行,仅提示)", file=sys.stderr)
        new_host = (host + suffix) if suffix else host
        if ":" in new_host:
            new_host = "[" + new_host + "]"
        new_scheme = rw.get("scheme") or parts.scheme
        userinfo = ""
        if parts.username:
            userinfo = parts.username + ((":" + parts.password) if parts.password else "") + "@"
        netloc = userinfo + new_host + ((":" + str(port)) if port else "")
        return urlunsplit((new_scheme, netloc, parts.path, parts.query, parts.fragment))
    except Exception as e:
        print(f"[providers] egress 变换异常(原样返回,不崩):{e.__class__.__name__}", file=sys.stderr)
        return url


def resolve_active() -> dict:
    sa = _store_active()
    entry_of = lambda p: _store_provider_entry(p)
    provider = (sa.get("provider") or os.environ.get("HXCTF_LLM_PROVIDER", "").strip()
                or _DEFAULTS["provider"])
    entry = entry_of(provider)
    model = (sa.get("model") or os.environ.get("HXCTF_LLM_MODEL", "").strip()
             or entry.get("default_model") or _PROVIDER_DEFAULT_MODELS.get(provider) or _DEFAULTS["model"])
    base_url = (entry.get("base_url") or os.environ.get("HXCTF_LLM_BASE_URL", "").strip() or "")
    key_ref = entry.get("key_ref") or ""
    key = ((_keyring().get(key_ref) if key_ref else "")
           or os.environ.get("HXCTF_LLM_API_KEY", "").strip() or "")
    out = {"provider": provider, "model": model, "egress": resolve_egress(),
           "base_url": base_url, "key": key}
    rot = main_rotation()
    if rot and out["provider"] == rot["failed_provider"]:
        out = {**out, "provider": rot["provider"], "model": rot["model"],
               "base_url": rot["base_url"], "key": rot["api_key"]}
    return out


ROLES = ("decide", "execute", "execute_high", "judge", "small")


def _parse_role_spec(v: str) -> tuple[str, str, str]:
    v = (v or "").strip()
    b = ""
    if "@" in v:
        v, b = v.rsplit("@", 1)
        b = b.strip()
    if ":" in v:
        p, m = v.split(":", 1)
        return p.strip(), m.strip(), b
    return "", v.strip(), b


def resolve_role(role: str) -> dict:
    if role not in ROLES:
        raise ValueError(f"未知角色 {role!r};可选: {', '.join(ROLES)}")
    base = resolve_active()
    a = _store().get("active") or {}
    spec = (a.get(role) or {}) if (a and all(isinstance(v, dict) for v in a.values())) else {}
    p_env, m_env, b_env = _parse_role_spec(os.environ.get(f"HXCTF_MODEL_{role.upper()}", ""))
    provider = (spec.get("provider") or p_env or "").strip()
    model = (spec.get("model") or m_env or "").strip()
    if not provider and not model:
        return base
    if not provider:
        return {**base, "model": model}
    if provider not in PROVIDERS and provider != "custom":
        print(f"[providers] 角色 {role} 配置了未知 provider {provider!r} → 回落单模型", file=sys.stderr)
        return base
    entry = _store_provider_entry(provider)
    same = provider == base["provider"]
    base_url = (spec.get("base_url") or b_env or entry.get("base_url")
                or (base["base_url"] if same else "") or "")
    key_ref = entry.get("key_ref") or spec.get("key_ref") or ""
    key = ((_keyring().get(key_ref) if key_ref else "")
           or resolve_key(provider, base["key"] if same else ""))
    model = model or entry.get("default_model") or _PROVIDER_DEFAULT_MODELS.get(provider) or base["model"]
    return {"provider": provider, "model": model, "egress": base["egress"],
            "base_url": base_url, "key": key}


def role_overridden(role: str) -> bool:
    return role_configured(role) and role not in _ROLE_RUNTIME_DISABLED


def role_configured(role: str) -> bool:
    a = _store().get("active") or {}
    if a and all(isinstance(v, dict) for v in a.values()) and (a.get(role) or {}):
        return True
    return bool(os.environ.get(f"HXCTF_MODEL_{role.upper()}", "").strip())


_ROLE_RUNTIME_DISABLED: set[str] = set()
_ROLE_CONSEC_EMPTY: dict[str, int] = {}
_ROLE_DISABLE_AFTER = 3
_ROLE_STATE_LOCK = threading.Lock()


def note_role_result(role: str, ok: bool) -> None:
    with _ROLE_STATE_LOCK:
        if not role_configured(role) or role in _ROLE_RUNTIME_DISABLED:
            return
        if ok:
            _ROLE_CONSEC_EMPTY.pop(role, None)
            return
        n = _ROLE_CONSEC_EMPTY.get(role, 0) + 1
        _ROLE_CONSEC_EMPTY[role] = n
        if n >= _ROLE_DISABLE_AFTER:
            _ROLE_RUNTIME_DISABLED.add(role)
            print(f"[providers] 角色 {role} 模型连续 {n} 次空产出 → 本 run 停用该 override,"
                  f"回落主模型(无需人工介入;下轮如需启用先修该模型接线)", file=sys.stderr)


def role_runtime_disabled(role: str) -> bool:
    return role in _ROLE_RUNTIME_DISABLED


def disable_role_runtime(role: str, reason: str = "") -> None:
    with _ROLE_STATE_LOCK:
        if role_configured(role) and role not in _ROLE_RUNTIME_DISABLED:
            _ROLE_RUNTIME_DISABLED.add(role)
            print(f"[providers] 角色 {role} override 已停用({reason or 'runtime self-heal'})→ 回落主模型,"
                  f"本 run 不再尝试(零人工;下轮修好接线再启用)", file=sys.stderr)


def role_summary() -> str:
    a = resolve_active()
    dflt = f"{a['provider']}:{a['model']}"
    parts = []
    for r in ROLES:
        s = resolve_role(r)
        v = f"{s['provider']}:{s['model']}"
        _mark = "" if v == dflt else "(角色覆盖)"
        if r in _ROLE_RUNTIME_DISABLED:
            _mark = "(角色覆盖·已自愈停用→主模型)"
        parts.append(f"{r}={v}{_mark}")
    return f"[providers] roles: {' | '.join(parts)}"


def resolve_base_url(provider: str, custom_base_url: str = "") -> str:
    if custom_base_url:
        return custom_base_url.rstrip("/")
    if provider == "custom":
        raise ValueError("custom provider 需提供 base_url(建任务时填)")
    if provider not in PROVIDERS:
        raise ValueError(f"未知 provider {provider!r};可选: {', '.join(PROVIDERS)}, custom")
    return PROVIDERS[provider][0]


def resolve_key(provider: str, explicit: str = "") -> str:
    if explicit:
        return explicit
    if provider == "custom":
        return os.environ.get(CUSTOM_KEY_ENV, "")
    if provider == "glm":
        _pk = glm_primary_key()
        if _pk:
            return _pk
    env_name = PROVIDERS.get(provider, ("", ""))[1]
    k = os.environ.get(env_name, "") if env_name else ""
    return k or os.environ.get("HXCTF_LLM_API_KEY", "")


_DEFAULT_BASH_MAX_OUTPUT = "10000"
_DEFAULT_THINKING_BUDGET = "4000"


def glm_key_pool() -> list:
    pool = [k.strip() for k in os.environ.get("GLM_API_KEYS", "").split(",") if k.strip()]
    if not pool:
        k = os.environ.get("GLM_API_KEY", "").strip()
        pool = [k] if k else []
    return pool


def glm_primary_key() -> str:
    k = os.environ.get("GLM_API_KEY", "").strip()
    return k or (glm_key_pool()[0] if glm_key_pool() else "")


_MAIN_FAIL_AFTER = 4
_MAIN_TRANSPORT_AFTER = 2
_MAIN_PROBE_EVERY_S = 900.0
_MAIN_STATE_LOCK = threading.Lock()
_MAIN_RUNTIME: dict = {"active": "", "failed": "", "streak": 0, "transport": 0,
                       "last_probe": 0.0, "probe_ok": 0}
_ROTATE_DEFAULT_MODELS = {"glm": "glm-5.3", "deepseek": "deepseek-flash"}


def _rotation_spec(p: str) -> dict | None:
    model = _ROTATE_DEFAULT_MODELS.get(p)
    entry = PROVIDERS.get(p)
    key = resolve_key(p, "")
    if not (model and entry and key):
        return None
    return {"provider": p, "model": model, "api_key": key,
            "base_url": egress_apply(entry[0], load_egress_profile(resolve_egress()))}


def _main_candidates(failed: str) -> list:
    return [p for p in PROVIDERS
            if p not in (failed, "glm-api", "custom")
            and p in _ROTATE_DEFAULT_MODELS and resolve_key(p, "")]


def _probe_provider(spec: dict) -> str:
    try:
        from engine.precheck import _probe_endpoint
        return _probe_endpoint(spec["base_url"], spec["api_key"], spec["model"], timeout=10.0)
    except Exception as e:
        return f"WARN:{e!r}"


def _record(ok: bool, transport: bool = False) -> str:
    with _MAIN_STATE_LOCK:
        r = _MAIN_RUNTIME
        if r["active"]:
            due = ok and (time.time() - r["last_probe"]) > _MAIN_PROBE_EVERY_S
            if due:
                r["last_probe"] = time.time()
            return "probe" if due else ""
        if ok:
            r["streak"] = 0
            r["transport"] = 0
            return ""
        r["streak"] += 1
        r["transport"] = r["transport"] + 1 if transport else 0
        if r["transport"] >= _MAIN_TRANSPORT_AFTER or r["streak"] == _MAIN_FAIL_AFTER:
            r["streak"] = 0
            return "rotate"
        return ""


def _act(action: str) -> None:
    if action == "rotate":
        failed = resolve_active()["provider"]
        for p in _main_candidates(failed):
            spec = _rotation_spec(p)
            if spec and _probe_provider(spec) == "PASS":
                with _MAIN_STATE_LOCK:
                    _MAIN_RUNTIME.update({"active": p, "failed": failed, "probe_ok": 0,
                                          "last_probe": time.time(), "streak": 0})
                print(f"[providers] ⚠ 主模型 {failed} 持续硬失败(通用{_MAIN_FAIL_AFTER}连/传输{_MAIN_TRANSPORT_AFTER}连) → 运行时轮转 {p}"
                      f"(model={spec['model']};新会话生效;主力恢复自动回切;候选链=key 在场的厂,零配置)",
                      file=sys.stderr)
                return
        with _MAIN_STATE_LOCK:
            _MAIN_RUNTIME["streak"] = 0
        return
    if action == "probe":
        orig = _rotation_spec(_MAIN_RUNTIME["failed"])
        if orig and _probe_provider(orig) == "PASS":
            with _MAIN_STATE_LOCK:
                _MAIN_RUNTIME["probe_ok"] += 1
                if _MAIN_RUNTIME["probe_ok"] >= 2:
                    back = _MAIN_RUNTIME["failed"]
                    _MAIN_RUNTIME.update({"active": "", "failed": "", "streak": 0, "probe_ok": 0})
                    print(f"[providers] 主模型 {back} 探针连续通过 → 回切(主力优先)", file=sys.stderr)
        else:
            with _MAIN_STATE_LOCK:
                _MAIN_RUNTIME["probe_ok"] = 0


def note_main_result(ok: bool, transport: bool = False) -> None:
    try:
        _act(_record(ok, transport))
    except Exception as _e:
        print(f"[providers] main-failover non-fatal: {_e!r}", file=sys.stderr)


def main_rotation() -> dict | None:
    p = _MAIN_RUNTIME["active"]
    if not p:
        return None
    spec = _rotation_spec(p)
    if not spec:
        return None
    return {**spec, "failed_provider": _MAIN_RUNTIME["failed"]}


def failover_candidates() -> list:
    try:
        failed = resolve_active()["provider"]
    except Exception:
        return []
    return [s for s in (_rotation_spec(p) for p in _main_candidates(failed)) if s]


def reset_main_runtime() -> None:
    with _MAIN_STATE_LOCK:
        _MAIN_RUNTIME.update({"active": "", "failed": "", "streak": 0, "transport": 0,
                                      "last_probe": 0.0, "probe_ok": 0})


def _exec_runtime_tuning() -> dict:
    return {"BASH_MAX_OUTPUT_LENGTH": (os.environ.get("BASH_MAX_OUTPUT_LENGTH") or _DEFAULT_BASH_MAX_OUTPUT),
            "MAX_THINKING_TOKENS": (os.environ.get("MAX_THINKING_TOKENS") or _DEFAULT_THINKING_BUDGET)}


def cc_env(provider: str, model: str, *, api_key: str = "", custom_base_url: str = "",
           thinking_budget: int | None = None) -> dict:
    active = resolve_active()
    same = (active.get("provider") == provider)
    if not custom_base_url and same:
        custom_base_url = active.get("base_url", "")
    if provider in _OPENAI_COMPAT:
        from engine.openai_bridge import bridge_base_url
        base = bridge_base_url(_OPENAI_COMPAT[provider])
    else:
        base = resolve_base_url(provider, custom_base_url)
        base = egress_apply(base, load_egress_profile(active.get("egress") or _DEFAULTS["egress"]))
    key = api_key or (active.get("key", "") if same else "") or resolve_key(provider)
    if not key:
        env_name = PROVIDERS.get(provider, ("", ""))[1]
        raise ValueError(f"provider {provider!r} 的 API key 为空 —— 请设置 {env_name}"
                         f"(该厂专用)或 HXCTF_LLM_API_KEY(显式通用,§15.23)")
    env = dict(_HYGIENE)
    env["ANTHROPIC_BASE_URL"] = base
    env["ANTHROPIC_AUTH_TOKEN"] = key
    env["ANTHROPIC_API_KEY"] = key
    if role_overridden("small"):
        small = resolve_role("small")
        if small.get("provider") not in ("", provider):
            print(f"[providers] small 角色配了异厂 {small['provider']}(槽位与主端点同连,不能换厂)"
                  f" → 只取其 model 名 {small['model']}", file=sys.stderr)
        fast_model = small["model"]
    else:
        fast_model = model
    for slot in _MODEL_SLOTS:
        env[slot] = (fast_model if slot in _FAST_SLOTS else model)
    env.update(_exec_runtime_tuning())
    if thinking_budget is not None:
        env["MAX_THINKING_TOKENS"] = str(thinking_budget)
    return env


def masked_active() -> str:
    a = resolve_active()
    try:
        env = cc_env(a["provider"], a["model"])
        base, key = env["ANTHROPIC_BASE_URL"], env["ANTHROPIC_AUTH_TOKEN"]
        fp = (key[:8] + "…") if key else "(空)"
        return f"provider={a['provider']} base={base} model={a['model']} egress={a['egress']} key={fp}"
    except ValueError as e:
        return f"provider={a['provider']} model={a['model']} egress={a['egress']} → 配置无效: {e}"


def probe_connection(provider: str = "", model: str = "", *, api_key: str = "",
                     custom_base_url: str = "", timeout: float = 10.0) -> tuple[bool, str]:
    a = resolve_active()
    provider = provider or a["provider"]
    model = model or a["model"]
    try:
        env = cc_env(provider, model, api_key=api_key, custom_base_url=custom_base_url)
    except ValueError as e:
        return (False, f"provider={provider} model={model} → 配置无效: {e}")
    base, key = env["ANTHROPIC_BASE_URL"], env["ANTHROPIC_AUTH_TOKEN"]
    fp = (key[:8] + "…") if key else "(空)"
    tag = f"provider={provider} base={base} model={model} key={fp}"
    import urllib.error
    import urllib.request
    body = json.dumps({"model": model, "max_tokens": 1,
                       "messages": [{"role": "user", "content": "ping"}]}).encode()
    req = urllib.request.Request(base.rstrip("/") + "/v1/messages", data=body, method="POST",
                                 headers={"content-type": "application/json", "x-api-key": key,
                                          "authorization": "Bearer " + key, "anthropic-version": "2023-06-01"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return (r.status < 500, f"{tag} → HTTP {r.status}")
    except urllib.error.HTTPError as e:
        return (e.code < 500, f"{tag} → HTTP {e.code}(连通,配置或额度需查)")
    except Exception as e:
        return (False, f"{tag} → 连接失败: {e.__class__.__name__}")


def probe_reasoning(provider: str = "", model: str = "", *, api_key: str = "",
                    custom_base_url: str = "", timeout: float = 40.0) -> tuple[bool, str]:
    a = resolve_active()
    provider = provider or a["provider"]
    model = model or a["model"]
    try:
        env = cc_env(provider, model, api_key=api_key, custom_base_url=custom_base_url)
    except ValueError as e:
        return (False, f"provider={provider} model={model} → 配置无效: {e}")
    base, key = env["ANTHROPIC_BASE_URL"], env["ANTHROPIC_AUTH_TOKEN"]
    fp = (key[:8] + "…") if key else "(空)"
    try:
        budget = max(256, int(os.environ.get("MAX_THINKING_TOKENS") or _DEFAULT_THINKING_BUDGET))
    except ValueError:
        budget = int(_DEFAULT_THINKING_BUDGET)
    tag = f"provider={provider} base={base} model={model} key={fp} budget={budget}"
    import urllib.error
    import urllib.request
    body = json.dumps({"model": model, "max_tokens": budget + 256,
                       "thinking": {"type": "enabled", "budget_tokens": budget},
                       "messages": [{"role": "user", "content": "What is 23*17? Reason briefly, then give the number."}]}).encode()
    req = urllib.request.Request(base.rstrip("/") + "/v1/messages", data=body, method="POST",
                                 headers={"content-type": "application/json", "x-api-key": key,
                                          "authorization": "Bearer " + key, "anthropic-version": "2023-06-01"})
    try:
        with urllib.request.urlopen(req, timeout=timeout) as r:
            data = json.loads(r.read().decode(errors="replace"))
    except urllib.error.HTTPError as e:
        detail = ""
        try:
            detail = e.read().decode(errors="replace")[:160].replace("\n", " ")
        except Exception:
            pass
        return (False, f"{tag} → HTTP {e.code}(reasoning 探针被拒/网关不认 thinking){(': ' + detail) if detail else ''}")
    except Exception as e:
        return (False, f"{tag} → 连接失败: {e.__class__.__name__}")
    think_chars = sum(len(b.get("thinking", "") or "")
                      for b in (data.get("content") or []) if isinstance(b, dict) and b.get("type") == "thinking")
    on = think_chars > 0
    verdict = "ON(reasoning 穿透)" if on else "OFF!(端点未返回 thinking —— 云上会重演 reasoning=0)"
    return (on, f"{tag} → reasoning {verdict}  thinking_chars={think_chars}")
