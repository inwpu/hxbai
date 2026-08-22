from __future__ import annotations

import os
from dataclasses import dataclass


def _env(name: str, default: str | None = None) -> str | None:
    val = os.environ.get(name)
    if val is None or val == "":
        return default
    return val


def apply_llm_profile() -> str | None:
    profile = (os.environ.get("LLM_PROFILE") or "").strip()
    if not profile:
        return None
    prefix = f"{profile.upper()}_LLM_"
    for k, v in list(os.environ.items()):
        if k.startswith(prefix) and v != "":
            os.environ["LLM_" + k[len(prefix):]] = v
    return profile


_SOLVER_PRESETS = {
    "deepseek": {
        "base_url": "https://api.deepseek.com/anthropic",
        "model": "deepseek-v4-flash",
        "small_fast_model": "deepseek-v4-flash",
    },
    "deepseek-1m": {
        "base_url": "https://api.deepseek.com/anthropic",
        "model": "deepseek-v4-pro[1m]",
        "small_fast_model": "deepseek-v4-flash",
        "subagent_model": "deepseek-v4-flash",
        "effort_level": "max",
        "auto_compact_window": "786432",
        "api_timeout_ms": "3000000",
    },
    "glm": {
        "base_url": "https://open.bigmodel.cn/api/anthropic",
        "model": "glm-5.3",
        "small_fast_model": "glm-5.3",
    },
    "glm-1m": {
        "base_url": "https://open.bigmodel.cn/api/anthropic",
        "model": "glm-5.3",
        "small_fast_model": "glm-5.3",
        "auto_compact_window": "1000000",
        "api_timeout_ms": "3000000",
    },
}


def _to_gateway(url: str) -> str:
    if not url:
        return url
    if ".tsecbench.gw" in url:
        u = url
    else:
        m = url.split("://", 1)
        scheme, rest = (m[0], m[1]) if len(m) == 2 else ("https", url)
        host, _, path = rest.partition("/")
        u = f"{scheme}://{host}.tsecbench.gw" + (("/" + path) if path else "")
    return u.replace("https://", "http://", 1)


@dataclass
class SolverConfig:
    provider: str
    base_url: str
    api_key: str
    model: str
    small_fast_model: str
    max_turns: int
    session_seconds: int
    reasoning: bool
    subagent_model: str = ""
    effort_level: str = ""
    auto_compact_window: str = ""
    api_timeout_ms: str = ""

    @classmethod
    def from_env(cls) -> "SolverConfig":
        provider = (_env("SOLVER_PROVIDER") or _env("HXBAI_PROVIDER", "deepseek") or "deepseek").lower()
        preset = _SOLVER_PRESETS.get(provider, _SOLVER_PRESETS["deepseek"])
        base = _env("SOLVER_BASE_URL", preset["base_url"]) or preset["base_url"]
        if _env("SOLVER_GATEWAY", "0") == "1":
            base = _to_gateway(base)
        key = (_env("SOLVER_API_KEY") or _env("ANTHROPIC_AUTH_TOKEN") or _env("ANTHROPIC_API_KEY") or "")
        return cls(
            provider=provider,
            base_url=base.rstrip("/"),
            api_key=key,
            model=_env("SOLVER_MODEL", preset["model"]) or preset["model"],
            small_fast_model=_env("SOLVER_SMALL_FAST_MODEL", preset["small_fast_model"]) or preset["small_fast_model"],
            max_turns=int(_env("SOLVER_MAX_TURNS", "60") or "60"),
            session_seconds=int(_env("SOLVER_SESSION_SECONDS", "1500") or "1500"),
            reasoning=(_env("SOLVER_REASONING", "0") == "1"),
            subagent_model=_env("SOLVER_SUBAGENT_MODEL", preset.get("subagent_model", "")) or "",
            effort_level=_env("SOLVER_EFFORT", preset.get("effort_level", "")) or "",
            auto_compact_window=_env("SOLVER_AUTO_COMPACT_WINDOW", preset.get("auto_compact_window", "")) or "",
            api_timeout_ms=_env("SOLVER_API_TIMEOUT_MS", preset.get("api_timeout_ms", "")) or "",
        )

    def anthropic_env(self) -> dict:
        e = {
            "ANTHROPIC_BASE_URL": self.base_url,
            "ANTHROPIC_AUTH_TOKEN": self.api_key,
            "ANTHROPIC_API_KEY": self.api_key,
            "ANTHROPIC_MODEL": self.model,
            "ANTHROPIC_DEFAULT_OPUS_MODEL": self.model,
            "ANTHROPIC_DEFAULT_SONNET_MODEL": self.model,
            "ANTHROPIC_DEFAULT_HAIKU_MODEL": self.small_fast_model,
            "ANTHROPIC_SMALL_FAST_MODEL": self.small_fast_model,
            "CLAUDE_CODE_DISABLE_NONESSENTIAL_TRAFFIC": "1",
            "DISABLE_TELEMETRY": "1",
            "DISABLE_ERROR_REPORTING": "1",
            "DISABLE_AUTOUPDATER": "1",
            "TERM": os.environ.get("TERM") or "xterm",
            "CLAUDE_CODE_SUBAGENT_MODEL": self.subagent_model,
            "CLAUDE_CODE_EFFORT_LEVEL": self.effort_level,
            "CLAUDE_CODE_AUTO_COMPACT_WINDOW": self.auto_compact_window,
            "API_TIMEOUT_MS": self.api_timeout_ms,
        }
        return {k: v for k, v in e.items() if v}


@dataclass
class LLMConfig:
    provider: str
    base_url: str
    api_key: str
    model: str
    temperature: float
    max_tokens: int
    timeout: int
    min_interval: float = 0.0
    thinking: bool = True
    reasoning_effort: str = "high"
    fast_model: str = ""
    empty_retries: int = 2
    max_tokens_fast: int = 3072
    fallback_provider: str | None = None
    fallback_base_url: str | None = None
    fallback_api_key: str | None = None
    fallback_model: str | None = None

    @classmethod
    def from_env(cls) -> "LLMConfig":
        apply_llm_profile()
        provider = (_env("LLM_PROVIDER", "openai") or "openai").lower()
        default_base = "" if provider in ("zai", "zhipu", "glm") else "https://api.deepseek.com"
        base_url = _env("LLM_BASE_URL", default_base)
        api_key = _env("LLM_API_KEY", "")
        model = _env("LLM_MODEL", "deepseek-chat")
        return cls(
            provider=provider,
            base_url=base_url.rstrip("/") if base_url else base_url,
            api_key=api_key or "",
            model=model,
            temperature=float(_env("LLM_TEMPERATURE", "0.4")),
            max_tokens=int(_env("LLM_MAX_TOKENS", "4096")),
            timeout=int(_env("LLM_TIMEOUT", "300")),
            min_interval=float(_env("LLM_MIN_INTERVAL", "0")),
            thinking=(_env("LLM_THINKING", "1") == "1"),
            reasoning_effort=_env("LLM_REASONING_EFFORT", "high"),
            max_tokens_fast=int(_env("LLM_MAX_TOKENS_FAST", "3072")),
            empty_retries=int(_env("LLM_EMPTY_RETRIES", "2")),
            fast_model=_env("LLM_FAST_MODEL", "deepseek-v4-flash" if "deepseek" in (model or "").lower() else ""),
            fallback_provider=(lambda p: p.lower() if p else None)(_env("LLM_FALLBACK_PROVIDER")),
            fallback_base_url=(lambda u: u.rstrip("/") if u else None)(_env("LLM_FALLBACK_BASE_URL")),
            fallback_api_key=_env("LLM_FALLBACK_API_KEY"),
            fallback_model=_env("LLM_FALLBACK_MODEL"),
        )

    def has_fallback(self) -> bool:
        return bool(self.fallback_api_key and self.fallback_model)

    def is_usable(self) -> bool:
        if self.provider in ("zai", "zhipu", "glm"):
            return bool(self.api_key)
        return bool(self.api_key and self.base_url)


_VERIFIER_PRESETS = {
    "deepseek": {"provider": "openai", "base_url": "https://api.deepseek.com/v1", "model": "deepseek-v4-flash"},
    "glm": {"provider": "zai", "base_url": "https://open.bigmodel.cn/api/paas/v4", "model": "glm-5.3"},
}


def build_verifier_config(solver: "SolverConfig") -> LLMConfig:
    apply_llm_profile()
    family = "glm" if solver.provider.startswith("glm") else "deepseek"
    preset = _VERIFIER_PRESETS.get(family, _VERIFIER_PRESETS["deepseek"])
    provider = (_env("LLM_PROVIDER") or preset["provider"]).lower()
    base = _env("LLM_BASE_URL") or preset["base_url"]
    if _env("SOLVER_GATEWAY", "0") == "1":
        base = _to_gateway(base)
    return LLMConfig(
        provider=provider,
        base_url=(base or "").rstrip("/"),
        api_key=(_env("LLM_API_KEY") or solver.api_key or ""),
        model=_env("LLM_MODEL") or preset["model"],
        temperature=float(_env("LLM_TEMPERATURE", "0.3") or "0.3"),
        max_tokens=int(_env("LLM_MAX_TOKENS", "1024") or "1024"),
        timeout=int(_env("LLM_TIMEOUT", "120") or "120"),
        min_interval=float(_env("LLM_MIN_INTERVAL", "0") or "0"),
        thinking=(_env("LLM_THINKING", "0") == "1"),
        reasoning_effort=_env("LLM_REASONING_EFFORT", "low") or "low",
        max_tokens_fast=int(_env("LLM_MAX_TOKENS_FAST", "1024") or "1024"),
        empty_retries=int(_env("LLM_EMPTY_RETRIES", "2") or "2"),
        fast_model=_env("LLM_FAST_MODEL", preset["model"]) or preset["model"],
    )


@dataclass
class ControllerConfig:
    workdir: str
    max_concurrency: int
    best_of: int
    per_challenge_seconds: int
    max_sessions_per_challenge: int
    dry_facts_cutoff: int
    use_hints: bool
    skeptic_votes: int
    min_request_interval: float
    round_timeboxes: list
    total_seconds: int
    secs_per_turn: float
    keepalive_max: int
    keepalive_window_s: int
    keepalive_phase_pending: int
    keepalive_tail_s: int
    keepalive_reaped_cooldown_s: int

    @classmethod
    def from_env(cls) -> "ControllerConfig":
        rounds_raw = (_env("HXBAI_ROUND_TIMEBOXES", "600,1200,1800") or "600,1200,1800")
        timeboxes = [int(x) for x in rounds_raw.split(",") if x.strip().isdigit()] or [600, 1200, 1800]
        return cls(
            workdir=_env("HXBAI_WORKDIR", "/tmp/hxbai-work") or "/tmp/hxbai-work",
            max_concurrency=max(1, int(_env("HXBAI_MAX_CONCURRENCY", "3") or "3")),
            best_of=max(1, int(_env("HXBAI_BEST_OF", "1") or "1")),
            per_challenge_seconds=int(_env("HXBAI_PER_CHALLENGE_SECONDS", "4000") or "4000"),
            max_sessions_per_challenge=int(_env("HXBAI_MAX_SESSIONS", "8") or "8"),
            dry_facts_cutoff=int(_env("HXBAI_DRY_FACTS_CUTOFF", "3") or "3"),
            use_hints=(_env("HXBAI_USE_HINTS", "0") == "1"),
            skeptic_votes=max(1, int(_env("SKEPTIC_VOTES", "1") or "1")),
            min_request_interval=float(_env("HXBAI_MIN_REQUEST_INTERVAL", "0.4") or "0.4"),
            round_timeboxes=timeboxes,
            total_seconds=int(_env("HXBAI_TOTAL_SECONDS", "21300") or "21300"),
            secs_per_turn=float(_env("HXBAI_SECS_PER_TURN", "5") or "5"),
            keepalive_max=max(0, int(_env("HXBAI_KEEPALIVE_MAX", "3") or "3")),
            keepalive_window_s=int(_env("HXBAI_KEEPALIVE_WINDOW_S", "7200") or "7200"),
            keepalive_phase_pending=int(_env("HXBAI_KEEPALIVE_PHASE_PENDING", "4") or "4"),
            keepalive_tail_s=int(_env("HXBAI_KEEPALIVE_TAIL_S", "1800") or "1800"),
            keepalive_reaped_cooldown_s=int(_env("HXBAI_KEEPALIVE_REAPED_COOLDOWN_S", "1800") or "1800"),
        )
