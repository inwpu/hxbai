from __future__ import annotations

import time
from dataclasses import dataclass
from typing import Any

from .config import LLMConfig


def _is_rate_error(e: Exception) -> bool:
    s = str(e).lower()
    return any(k in s for k in ("429", "rate", "too many", "timeout", "authentication fails", "invalid_request_error"))


@dataclass
class LLMResult:
    text: str
    prompt_tokens: int
    completion_tokens: int
    model: str
    provider_used: str
    reasoning_text: str = ""


class _Backend:
    provider: str = ""
    model: str = ""

    def complete(self, messages, temperature, max_tokens, stop, thinking=None) -> tuple[str, str, int, int]:
        raise NotImplementedError


class OpenAIBackend(_Backend):
    provider = "openai"

    def __init__(self, base_url: str, api_key: str, model: str, timeout: int,
                 thinking: bool = True, fast_model: str = "", reasoning_effort: str = "high"):
        from openai import OpenAI
        self.model = model
        self.fast_model = fast_model
        self.reasoning_effort = reasoning_effort
        self.thinking = thinking
        self._no_effort = False
        self.client = OpenAI(api_key=api_key, base_url=base_url, timeout=timeout)

    def complete(self, messages, temperature, max_tokens, stop, thinking=None):
        th = self.thinking if thinking is None else thinking
        model = self.model if (th or not self.fast_model) else self.fast_model
        self._last_model = model
        kwargs = dict(model=model, messages=messages, temperature=temperature,
                      max_tokens=max_tokens, stop=stop or None)
        if th and self.reasoning_effort and not self._no_effort:
            kwargs["reasoning_effort"] = self.reasoning_effort
        try:
            resp = self.client.chat.completions.create(**kwargs)
        except Exception as e:
            if "reasoning_effort" in kwargs and "reasoning_effort" in str(e).lower():
                self._no_effort = True
                kwargs.pop("reasoning_effort")
                resp = self.client.chat.completions.create(**kwargs)
            else:
                raise
        text = resp.choices[0].message.content or ""
        reasoning = getattr(resp.choices[0].message, "reasoning_content", "") or ""
        usage = getattr(resp, "usage", None)
        self._last_cache_hit = getattr(usage, "prompt_cache_hit_tokens", 0) if usage else 0
        return (
            text,
            reasoning,
            getattr(usage, "prompt_tokens", 0) if usage else 0,
            getattr(usage, "completion_tokens", 0) if usage else 0,
        )


class ZaiBackend(_Backend):
    provider = "zai"

    def __init__(self, api_key: str, model: str, timeout: int, thinking: bool, reasoning_effort: str, base_url: str | None = None):
        from zai import ZhipuAiClient
        self.model = model
        self.thinking = thinking
        self.reasoning_effort = reasoning_effort
        kwargs: dict[str, Any] = {"api_key": api_key}
        if base_url:
            kwargs["base_url"] = base_url
        try:
            self.client = ZhipuAiClient(timeout=timeout, **kwargs)
        except TypeError:
            self.client = ZhipuAiClient(**kwargs)

    def complete(self, messages, temperature, max_tokens, stop, thinking=None):
        th = self.thinking if thinking is None else thinking
        budget = max(int(max_tokens), 8192) if th else int(max_tokens)
        resp = self.client.chat.completions.create(
            model=self.model,
            messages=messages,
            temperature=temperature,
            max_tokens=budget,
            thinking={"type": "enabled" if th else "disabled"},
            reasoning_effort=self.reasoning_effort,
        )
        msg = resp.choices[0].message
        text = getattr(msg, "content", None) or ""
        reasoning = getattr(msg, "reasoning_content", "") or ""
        usage = getattr(resp, "usage", None)
        return (
            text,
            reasoning,
            getattr(usage, "prompt_tokens", 0) if usage else 0,
            getattr(usage, "completion_tokens", 0) if usage else 0,
        )


def _make_backend(provider: str, base_url: str, api_key: str, model: str, cfg: LLMConfig) -> _Backend:
    provider = (provider or "openai").lower()
    if provider in ("zai", "zhipu", "glm"):
        return ZaiBackend(
            api_key=api_key, model=model, timeout=cfg.timeout,
            thinking=cfg.thinking, reasoning_effort=cfg.reasoning_effort,
            base_url=base_url or None,
        )
    return OpenAIBackend(base_url=base_url, api_key=api_key, model=model, timeout=cfg.timeout,
                         thinking=cfg.thinking, fast_model=cfg.fast_model,
                         reasoning_effort=cfg.reasoning_effort)


class LLMClient:
    def __init__(self, cfg: LLMConfig):
        self.cfg = cfg
        self._last_call = 0.0
        self._primary = _make_backend(cfg.provider, cfg.base_url, cfg.api_key, cfg.model, cfg)
        self._fallback = None
        if cfg.has_fallback():
            self._fallback = _make_backend(
                cfg.fallback_provider or cfg.provider,
                cfg.fallback_base_url or "",
                cfg.fallback_api_key or "",
                cfg.fallback_model or cfg.model,
                cfg,
            )

    def chat(
        self,
        messages: list[dict[str, str]],
        *,
        temperature: float | None = None,
        max_tokens: int | None = None,
        stop: list[str] | None = None,
        max_retries: int = 4,
        thinking: bool | None = None,
    ) -> LLMResult:
        temperature = self.cfg.temperature if temperature is None else temperature
        explicit_tokens = max_tokens is not None

        last_err: Exception | None = None
        empty_result: LLMResult | None = None
        for provider_used, backend in self._backends():
            mt = max_tokens if explicit_tokens else self._auto_tokens(backend, thinking)
            empty_tries = 0
            attempt = 0
            while attempt < max_retries:
                attempt += 1
                self._throttle()
                try:
                    text, rt, pt, ct = backend.complete(messages, temperature, mt, stop, thinking=thinking)
                    self._last_call = time.monotonic()
                    model = getattr(backend, "_last_model", backend.model)
                    if (text or "").strip():
                        try:
                            from . import observability as _obs
                            _obs.emit("model_call", layer="llm",
                                      payload={"model": model, "provider": provider_used,
                                               "prompt_tokens": pt, "completion_tokens": ct,
                                               "cache_hit_tokens": getattr(backend, "_last_cache_hit", 0)})
                        except Exception:
                            pass
                        return LLMResult(text=text, prompt_tokens=pt, completion_tokens=ct,
                                         model=model, provider_used=provider_used, reasoning_text=rt)
                    empty_result = LLMResult(text="", prompt_tokens=pt, completion_tokens=ct,
                                             model=model, provider_used=provider_used, reasoning_text=rt)
                    empty_tries += 1
                    if empty_tries >= max(1, getattr(self.cfg, "empty_retries", 3)):
                        break
                    if mt > 2048:
                        mt = max(2048, mt // 2)
                except Exception as e:
                    last_err = e
                    self._last_call = time.monotonic()
                    if attempt < max_retries:
                        base = 8 if _is_rate_error(e) else 2
                        time.sleep(min(base * (attempt + 1), 45))
        if empty_result is not None:
            return empty_result
        raise RuntimeError(f"LLM request failed on all providers: {last_err}") from last_err

    def _auto_tokens(self, backend, thinking: bool | None = None) -> int:
        th = getattr(backend, "thinking", True) if thinking is None else thinking
        if th:
            return self.cfg.max_tokens
        if getattr(backend, "provider", "") == "zai":
            return max(self.cfg.max_tokens_fast, 6144)
        return self.cfg.max_tokens_fast

    def _throttle(self):
        if self.cfg.min_interval <= 0:
            return
        delta = time.monotonic() - self._last_call
        if delta < self.cfg.min_interval:
            time.sleep(self.cfg.min_interval - delta)

    def _backends(self):
        yield ("primary", self._primary)
        if self._fallback is not None:
            yield ("fallback", self._fallback)

    def set_thinking(self, enabled: bool) -> None:
        for _, b in self._backends():
            if getattr(b, "provider", "") in ("zai", "openai"):
                b.thinking = enabled

    def provider(self) -> str:
        return getattr(self._primary, "provider", "")
