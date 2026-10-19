from __future__ import annotations

import threading
from typing import Any, Callable


class CallTimeout(TimeoutError):
    pass


def call_with_timeout(fn: Callable[..., Any], *args: Any, timeout: float, **kwargs: Any) -> Any:
    box: dict[str, Any] = {}

    def _run() -> None:
        try:
            box["v"] = fn(*args, **kwargs)
        except BaseException as e:
            box["e"] = e

    t = threading.Thread(target=_run, daemon=True)
    t.start()
    t.join(max(1e-3, timeout))
    if t.is_alive():
        raise CallTimeout(f"call {getattr(fn, '__name__', fn)!r} exceeded {timeout:.0f}s wall-clock (platform hang?)")
    if "e" in box:
        raise box["e"]
    return box.get("v")
