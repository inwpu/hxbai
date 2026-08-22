from __future__ import annotations

from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class AgentTask:
    objective: str
    targets: list[str] = field(default_factory=list)
    flag_count: int = 1
    flag_format: Optional[str] = None
    files: list[str] = field(default_factory=list)
    workdir: str = "/tmp/hxbai-work"
    category: Optional[str] = None
    hint_fn: Optional[Callable[[], Optional[str]]] = None
    unique_code: Optional[str] = None

    def target_str(self) -> str:
        return ", ".join(self.targets) if self.targets else "(no network target; local files only)"
