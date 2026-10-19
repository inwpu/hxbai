from __future__ import annotations

import re

_VERBS = ("add_subgoal", "achieve_subgoal", "abandon_subgoal",
          "add_step", "drop_step", "satisfy_goal", "recall", "add_route")
_LINE = re.compile(r"^\s*(" + "|".join(_VERBS) + r")\s*:\s*(.+?)\s*$", re.I)


def parse_decisions(text: str) -> dict:
    out: dict[str, list[str]] = {v: [] for v in _VERBS}
    for line in (text or "").splitlines():
        m = _LINE.match(line)
        if not m:
            continue
        verb, arg = m.group(1).lower(), m.group(2).strip()
        if not arg or arg.startswith("<"):
            continue
        if arg not in out[verb]:
            out[verb].append(arg[:300])
    out["satisfy"] = out.pop("satisfy_goal")
    return out


def any_action(decisions: dict) -> bool:
    return any(decisions.get(k) for k in decisions)
