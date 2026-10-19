from __future__ import annotations

import re

_EXCLUSION_RX = re.compile(
    r"ruled\b[^.\n]{0,40}\bout\b|not\s*vulnerable|no\s*vulnerability|无法利用|不可利用|被\s*WAF\s*拦|WAF\s*拦截"
    r"|blocked\s+by|definitively\s+(?:ruled|blocked)|exists\s+but\s+(?:blocked|not\s+exploitable)"
    r"|false\s+positive|误报|已排除|排除(?:该|此)?(?:漏洞|路径|方向)", re.I)


def is_exclusion_finding(summary: str) -> bool:
    return bool(_EXCLUSION_RX.search(summary or ""))
