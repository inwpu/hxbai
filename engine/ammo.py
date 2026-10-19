from __future__ import annotations

import datetime
import re

_CRED_CTX_RX = re.compile(
    r"(?:user(?:name)?|login|account|owner|uid|hostname|host|realm|domain|"
    r"server|x-powered-by|powered-by)\s*[:=]\s*([A-Za-z][A-Za-z0-9_.\-]{1,30})", re.I)
_YEAR_RX = re.compile(r"\b(19[89]\d|20[0-3]\d)\b")
_FLAG_RX = re.compile(r"[A-Za-z][\w.\-]{1,30}\{[^}]{1,}\}")
_STOP = {"nginx", "apache", "iis", "http", "https", "html", "php", "tcp", "ssl", "tls", "true", "false", "none"}
_YEARS = tuple(str(datetime.datetime.now().year - d) for d in range(0, 3))
_SUFFIXES = ("", "123", "1234", "12345", "!", "@123", "#123") + _YEARS + tuple("@" + y for y in _YEARS)
_LEET = str.maketrans({"e": "3", "a": "4", "o": "0", "i": "1", "s": "5"})

_VENDOR_PRODUCTS = frozenset({
    "weaver", "ecology", "seeyon", "landray", "thinkphp", "tomcat", "weblogic", "jboss", "ofbiz",
    "confluence", "jenkins", "gitlab", "grafana", "zabbix", "nexus", "solr", "jira", "wordpress",
    "joomla", "drupal", "phpmyadmin", "nacos", "harbor", "rancher", "minio", "kibana", "elastic",
    "1panel", "comfyui", "jumpserver", "kkfileview", "dahua", "hikvision", "sangfor",
})
_PRODUCT_ALIASES = {
    "泛微": "weaver", "致远": "seeyon", "蓝凌": "landray", "深信服": "sangfor",
}
_VENDOR_YEARS = tuple(str(datetime.datetime.now().year - d) for d in range(0, 8))
_PRODUCT_TOK_RX = re.compile(r"[A-Za-z][A-Za-z0-9]{2,20}")
_FP_CUE = re.compile(
    r"\bv?\d+\.\d+"
    r"|server\s*[:=]|x-powered-by|powered[ -]?by"
    r"|\bversion\b|\brelease\b|\bbuild\b|banner"
    r"|\bOA\b|\bCMS\b|framework|webapp"
    r"|/\w+\.(?:php|jsp|jspx|do|action|aspx)"
    r"|指纹|fingerprint|nuclei|whatweb",
    re.I)


def harvest_tokens(text: str) -> list[str]:
    if not text:
        return []
    text = _FLAG_RX.sub(" ", text)
    out, seen = [], set()
    for m in _CRED_CTX_RX.finditer(text):
        t = m.group(1)
        low = t.lower()
        if low in _STOP or low in seen:
            continue
        seen.add(low)
        out.append(t)
    for m in _YEAR_RX.finditer(text):
        y = m.group(0)
        if y not in seen:
            seen.add(y)
            out.append(y)
    return out


def harvest_products(text: str, extra: list[str] | None = None) -> list[str]:
    found, seen = [], set()

    def _add(p: str) -> None:
        p = (p or "").lower()
        if p and p in _VENDOR_PRODUCTS and p not in seen:
            seen.add(p)
            found.append(p)

    def _scan(s: str) -> None:
        if not s or not _FP_CUE.search(s):
            return
        for zh, en in sorted(_PRODUCT_ALIASES.items()):
            if zh in s:
                _add(en)
        low = s.lower()
        for p in sorted(_VENDOR_PRODUCTS):
            if re.search(r"(?<![a-z])" + re.escape(p) + r"(?![a-z])", low):
                _add(p)
    _scan(" ".join(str(t) for t in (extra or [])))
    _scan(text or "")
    return found


def vendor_default_creds(product: str) -> list[str]:
    p = (product or "").lower()
    if not p:
        return []
    P = p[:1].upper() + p[1:]
    out, seen = [], set()

    def _add(s: str) -> None:
        if s and s not in seen and not _FLAG_RX.search(s):
            seen.add(s)
            out.append(s)
    for s in (p, P, p + "123", P + "123", p + "@123", P + "@123", p + "@1234", P + "@1234",
              p + "_admin", "admin@" + p, "admin", p + "!"):
        _add(s)
    for y in _VENDOR_YEARS:
        _add(P + "@" + y); _add(p + "@" + y); _add(P + y); _add(p + y)
    return out


def mutate(base: str) -> list[str]:
    if not base:
        return []
    low = base.lower()
    out, seen = [], set()

    def _add(s: str) -> None:
        if s and s not in seen:
            seen.add(s)
            out.append(s)

    for suf in _SUFFIXES:
        _add(low + suf)
    _add(base[:1].upper() + base[1:])
    _add(low.translate(_LEET))
    return out


def build_candidates(obs_text: str, *, hint_text: str | None = None, ekb_creds: list[str] | None = None,
                     product_tokens: list[str] | None = None, limit: int = 500) -> list[str]:
    out, seen = [], set()

    def _add(s: str) -> None:
        if s and s not in seen and not _FLAG_RX.search(s) and len(out) < limit:
            seen.add(s)
            out.append(s)

    if hint_text:
        for prod in harvest_products(hint_text):
            for cand in vendor_default_creds(prod):
                _add(cand)
        for tok in harvest_tokens(hint_text):
            for cand in mutate(tok):
                _add(cand)
    for cred in (ekb_creds or []):
        pw = cred.split(":", 1)[1] if ":" in cred else cred
        _add(pw.strip())
    for prod in harvest_products(obs_text, extra=product_tokens):
        for cand in vendor_default_creds(prod):
            _add(cand)
    for tok in harvest_tokens(obs_text):
        for cand in mutate(tok):
            _add(cand)
    return out
