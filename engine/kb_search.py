from __future__ import annotations

import json
import os
import re
import sys

KB_ROOT = "/opt/kb"
INDEX_PATH = "/opt/kb-index.json"
NUCLEI_INDEX_PATH = "/opt/nuclei-index.json"
MSF_INDEX_PATH = "/opt/msf-index.json"
DEFAULT_LOGIN_INDEX_PATH = "/opt/nuclei-login-index.json"
EXPLOITDB_CSV_PATH = "/usr/share/exploitdb/files_exploits.csv"
EXPLOITDB_ROOT = "/usr/share/exploitdb"
_TEXT_EXTS = (".md", ".txt", ".py", ".yaml", ".yml", ".json", ".rb", ".sh", ".c", ".java", ".php", ".rst")
_CVE_RX = re.compile(r"CVE-\d{4}-\d{3,7}", re.I)
_HEADING_RX = re.compile(r"^\s{0,3}#{1,3}\s+(.+?)\s*$", re.M)


def _read_head(path: str, nbytes: int = 4096) -> str:
    try:
        with open(path, encoding="utf-8", errors="replace") as f:
            return f.read(nbytes)
    except OSError:
        return ""


def index_file(path: str, kb_root: str) -> dict | None:
    if not path.lower().endswith(_TEXT_EXTS):
        return None
    rel = os.path.relpath(path, kb_root)
    parts = rel.split(os.sep)
    category = parts[0] if len(parts) > 1 else "(root)"
    head = _read_head(path)
    hm = _HEADING_RX.search(head)
    title = (hm.group(1).strip() if hm else os.path.basename(path))[:160]
    cves = sorted({c.upper() for c in _CVE_RX.findall(head + " " + rel)})
    desc = re.sub(r"[#>*`\-\s]+", " ", head).strip()[:200]
    return {"path": path, "rel": rel, "category": category, "title": title, "cves": cves, "desc": desc}


def build_index(kb_root: str) -> list[dict]:
    out = []
    for root, _, files in os.walk(kb_root):
        for f in sorted(files):
            m = index_file(os.path.join(root, f), kb_root)
            if m:
                out.append(m)
    return sorted(out, key=lambda m: m["rel"])


_NUC_ID_RX = re.compile(r"(?im)^\s*id:\s*(\S+)")
_NUC_NAME_RX = re.compile(r"(?im)^\s{1,6}name:\s*(.+?)\s*$")
_NUC_CVEID_RX = re.compile(r"(?im)^\s*cve-id:\s*(CVE-\d{4}-\d{3,7})")
_NUC_VENDOR_RX = re.compile(r"(?im)^\s*vendor:\s*([a-z0-9_.\-]+)")
_NUC_PRODUCT_RX = re.compile(r"(?im)^\s*product:\s*([a-z0-9_.\-]+)")
_NUC_CPE_RX = re.compile(r"(?im)^\s*cpe:\s*(cpe:[^\s]+)")
_NUC_TAGS_RX = re.compile(r"(?im)^\s*tags:\s*(.+?)\s*$")


def index_nuclei_template(path: str, nuclei_root: str) -> dict | None:
    if not path.lower().endswith((".yaml", ".yml")):
        return None
    head = _read_head(path, 2048)
    cm = _NUC_CVEID_RX.search(head)
    idm = _NUC_ID_RX.search(head)
    cve = (cm.group(1) if cm else (idm.group(1) if idm and idm.group(1).upper().startswith("CVE-") else "")).upper()
    if not cve or not _CVE_RX.fullmatch(cve):
        return None
    nm = _NUC_NAME_RX.search(head)
    title = (nm.group(1).strip().strip('"\'')[:160] if nm else cve)
    _vd = _NUC_VENDOR_RX.search(head)
    vendor = (_vd.group(1) or "") if _vd else ""
    product = (_NUC_PRODUCT_RX.search(head) or [None, ""])[1] if _NUC_PRODUCT_RX.search(head) else ""
    cpe = (_NUC_CPE_RX.search(head) or [None, ""])[1] if _NUC_CPE_RX.search(head) else ""
    _tg = _NUC_TAGS_RX.search(head)
    tags = (_tg.group(1) or "") if _tg else ""
    if cpe:
        _pp = cpe.split(":")
        if len(_pp) >= 5:
            vendor = vendor or _pp[3]
            product = product or _pp[4]
    _prod_seg = re.split(r"\s+[-<]\s+|\s*<\s*", title)[0].strip() if title else ""
    _slug = re.sub(r"[^a-z0-9]+", "-", _prod_seg.lower()).strip("-")[:40] or "cve"
    rel = "nuclei-cve/" + _slug + "/" + os.path.splitext(os.path.basename(path))[0]
    desc = " ".join(x for x in (product, vendor, cpe, tags) if x)[:200]
    return {"path": path, "rel": rel, "category": "nuclei-cve", "title": title, "cves": [cve], "desc": desc}


def build_nuclei_index(nuclei_root: str) -> list[dict]:
    out = []
    if not nuclei_root or not os.path.isdir(nuclei_root):
        return out
    for root, _, files in os.walk(nuclei_root):
        for f in sorted(files):
            if f.lower().endswith((".yaml", ".yml")):
                m = index_nuclei_template(os.path.join(root, f), nuclei_root)
                if m:
                    out.append(m)
    return sorted(out, key=lambda m: m["rel"])


_DL_SUFFIX_RX = re.compile(r"\s*default\s+log(?:in|ins)\s*$", re.I)


def index_default_login_template(path: str, dl_root: str) -> dict | None:
    if not path.lower().endswith((".yaml", ".yml")):
        return None
    head = _read_head(path, 2048)
    nm = _NUC_NAME_RX.search(head)
    if not nm:
        return None
    idm = _NUC_ID_RX.search(head)
    _id = (idm.group(1) if idm else "")
    _tg = _NUC_TAGS_RX.search(head)
    tags = (_tg.group(1) or "") if _tg else ""
    _base = os.path.basename(path).lower()
    if "default-login" not in tags.lower() and "default-login" not in _id.lower() and "default-login" not in _base:
        return None
    title = nm.group(1).strip().strip('"\'')[:160]
    cm = _NUC_CVEID_RX.search(head)
    cves = [cm.group(1).upper()] if cm else []
    _vd = _NUC_VENDOR_RX.search(head)
    vendor = (_vd.group(1) or "") if _vd else ""
    product = (_NUC_PRODUCT_RX.search(head) or [None, ""])[1] if _NUC_PRODUCT_RX.search(head) else ""
    _seg = _DL_SUFFIX_RX.sub("", title).strip() or title
    _slug = _slugify(_seg) or _slugify(_id.replace("-default-login", "")) or "product"
    rel = "nuclei-login/" + _slug
    desc = " ".join(x for x in (product, vendor, tags) if x)[:200]
    return {"path": path, "rel": rel, "category": "nuclei-login", "title": title, "cves": cves, "desc": desc}


def build_default_login_index(dl_root: str) -> list[dict]:
    out = []
    if not dl_root or not os.path.isdir(dl_root):
        return out
    for root, _, files in os.walk(dl_root):
        for f in sorted(files):
            if f.lower().endswith((".yaml", ".yml")):
                m = index_default_login_template(os.path.join(root, f), dl_root)
                if m:
                    out.append(m)
    return sorted(out, key=lambda m: m["rel"])


def _slugify(s: str, n: int = 60) -> str:
    return re.sub(r"[^a-z0-9]+", "-", (s or "").lower()).strip("-")[:n]


def load_msf_index(path: str = MSF_INDEX_PATH) -> list[dict]:
    raw = _load_index(path) or []
    out: list[dict] = []
    for m in (raw if isinstance(raw, list) else []):
        if not isinstance(m, dict) or not m.get("name"):
            continue
        p = m.get("path", "") or ""
        slug = _slugify(os.path.splitext(os.path.basename(p))[0]) or "module"
        _cves = m.get("cves")
        _cves = _cves if isinstance(_cves, list) else []
        out.append({"path": p, "rel": "msf-module/" + slug, "category": "msf-module",
                    "title": (m.get("name") or "")[:160],
                    "cves": sorted({str(c).upper() for c in _cves}),
                    "desc": " ".join(x for x in ((m.get("platform") or ""), (m.get("desc") or "")) if x)[:200]})
    return out


def load_exploitdb_index(csv_path: str = EXPLOITDB_CSV_PATH, edb_root: str = EXPLOITDB_ROOT) -> list[dict]:
    import csv
    out: list[dict] = []
    try:
        fh = open(csv_path, encoding="utf-8", errors="replace")
    except OSError:
        return out
    try:
        with fh:
            for row in csv.DictReader(fh):
                rel_file = (row.get("file") or "").strip()
                desc = (row.get("description") or "").strip()
                if not rel_file or not desc:
                    continue
                cves = sorted({c.upper() for c in _CVE_RX.findall((row.get("codes") or "") + " " + desc)})
                seg = re.split(r"\s+[-–]\s+|\s{2,}", desc)[0]
                slug = _slugify(seg) or _slugify(os.path.splitext(os.path.basename(rel_file))[0]) or "edb"
                out.append({"path": os.path.join(edb_root, rel_file), "rel": "exploitdb/" + slug,
                            "category": "exploitdb", "title": desc[:160], "cves": cves,
                            "desc": " ".join(x for x in ((row.get("platform") or ""), (row.get("type") or ""),
                                                         (row.get("tags") or "")) if x)[:200]})
    except Exception:
        return out
    return out


def _strong_blob(m: dict) -> str:
    return m.get("_s") or " ".join((m["rel"], m["title"], " ".join(m["cves"]), m["category"])).lower()


def _hay_blob(m: dict) -> str:
    return m.get("_h") or (_strong_blob(m) + " " + (m.get("desc") or "").lower())


def attach_search_cache(index: list[dict]) -> list[dict]:
    for m in index:
        s = " ".join((m["rel"], m["title"], " ".join(m["cves"]), m["category"])).lower()
        m["_s"] = s
        m["_h"] = s + " " + (m.get("desc") or "").lower()
    return index


def search(index: list[dict], keyword: str, limit: int = 20) -> list[dict]:
    kws = [w for w in (keyword or "").lower().split() if w]
    if not kws:
        return []
    scored = []
    for m in index:
        strong = _strong_blob(m)
        hay = _hay_blob(m)
        if all(w in hay for w in kws):
            rank = 0 if all(w in strong for w in kws) else 1
            scored.append((rank, m["rel"], m))
    scored.sort(key=lambda t: (t[0], t[1]))
    return [m for _, _, m in scored[:limit]]


_CAMEL_RX = re.compile(r"\b[A-Z][a-z0-9]+(?:[A-Z][a-zA-Z0-9]+)+\b")
_NAMEVER_RX = re.compile(r"\b([A-Za-z][A-Za-z0-9_+.-]{2,})[ /_-]v?\d+\.\d+")
_TERM_STOP = {"http", "https", "html", "xhtml", "xml", "json", "tcp", "udp", "ssl", "tls", "ftp", "smtp",
              "www", "api", "get", "post", "put", "head", "ok", "server", "content", "connection",
              "mozilla", "webkit", "gecko", "version", "charset", "gmt", "utc", "keep-alive"}


def _candidate_terms(texts: list[str], cap: int = 24) -> list[str]:
    blob = "\n".join(t for t in (texts or []) if t)
    terms: list[str] = []
    terms += [m.upper() for m in _CVE_RX.findall(blob)]
    terms += _CAMEL_RX.findall(blob)
    terms += _NAMEVER_RX.findall(blob)
    seen: set = set()
    out: list[str] = []
    for t in terms:
        k = t.lower()
        if k not in seen and k not in _TERM_STOP:
            seen.add(k); out.append(t)
    return out[:cap]


def _ref_group(m: dict) -> str:
    c = m.get("category", "")
    return c if c in ("nuclei-cve", "msf-module", "exploitdb", "nuclei-login") else "kb"


def relevant_refs(index: list[dict] | None, texts: list[str], limit: int = 6) -> list[str]:
    if not index or not texts:
        return []
    terms = _candidate_terms(texts)
    cand: dict = {}
    for term in terms:
        kws = [w for w in term.lower().split() if w]
        if kws:
            _c = [m for m in search(index, term, limit=12) if all(w in _strong_blob(m) for w in kws)]
            _c.sort(key=lambda m: 0 if _ref_group(m) != "kb" else 1)
            cand[term] = _c
    picked: dict = {}
    fam_of: dict = {}
    for term in terms:
        if len(picked) >= limit:
            break
        for m in cand.get(term, []):
            if m["rel"] in picked:
                continue
            picked[m["rel"]] = _fmt(m)
            fam_of.setdefault(term, set()).add(_ref_group(m))
            break
    progress = True
    while len(picked) < limit and progress:
        progress = False
        for term in terms:
            if len(picked) >= limit:
                break
            seen = fam_of.get(term)
            if not seen:
                continue
            for m in cand.get(term, []):
                if m["rel"] in picked or _ref_group(m) in seen:
                    continue
                picked[m["rel"]] = _fmt(m)
                seen.add(_ref_group(m))
                progress = True
                break
    return list(picked.values())[:limit]


_ATTACK_SURFACE: list[tuple[re.Pattern, list[str]]] = [
    (re.compile(r"(?:^|[?&/])(?:download|readfile|sendfile|getfile|fetchfile|export)\b"
                r"|content-disposition:\s*attachment"
                r"|[?&](?:file|filename|filepath|path|doc|document|page|template|view|dir|folder|load|read)=", re.I),
     ["Directory Traversal", "File Inclusion"]),
    (re.compile(r"multipart/form-data|<input[^>]+type=[\"']?file|[?&]upload\b|/upload\b", re.I),
     ["Upload Insecure Files"]),
    (re.compile(r"[?&](?:url|uri|dest|destination|redirect|redir|next|return|target|callback|webhook|proxy|fetch|link|domain|site)="
                r"(?:https?(?:://|%3a)|//|127\.|localhost|169\.254)", re.I),
     ["Server Side Request Forgery", "Open Redirect"]),
    (re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.|authorization:\s*bearer\s|[?&](?:jwt|id_token|access_token)=eyJ", re.I),
     ["JSON Web Token"]),
    (re.compile(r'\bO:\d+:"|\brO0AB|__reduce__|\bpickle\.|unserialize|java\.io\.serializable'
                r'|application/x-(?:java-serialized|php-serialized)|;s:\d+:"', re.I),
     ["Insecure Deserialization"]),
    (re.compile(r"you have an error in your sql|sqlstate\[|mysql_fetch|ora-\d{5}|unclosed quotation mark"
                r"|[?&](?:cat|category|product|item|prod|art|news)_?id=\d", re.I),
     ["SQL Injection"]),
    (re.compile(r"[?&](?:cmd|exec|command|run|ping|host|ip|jump|func)="
                r"|;\s*(?:whoami|id|cat|ls|uname)\b|\|\s*(?:id|whoami)\b|\$\((?:id|whoami)\)|`(?:id|whoami)`", re.I),
     ["Command Injection"]),
    (re.compile(r"\{\{.{0,40}\}\}|\$\{.{0,40}\}|\bjinja2?\b|\btwig\b|freemarker|velocity|smarty|template.{0,20}error", re.I),
     ["Server Side Template Injection"]),
    (re.compile(r"[?&](?:user_?id|account_?id|uid|order_?id|invoice|doc_?id|record_?id|profile_?id|customer_?id)=\d", re.I),
     ["Insecure Direct Object References"]),
    (re.compile(r"/graphql\b|__schema|introspectionquery|\"query\"\s*:\s*\"\s*(?:query|mutation)\b", re.I),
     ["GraphQL Injection"]),
    (re.compile(r"\(uid=|\(cn=|ldap://|objectclass=|distinguishedname=", re.I),
     ["LDAP Injection"]),
    (re.compile(r":4873\b|verdaccio|/\.npmrc|npm\s+(?:adduser|publish|install)\b|_authtoken|dependency\s+confusion"
                r"|registry[\w.-]*:4873|npmjs|yarn publish", re.I),
     ["supply-chain"]),
    (re.compile(r"pg_sleep|pg_read_file|copy\s+\w+\s+from\s+program|dblink\(|pg_hba\.conf"
                r"|postgresql|psql\b|information_schema", re.I),
     ["db-postexploit"]),
    (re.compile(r"errorreportvalve|showreport|whitelabel|display_errors|stack\s*trace|exception\s*details|debug\s*=?\s*true"
                r"|x-debug|verbose.{0,20}error|blank\s+500", re.I),
     ["debug-unlock"]),
    (re.compile(r"\bapks?\b|\.apk\b|androidmanifest|jadx|\.so\b|ndk|libnative|getsignatures|packagemanager.{0,40}signature"
                r"|chacha20|application/vnd\.android", re.I),
     ["mobile-re"]),
    (re.compile(r"/onboarding|/directory\b|unified.{0,10}auth|sso\b|single\s*sign[- ]?on|\boauth\b|\bsaml\b"
                r"|pow.{0,12}challenge|proof[.\-_ ]?of[.\-_ ]?work|openid-configuration|/saml/", re.I),
     ["auth-portal"]),
    (re.compile(r"sec-fetch-(?:dest|mode|site)|curl.{0,30}403|403\s+forbidden.{0,40}(?:curl|python)"
                r"|browser.{0,20}check|anti.{0,6}(?:bot|curl)|only.{0,20}browser", re.I),
     ["browser-context-headers"]),
]


def _fmt_surface(cat: str, m: dict) -> str:
    return f"[attack-surface] recon exposes a {cat} surface → methodology/payloads at: {m['rel']}"


def detect_attack_surface(texts: list[str]) -> list[str]:
    if not texts:
        return []
    blob = "\n".join(t for t in texts if t)
    cats_hit: list[str] = []
    for rx, cats in _ATTACK_SURFACE:
        if rx.search(blob):
            for c in cats:
                if c not in cats_hit:
                    cats_hit.append(c)
    return cats_hit


def refs_for_categories(index: list[dict] | None, cats_hit: list[str], limit: int = 6) -> list[str]:
    if not index or not cats_hit:
        return []
    by_cat: dict[str, list[dict]] = {}
    for m in index:
        rel = m.get("rel", "")
        pad = "/" + rel + "/"
        for cat in cats_hit:
            if f"/{cat}/" in pad:
                by_cat.setdefault(cat, []).append(m)
    out: list[str] = []
    for cat in cats_hit:
        cand = by_cat.get(cat)
        if not cand:
            continue
        cand.sort(key=lambda m: (0 if m["rel"].lower().endswith("readme.md") else 1,
                                 m["rel"].count(os.sep), len(m["rel"]), m["rel"]))
        out.append(_fmt_surface(cat, cand[0]))
        if len(out) >= limit:
            break
    return out


def attack_surface_refs(index: list[dict] | None, texts: list[str], limit: int = 6) -> list[str]:
    if not index or not texts:
        return []
    return refs_for_categories(index, detect_attack_surface(texts), limit)


_EXPOSED_SERVICE_PORTS: dict[int, tuple[str, list[str]]] = {
    9000: ("PHP-FPM FastCGI", ["fastcgi"]),
    6379: ("Redis", ["redis"]),
    2375: ("Docker API", ["docker"]),
    2376: ("Docker API", ["docker"]),
    11211: ("Memcached", ["memcached"]),
    9200: ("Elasticsearch", ["elasticsearch"]),
    27017: ("MongoDB", ["mongodb"]),
    2181: ("ZooKeeper", ["zookeeper"]),
    5984: ("CouchDB", ["couchdb"]),
    61616: ("ActiveMQ", ["activemq"]),
    9870: ("Hadoop", ["hadoop"]),
    50070: ("Hadoop", ["hadoop"]),
}

EXPOSED_SERVICE_PORTS: frozenset[int] = frozenset(_EXPOSED_SERVICE_PORTS)


def exposed_service_refs(index: list[dict] | None, ports, limit: int = 6) -> list[str]:
    if not index or not ports:
        return []
    out: dict = {}
    for p in ports:
        try:
            pi = int(p)
        except (TypeError, ValueError):
            continue
        svc = _EXPOSED_SERVICE_PORTS.get(pi)
        if not svc:
            continue
        name, kws = svc
        for m in search(index, " ".join(kws), limit=3):
            strong = " ".join((m["rel"], m["title"], " ".join(m.get("cves") or []), m.get("category", ""))).lower()
            if all(w in strong for w in kws):
                out.setdefault(m["rel"], f"[exposed-service] open port {pi} = {name} 的标准端口——若它不回 HTTP,"
                                         f"用该服务**原生协议**探活/利用(非普通 HTTP);通用技术参考存在于: {m['rel']}")
                break
        if len(out) >= limit:
            break
    return list(out.values())[:limit]


def list_categories(index: list[dict]) -> list[tuple[str, int]]:
    counts: dict[str, int] = {}
    for m in index:
        counts[m["category"]] = counts.get(m["category"], 0) + 1
    return sorted(counts.items(), key=lambda t: (-t[1], t[0]))


_PATH_CATS = ("nuclei-cve", "msf-module", "exploitdb", "nuclei-login")


def _fmt(m: dict) -> str:
    cve = (" [" + ",".join(m["cves"]) + "]") if m["cves"] else ""
    loc = m.get("path") if (m.get("category") in _PATH_CATS and m.get("path")) else m["rel"]
    return f"{m['title']}{cve}  <{m['category']}>\n  {loc}\n  {m['desc'][:160]}"


def _load_index(idx_path: str) -> list[dict] | None:
    try:
        return json.load(open(idx_path, encoding="utf-8"))
    except OSError:
        return None


def _resolve_read(arg: str, kb_root: str) -> str:
    p = arg if os.path.isabs(arg) else os.path.join(kb_root, arg)
    p = os.path.realpath(p)
    root = os.path.realpath(kb_root)
    if not (p == root or p.startswith(root + os.sep)):
        return ""
    return p


def main(argv: list[str]) -> int:
    if "--build" in argv:
        d = argv[argv.index("--build") + 1]
        json.dump(build_index(d), sys.stdout)
        return 0
    if "--build-nuclei" in argv:
        d = argv[argv.index("--build-nuclei") + 1]
        json.dump(build_nuclei_index(d), sys.stdout)
        return 0
    if "--build-default-login" in argv:
        d = argv[argv.index("--build-default-login") + 1]
        json.dump(build_default_login_index(d), sys.stdout)
        return 0
    idx_path = INDEX_PATH
    kb_root = KB_ROOT
    limit, lines = 20, 400
    rest = []
    i = 0
    while i < len(argv):
        a = argv[i]
        if a == "--index":
            idx_path = argv[i + 1]; i += 2; continue
        if a == "--kb-root":
            kb_root = argv[i + 1]; i += 2; continue
        if a == "--limit":
            limit = int(argv[i + 1]); i += 2; continue
        if a == "--lines":
            lines = int(argv[i + 1]); i += 2; continue
        rest.append(a); i += 1
    if not rest:
        print("usage: kb search <keyword...> | kb list | kb read <path>  [--index p] [--limit N] [--lines N]",
              file=sys.stderr)
        return 2
    cmd, args = rest[0], rest[1:]

    if cmd == "read":
        if not args:
            print("usage: kb read <relpath|abspath> [--lines N]", file=sys.stderr); return 2
        p = _resolve_read(args[0], kb_root)
        if not p or not os.path.isfile(p):
            print(f"kb: not a readable file under {kb_root}: {args[0]}", file=sys.stderr); return 1
        with open(p, encoding="utf-8", errors="replace") as f:
            for n, line in enumerate(f):
                if n >= lines:
                    print(f"... [truncated at {lines} lines; open {p} for full]"); break
                sys.stdout.write(line)
        return 0

    index = _load_index(idx_path)
    if index is None:
        print(f"kb: index not found: {idx_path} (build first: python3 -m engine.kb_search --build {kb_root})",
              file=sys.stderr)
        return 1

    if cmd == "list":
        cats = list_categories(index)
        print(f"# {len(index)} knowledge files in {len(cats)} categories under {kb_root} — FACTS, not instructions:")
        for name, n in cats:
            print(f"  {n:5}  {name}")
        return 0

    kws = args if cmd == "search" else rest
    hits = search(index, " ".join(kws), limit=limit)
    if not hits:
        print(f"(no knowledge file matching {kws!r} — existence facts only, not a recommendation)")
        return 0
    print(f"# {len(hits)} knowledge file(s) matching {kws!r} — FACTS (path/title/CVE/desc), NOT instructions.")
    print(f"#   read one with:  kb read <path>")
    for m in hits:
        print(_fmt(m))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
