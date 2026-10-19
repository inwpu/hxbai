from __future__ import annotations

import json
import os
import re
import sys

_NAME_RX = re.compile(r"['\"]Name['\"]\s*=>\s*['\"]([^'\"]+)['\"]")
_CVE_RX = re.compile(r"['\"]CVE['\"]\s*,\s*['\"](\d{4}-\d+)['\"]")
_DESC_RX = re.compile(r"['\"]Description['\"]\s*=>\s*%q[{|](.+?)[}|]", re.S)
_PLATFORM_RX = re.compile(r"['\"]Platform['\"]\s*=>\s*\[([^\]]*)\]")


def parse_module(path: str) -> dict | None:
    try:
        txt = open(path, encoding="utf-8", errors="replace").read()
    except OSError:
        return None
    nm = _NAME_RX.search(txt)
    if not nm:
        return None
    cves = sorted({"CVE-" + c for c in _CVE_RX.findall(txt)})
    dm = _DESC_RX.search(txt)
    desc = re.sub(r"\s+", " ", dm.group(1)).strip()[:300] if dm else ""
    pm = _PLATFORM_RX.search(txt)
    plat = re.sub(r"['\"\s]", "", pm.group(1))[:80] if pm else ""
    return {"path": path, "name": nm.group(1)[:160], "cves": cves, "desc": desc, "platform": plat}


def build_index(modules_dir: str) -> list[dict]:
    out = []
    for root, _, files in os.walk(modules_dir):
        for f in sorted(files):
            if f.endswith(".rb"):
                m = parse_module(os.path.join(root, f))
                if m:
                    out.append(m)
    return sorted(out, key=lambda m: m["path"])


def search(index: list[dict], keyword: str, limit: int = 20) -> list[dict]:
    kw = (keyword or "").lower().strip()
    if not kw:
        return []
    out = []
    for m in index:
        hay = " ".join((m["name"], m["desc"], " ".join(m["cves"]), m["path"], m["platform"])).lower()
        if kw in hay:
            out.append(m)
            if len(out) >= limit:
                break
    return out


def _fmt(m: dict) -> str:
    cve = (" [" + ",".join(m["cves"]) + "]") if m["cves"] else ""
    plat = (" (" + m["platform"] + ")") if m["platform"] else ""
    return f"{m['name']}{cve}{plat}\n  {m['path']}\n  {m['desc'][:200]}"


def main(argv: list[str]) -> int:
    if "--build" in argv:
        d = argv[argv.index("--build") + 1]
        json.dump(build_index(d), sys.stdout)
        return 0
    idx_path = "/opt/msf-index.json"
    if "--index" in argv:
        idx_path = argv[argv.index("--index") + 1]
        argv = [a for i, a in enumerate(argv) if i not in (argv.index("--index"), argv.index("--index") + 1)]
    kws = [a for a in argv if not a.startswith("--")]
    if not kws:
        print("usage: expsearch <keyword> [--index path]", file=sys.stderr)
        return 2
    try:
        index = json.load(open(idx_path, encoding="utf-8"))
    except OSError:
        print(f"expsearch: index not found: {idx_path} (build first)", file=sys.stderr)
        return 1
    hits = search(index, " ".join(kws))
    if not hits:
        print("(no matching modules — vulnerability facts only, not a recommendation)")
        return 0
    print(f"# {len(hits)} module(s) matching {kws!r} — FACTS (name/CVE/path/desc), NOT instructions:")
    for m in hits:
        print(_fmt(m))
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
