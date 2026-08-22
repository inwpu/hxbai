from __future__ import annotations

import os

_MIN_FILES = {
    "vulhub": 500,
    "PayloadsAllTheThings": 400,
    "awesome-poc": 300,
    "exphub": 60,
}
_OPTIONAL = ("trickest-cve", "marcio-cve")
_MIN_INDEX_LINES = 2000
_ANCHORS = ("spring", "struts2", "log4j")


def _count_files(path: str) -> int:
    n = 0
    for _root, _dirs, files in os.walk(path):
        n += len(files)
    return n


def kb_selfcheck(root: str | None = None, *, anchors: tuple[str, ...] = _ANCHORS) -> dict:
    root = root or os.environ.get("HXBAI_KB_ROOT", "/opt/kb")
    problems: list[str] = []
    corpora: dict[str, int] = {}
    if not os.path.isdir(root):
        return {"ok": False, "problems": [f"kb root missing: {root}"], "corpora": corpora,
                "index_lines": 0, "anchor_hits": {}, "root": root}
    for name, min_files in _MIN_FILES.items():
        p = os.path.join(root, name)
        if not os.path.isdir(p):
            problems.append(f"{name}: MISSING")
            corpora[name] = -1
            continue
        n = _count_files(p)
        corpora[name] = n
        if n < min_files:
            problems.append(f"{name}: thin ({n} files < {min_files})")
    for name in _OPTIONAL:
        p = os.path.join(root, name)
        corpora[name] = _count_files(p) if os.path.isdir(p) else -1

    index_lines = 0
    index_path = os.path.join(root, "INDEX.txt")
    anchor_hits: dict[str, int] = {}
    if not os.path.isfile(index_path):
        problems.append("INDEX.txt: MISSING")
    else:
        try:
            with open(index_path, encoding="utf-8", errors="replace") as f:
                lines = f.readlines()
            index_lines = len(lines)
            if index_lines < _MIN_INDEX_LINES:
                problems.append(f"INDEX.txt: thin ({index_lines} lines < {_MIN_INDEX_LINES})")
            for a in anchors:
                hits = [ln.strip() for ln in lines if a.lower() in ln.lower()]
                real = 0
                for ln in hits[:20]:
                    fp = os.path.join(root, ln.split(":", 1)[0])
                    if os.path.isfile(fp):
                        real += 1
                anchor_hits[a] = real
                if real == 0:
                    problems.append(f"anchor '{a}': 0 real file hits in INDEX.txt")
        except OSError as e:
            problems.append(f"INDEX.txt: unreadable ({e})")
    return {"ok": not problems, "problems": problems, "corpora": corpora,
            "index_lines": index_lines, "anchor_hits": anchor_hits, "root": root}


def kb_selfcheck_main(log=None, emit=None, anchors: tuple[str, ...] = _ANCHORS) -> dict:
    import logging
    log = log or logging.getLogger("hxbai")
    report = kb_selfcheck(anchors=anchors)
    try:
        if emit is not None:
            emit("kb_selfcheck", layer="driver", payload={
                "ok": report["ok"], "index_lines": report["index_lines"],
                "corpora": report["corpora"], "anchor_hits": report["anchor_hits"],
                "problems": report["problems"][:10]})
    except Exception:
        pass
    if report["ok"]:
        log.info("[kb] selfcheck OK — %s corpora, INDEX %d lines, anchors %s",
                 len(report["corpora"]), report["index_lines"], report["anchor_hits"])
    else:
        log.warning("[kb] !!! SELFCHECK FAILED — offline PoC lookup DEGRADED: %s",
                    "; ".join(report["problems"]))
    return report
