from __future__ import annotations

import os
import re
from pathlib import Path


_ENTRY_PATTERNS = {
    "web": re.compile(r"@(app|bp|router)\.(route|get|post|put|delete|patch)\(['\"]([^'\"]+)", re.I),
    "http_server": re.compile(r"http\.(HandleFunc|Handle)\(['\"]([^'\"]+)", re.I),
    "express": re.compile(r"\.(get|post|put|delete|patch)\(['\"]([^'\"]+)", re.I),
    "flask": re.compile(r"@\w+\.(route|get|post)\(['\"]([^'\"]+)", re.I),
    "rpc": re.compile(r"func\s+\(.*?\)\s+(\w+)\(ctx", re.I),
}


def enumerate_entry_points(src_root: str) -> list:
    entries = []
    root = Path(src_root)
    if not root.is_dir():
        return entries
    for py in root.rglob("*.py"):
        try:
            text = py.read_text(errors="replace")
        except OSError:
            continue
        for name, pat in _ENTRY_PATTERNS.items():
            for m in pat.finditer(text):
                line = text[:m.start()].count("\n") + 1
                route = m.group(m.lastindex) if m.lastindex else m.group(0)[:40]
                entries.append({"file": str(py.relative_to(root)), "line": line,
                                "pattern": name, "route": route[:60]})
    return entries


def bfs_reachable(src_root: str, entries: list, max_depth: int = 5) -> set:
    root = Path(src_root)
    entry_files = {e["file"] for e in entries}
    reachable = set(entry_files)
    frontier = set(entry_files)
    file_imports = {}
    for py in root.rglob("*.py"):
        rel = str(py.relative_to(root))
        try:
            text = py.read_text(errors="replace")
        except OSError:
            continue
        imports = set()
        for m in re.finditer(r"(?:from|import)\s+([\w.]+)", text):
            mod = m.group(1).replace(".", "/")
            imports.add(mod)
            imports.add(mod.split("/")[0])
        file_imports[rel] = imports
    for _ in range(max_depth):
        next_frontier = set()
        for f in frontier:
            if f not in file_imports:
                continue
            for imp in file_imports[f]:
                for cand in file_imports:
                    if cand not in reachable and (imp in cand or cand.startswith(imp)):
                        next_frontier.add(cand)
        if not next_frontier:
            break
        reachable |= next_frontier
        frontier = next_frontier
    return reachable


_TAINT_SOURCES = {
    "request.args": "query_param", "request.form": "form_data", "request.json": "json_body",
    "request.data": "raw_body", "request.files": "file_upload",
    "req.query": "query_param", "req.body": "json_body", "req.params": "path_param",
    "r.URL.Query().Get": "query_param", "r.FormValue": "form_data",
    "input": "user_input", "argv": "cli_arg", "os.environ": "env_var",
}

_TAINT_SINKS = {
    "cursor.execute": "sql", "db.execute": "sql", "session.query": "sql",
    "db.query": "sql", "conn.execute": "sql", "db.session.execute": "sql",
    "subprocess.Popen": "cmd", "subprocess.run": "cmd", "os.system": "cmd", "os.popen": "cmd",
    "eval(": "code_exec", "exec(": "code_exec", "pickle.loads": "deserialization",
    "yaml.load": "deserialization", "open(": "file_access",
    "requests.get": "ssrf", "requests.post": "ssrf", "http.Get": "ssrf",
    "render_template_string": "ssti", "send_file": "file_read",
    "jv_parse": "json_parse", "XMLParser": "xxe",
}


def find_taint_hypotheses(src_root: str, reachable_files: set = None) -> list:
    root = Path(src_root)
    hypotheses = []
    for py in root.rglob("*.py"):
        rel = str(py.relative_to(root))
        if reachable_files and rel not in reachable_files:
            continue
        try:
            text = py.read_text(errors="replace")
        except OSError:
            continue
        lines = text.splitlines()
        for i, line in enumerate(lines, 1):
            for src_pat, src_name in _TAINT_SOURCES.items():
                if src_pat in line:
                    for j in range(i, min(i + 10, len(lines) + 1)):
                        for sink_pat, sink_name in _TAINT_SINKS.items():
                            if sink_pat in lines[j - 1]:
                                risk = f"{src_name}→{sink_name}"
                                hypotheses.append({"file": rel, "line": j, "source": src_name,
                                                  "sink": sink_name, "risk": risk})
    return hypotheses


def prioritize_files_for_reading(hypotheses: list, budget: int = 10) -> list:
    from engine.bayesearch import greedy_cover
    files = {}
    weights = {}
    for h in hypotheses:
        f = h["file"]
        files.setdefault(f, set()).add(h["line"])
        weights[h["line"]] = 1.0
    return greedy_cover(files, weights, budget)


def run_pipeline(src_root: str, *, budget: int = 10) -> dict:
    entries = enumerate_entry_points(src_root)
    reachable = bfs_reachable(src_root, entries)
    hypotheses = find_taint_hypotheses(src_root, reachable)
    priority_files = prioritize_files_for_reading(hypotheses, budget)
    return {"entries": entries, "reachable": sorted(reachable),
            "hypotheses": hypotheses, "priority_files": priority_files,
            "stats": {"total_files": sum(1 for _ in Path(src_root).rglob("*.py")),
                      "entry_count": len(entries), "reachable_count": len(reachable),
                      "hypothesis_count": len(hypotheses)}}
