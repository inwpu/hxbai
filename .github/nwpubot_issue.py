#!/usr/bin/env python3
"""nwpubot 直推 main 的 issue 管理。

行为：
- 本次直推引入了新高危(bandit 改动文件高危 + semgrep 新增 ERROR)：
  维护一个带 nwpubot 标签的开放 issue，@提交人、列出明细，
  正文里用 HTML 注释存指纹清单(path|rule)，供后续核对。
- 本次直推干净且存在开放 issue：全量重扫，若指纹清单里的项全部消失
  则自动关闭 issue；否则留言还剩几处、保持开放。
- json 不存在(扫描中断)：不动 issue，保持现状。

环境变量：GH_TOKEN, GITHUB_REPOSITORY, BASE_SHA, HEAD_SHA, PUSHER
文件输入：bandit.json(全量), semgrep.json(本次 baseline 过滤后)
"""
import json
import os
import subprocess
import sys

LABEL = "nwpubot"
TRACK_MARK = "<!-- nwpubot-tracked:"


def sh(*args, **kw):
    try:
        return subprocess.run(args, capture_output=True, text=True, **kw)
    except FileNotFoundError:
        class _E:  # 二进制不存在时降级为空输出，不让脚本崩
            stdout, stderr, returncode = "", "", 127
        return _E()


def norm(p):
    p = p or ""
    return p[2:] if p.startswith("./") else p


def gh(*args):
    r = sh("gh", *args)
    if r.returncode != 0:
        print(f"[bot] gh {' '.join(args[:3])}... 失败: {r.stderr.strip()[:200]}")
    return r.stdout.strip()


def load_json(path):
    if not os.path.exists(path):
        return None
    try:
        return json.load(open(path))
    except Exception:
        return None


def changed_py(base, head):
    r = sh("git", "diff", "--name-only", f"{base}...{head}")
    return [l for l in r.stdout.splitlines() if l.endswith(".py")]


def findings_new(bandit, semgrep, changed):
    items = []
    for r in (bandit or {}).get("results", []):
        if norm(r.get("filename")) in {norm(c) for c in changed}:
            items.append({"f": norm(r["filename"]), "line": r.get("line_number"), "rule": r.get("test_id", "?"),
                          "msg": (r.get("issue_text") or "")[:120]})
    for r in (semgrep or {}).get("results", []):
        if r.get("extra", {}).get("severity") == "ERROR":
            items.append({"f": norm(r["path"]), "line": r.get("start", {}).get("line"), "rule": r.get("check_id", "?"),
                          "msg": (r.get("extra", {}).get("message") or "")[:120]})
    return items


def full_current():
    """全量重扫(不带 baseline)，返回当前 ERROR 级指纹集合 (path, rule)。"""
    cur = set()
    b = load_json("bandit.json")
    for r in (b or {}).get("results", []):
        cur.add((norm(r["filename"]), r.get("test_id", "?")))
    r = sh("semgrep", "scan", "--config", "p/secrets", "--config", "p/python",
           "--json", "--metrics=off")
    try:
        for x in json.loads(r.stdout).get("results", []):
            if x.get("extra", {}).get("severity") == "ERROR":
                cur.add((norm(x["path"]), x.get("check_id", "?")))
    except Exception:
        pass
    return cur


def open_issues():
    repo = os.environ.get("GITHUB_REPOSITORY", "")
    nums = gh("issue", "list", "-R", repo, "--label", LABEL, "--state", "open",
              "--json", "number", "--jq", ".[].number")
    res = []
    for n in nums.split():
        # body 是多行文本，issue list 的 jq 拼接会丢行，必须逐个 view 拿全文
        body = gh("issue", "view", n, "-R", repo, "--json", "body", "--jq", ".body")
        res.append((int(n), body))
    return res


def tracked_set(body):
    for line in body.splitlines():
        if line.startswith(TRACK_MARK):
            inner = line[len(TRACK_MARK):].strip().rstrip(">").strip()
            s = set()
            for pair in inner.split(";"):
                if "|" in pair:
                    f, _, rule = pair.partition("|")
                    s.add((norm(f), rule.strip()))
            return s
    return set()


def fmt_tracked(items):
    return TRACK_MARK + ";".join(f"{i['f']}|{i['rule']}" for i in items) + "-->"


def fmt_body(pusher, items, head):
    lines = [
        f"**main 直推引入了未修复的高危问题**（pusher: @{pusher}，HEAD `{head[:8]}`）",
        "",
        "| 位置 | 规则 | 说明 |",
        "|---|---|---|",
    ]
    for i in items:
        lines.append(f"| `{i['f']}:{i['line']}` | `{i['rule']}` | {i['msg']} |")
    lines += [
        "",
        "修复并直推（或走 PR）后，机器人会自动重扫；全部清零时本 issue 自动关闭。",
        "",
        fmt_tracked(items),
    ]
    return "\n".join(lines)


def main():
    pusher = os.environ.get("PUSHER", "")
    head = os.environ.get("HEAD_SHA", "")
    base = os.environ.get("BASE_SHA", "")
    repo = os.environ.get("GITHUB_REPOSITORY", "")

    bandit = load_json("bandit.json")
    semgrep = load_json("semgrep.json")
    if bandit is None and semgrep is None:
        print("[bot] 扫描产物缺失(可能被更早步骤拦下)，不动 issue。")
        return 0

    gh("label", "create", LABEL, "--color", "d73a4a", "--force", "-R", repo)  # 幂等

    changed = changed_py(base, head) if base and head else []
    items = findings_new(bandit, semgrep, changed)
    issues = open_issues()

    if items:
        body = fmt_body(pusher, items, head)
        if issues:
            num = issues[0][0]
            gh("issue", "comment", str(num), "-R", repo, "--body-file", write_tmp(body))
            print(f"[bot] 新增高危 {len(items)} 处，已评论 issue #{num}")
        else:
            url = gh("issue", "create", "-R", repo, "-t", "main 存在未修复高危(nwpubot)",
                     "--label", LABEL, "--body-file", write_tmp(body))
            if url:
                print(f"[bot] 新增高危 {len(items)} 处，已开 issue: {url}")
            else:
                print("[bot] issue create 失败(权限?)，高危未登记成 issue！")
                return 1
        return 0

    if not issues:
        print("[bot] 干净且无开放 issue，无事可做。")
        return 0

    cur = full_current()
    for num, body in issues:
        tracked = tracked_set(body)
        remain = sorted(tracked & cur)
        if tracked and not remain:
            gh("issue", "close", str(num), "-R", repo,
               "-c", "追踪的高危已全部修复，自动关闭。")
            print(f"[bot] issue #{num} 的 {len(tracked)} 项已全清，自动关闭。")
        elif remain:
            gh("issue", "comment", str(num), "-R", repo, "--body-file",
                write_tmp(f"本次直推干净，但仍有 {len(remain)} 处未修复：\n" +
                          "\n".join(f"- `{f}` `{r}`" for f, r in remain)))
            print(f"[bot] issue #{num} 仍开放，剩 {len(remain)} 处。")
    return 0


def write_tmp(text):
    import tempfile
    fd, p = tempfile.mkstemp(suffix=".md")
    with os.fdopen(fd, "w") as f:
        f.write(text)
    return p


if __name__ == "__main__":
    sys.exit(main())
