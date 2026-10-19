#!/usr/bin/env python3
import argparse
import os
import shutil
import subprocess
import sys
import time

DOCKERFILE = "Dockerfile.all"
DEFAULT_TAG = "hxctf:v1"
DEFAULT_PROXY_PORT = 7897
PROXY_HOST = "host.docker.internal"
CONTEXT_DIRS = ["engine", "solver", "kb-extra"]
REQUIRED_FILES = [DOCKERFILE, "engine/kb_search.py", "solver/run.sh",
                  "kb-extra/crypto-attacks", "kb-extra/lang-jails", "kb-extra/web-logic"]


def _enable_ansi():
    if os.environ.get("NO_COLOR") is not None or not sys.stdout.isatty():
        return False
    if os.name == "nt":
        try:
            import ctypes
            k = ctypes.windll.kernel32
            k.SetConsoleMode(k.GetStdHandle(-11), 7)
        except Exception:
            return False
    return True


_COLOR = _enable_ansi()


def c(msg, color=""):
    codes = {"g": "92", "y": "93", "r": "91", "b": "96", "": ""}
    if color and _COLOR:
        return f"\033[{codes.get(color,'')}m{msg}\033[0m"
    return msg


def run(cmd, **kw):
    print(c("$ " + " ".join(cmd), "b"), flush=True)
    return subprocess.call(cmd, **kw)


def preflight(args):
    print(c("=== [1/4] 前置自检 ===", "y"))
    if shutil.which("docker") is None:
        print(c("✗ 找不到 docker 命令。请安装并启动 Docker Desktop,确保它在 PATH 中。", "r"))
        sys.exit(2)
    rc = subprocess.call(["docker", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    if rc != 0:
        print(c("✗ `docker version` 失败。请确认 Docker Desktop 已启动(鲸鱼图标常亮)。", "r"))
        sys.exit(2)
    print(c("  ✓ docker 可用", "g"))

    here = os.getcwd()
    missing = [p for p in REQUIRED_FILES if not os.path.exists(p)]
    if missing:
        print(c(f"✗ 当前目录 {here} 缺少构建上下文:", "r"))
        for m in missing:
            print(c(f"    - {m}", "r"))
        print(c("  请把 Dockerfile.all、engine/、solver/、kb-extra/、.dockerignore 一起拷到同一目录,"
                "并在该目录运行本脚本。", "r"))
        sys.exit(2)
    print(c(f"  ✓ 构建上下文齐全({', '.join(CONTEXT_DIRS)} + {DOCKERFILE})", "g"))

    if not os.path.exists(".dockerignore"):
        print(c("  ⚠ 未发现 .dockerignore —— 整个目录(可能含 2.7G 的 .tar.gz)会被当构建上下文上传,"
                "强烈建议把仓库里的 .dockerignore 一并拷过来。", "y"))
    else:
        print(c("  ✓ .dockerignore 就位(上下文已裁剪到 ~8MB)", "g"))

    if not args.no_proxy:
        print(c(f"  · 构建将经本地代理(Clash/v2ray 均可):http://{PROXY_HOST}:{args.proxy_port}", "b"))
        try:
            import socket
            s = socket.create_connection(("127.0.0.1", args.proxy_port), timeout=2)
            s.close()
            print(c(f"    ✓ 本机 127.0.0.1:{args.proxy_port} 有服务在听", "g"))
        except Exception:
            print(c(f"    ⚠ 本机 127.0.0.1:{args.proxy_port} 连不上 —— 确认代理已启动且 HTTP/混合端口=该端口。", "y"))
            print(c("    ⚠ 继续构建大概率得到空工具/空知识库层(失败被吞进缓存);先修代理。", "y"))
        _probe = subprocess.run(["docker", "run", "--rm", "alpine", "sh", "-c",
                                 f"apk add -q curl >/dev/null 2>&1; curl -s -m 10 -x "
                                 f"http://{PROXY_HOST}:{args.proxy_port} -o /dev/null -w '%{{http_code}}' https://github.com"],
                                capture_output=True, text=True, timeout=90)
        if _probe.stdout.strip().endswith("200"):
            print(c(f"    ✓ 容器视角经 {PROXY_HOST}:{args.proxy_port} 转发 github → 200(真转发,可构建)", "g"))
        else:
            print(c(f"    ✗ 容器视角经 {PROXY_HOST}:{args.proxy_port} 打 github 失败({_probe.stdout.strip() or 'no output'})——"
                    "TCP 通≠能转发;先修代理再构建,否则空层进缓存。", "r"))
            print(c("  中止:代理不可转发时继续构建会把空工具/空 kb 层吞进缓存(1015 实锤);修好代理或 --no-proxy 后重试。", "r"))
            sys.exit(1)
    else:
        print(c("  · --no-proxy:不走代理(仅当本机能直连 github 时可用)", "b"))


def _out(cmd):
    try:
        return subprocess.run(cmd, capture_output=True, text=True, encoding="utf-8", errors="replace").stdout or ""
    except Exception:
        return ""


def _image_exists(tag):
    return subprocess.call(["docker", "image", "inspect", tag],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def _current_builder():
    for line in _out(["docker", "buildx", "ls"]).splitlines():
        if not line.strip() or line.startswith(" ") or line.startswith("NAME"):
            continue
        parts = line.split()
        if parts and parts[0].endswith("*"):
            return parts[0].rstrip("*"), (parts[1] if len(parts) > 1 else "")
    return "", ""


def _inspect_builder(name):
    out = _out(["docker", "buildx", "inspect", name])
    if not out:
        return "", False
    driver, err = "", False
    for l in out.splitlines():
        s = l.strip()
        if s.startswith("Driver:"):
            driver = s.split(":", 1)[1].strip()
        if s.startswith("Error:") and len(s) > len("Error:"):
            err = True
    return driver, (bool(driver) and not err)


def ensure_cache_builder():
    cur_name, cur_driver = _current_builder()
    if cur_driver == "docker":
        print(c(f"  ✓ 当前 builder={cur_name}(docker 驱动):缓存存镜像库,跨构建持久", "g"))
        _print_cache_du(cur_name)
        return
    print(c(f"  · 当前 builder={cur_name}(驱动={cur_driver or '?'})—— 缓存不持久(容器重建即丢);找 docker 驱动的 builder...", "b"))
    for cand in ("default", "desktop-linux", "docker"):
        if cand == cur_name:
            continue
        drv, ok = _inspect_builder(cand)
        if ok and drv == "docker":
            subprocess.call(["docker", "buildx", "use", cand],
                            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
            print(c(f"    ✓ 已切到 builder={cand}(docker 驱动):缓存将跨构建持久", "g"))
            _print_cache_du(cand)
            return
    print(c("    ⚠ 没找到可用的 docker 驱动 builder —— 本次仍可能从 0。手动排查:`docker buildx ls`;"
            "Docker Desktop 一般有个 docker 驱动的 default/desktop-linux,设为默认即可。", "y"))


def _print_cache_du(name):
    du = _out(["docker", "buildx", "du", "--builder", name])
    tail = [l for l in du.splitlines() if l.strip()]
    if tail:
        print(c(f"    {name} 缓存:{tail[-1].strip()}", "b"))


def build(args):
    print(c("\n=== [2/4] docker build(改 Dockerfile 后:命中缓存则只重建改动层及其后;从 0 约 30–60 分钟)===", "y"))
    print(c("  (每一步日志会实时打印 —— --progress=plain + 直通终端,随时可见进度)", "b"))
    ensure_cache_builder()
    cmd = ["docker", "build", "-f", DOCKERFILE, "-t", args.tag, "--progress=plain"]
    cmd += ["--build-arg", "BUILDKIT_INLINE_CACHE=1"]
    if _image_exists(args.tag):
        cmd += ["--cache-from", args.tag]

    if not args.no_proxy:
        purl = f"http://{PROXY_HOST}:{args.proxy_port}"
        for k in ("HTTP_PROXY", "HTTPS_PROXY", "http_proxy", "https_proxy"):
            cmd += ["--build-arg", f"{k}={purl}"]
        noproxy = ("localhost,127.0.0.1,"
                   "mirrors.aliyun.com,mirrors.bfsu.edu.cn,mirrors.ustc.edu.cn,"
                   "mirrors.tuna.tsinghua.edu.cn,mirrors.cloud.tencent.com")
        for k in ("NO_PROXY", "no_proxy"):
            cmd += ["--build-arg", f"{k}={noproxy}"]

    if args.marcio:
        cmd += ["--build-arg", "KB_MARCIO=1"]
    if args.trickest:
        cmd += ["--build-arg", "KB_TRICKEST=1"]

    cmd += ["."]

    t0 = time.time()
    rc = run(cmd)
    dur = int(time.time() - t0)
    if rc != 0:
        print(c(f"\n✗ docker build 失败(退出码 {rc},耗时 {dur//60}m{dur%60}s)。", "r"))
        print(c("  常见原因:① 代理未就绪/不可转发(v2ray/Clash) → github/MSF clone 全失败;"
                "② 某 P0 工具缺失触发 base 自检 exit 1(日志里搜 'BUILD FAILED: P0 tools missing');"
                "③ 磁盘不足(需 ~25GB 构建空间)。", "y"))
        sys.exit(rc)
    print(c(f"\n  ✓ 构建成功:{args.tag}(耗时 {dur//60}m{dur%60}s)", "g"))


def report(args):
    print(c("\n=== [3/4] 镜像信息 ===", "y"))
    run(["docker", "images", args.tag])


_CHECK_SCRIPT = r'''
set +e
fail_p0=""; warn_opt=""
chk_bin(){ grp=$1; shift; for b in "$@"; do if command -v "$b" >/dev/null 2>&1; then printf "  OK   %s\n" "$b"; \
  else if [ "$grp" = p0 ]; then printf "  MISS %s\n" "$b"; fail_p0="$fail_p0 $b"; else printf "  warn %s\n" "$b"; warn_opt="$warn_opt $b"; fi; fi; done; }
chk_py(){ grp=$1; shift; for m in "$@"; do if python3 -c "import $m" >/dev/null 2>&1; then printf "  OK   py:%s\n" "$m"; \
  else if [ "$grp" = p0 ]; then printf "  MISS py:%s\n" "$m"; fail_p0="$fail_p0 py:$m"; else printf "  warn py:%s\n" "$m"; warn_opt="$warn_opt py:$m"; fi; fi; done; }

echo "===== 功能全量检查 ====="
echo "--- P0 二进制(必备)---"
chk_bin p0 node python3 curl wget git jq rg nmap ffuf gobuster sqlmap nikto whatweb tshark binwalk foremost exiftool steghide xxd zip unzip file gdb radare2 objdump strings hydra john socat ncat proxychains4 tmux openvpn java unsquashfs tesseract redis-cli psql php nc ssh sshpass
echo "--- claude 原生引擎(必备)---"
if claude --version >/dev/null 2>&1; then echo "  OK   claude ($(claude --version 2>&1|head -1))"; else echo "  MISS claude"; fail_p0="$fail_p0 claude"; fi
echo "--- P0 Python 库(必备)---"
chk_py p0 Crypto z3 pwn PIL scapy lxml scipy sympy impacket
echo "--- 可选二进制(缺=降级,不致命)---"
chk_bin opt hashcat chisel nuclei cloudfox cdk gh analyzeHeadless forge cast anvil gdb-multiarch tcpdump masscan zsteg stegsolve ilspycmd GoReSym jadx apktool searchsploit jwt_tool kb expsearch xform-solve length-extension flask-unsign bc ip ss traceroute sox RsaCtfTool rsacrack pike pike8.0
echo "--- 可选 Python 库(缺=降级)---"
chk_py opt web3 requests httpx yaml openai jwt pydash pymysql pytesseract keystone tqdm websocket base58 word2number fitz pyfinite ortools cheb3 solana solders rapidocr_onnxruntime
echo "--- 弹药/知识库 ---"
KB=$(wc -l < /opt/kb/INDEX.txt 2>/dev/null || echo 0); echo "  kb INDEX: $KB files"; [ "$KB" -gt 2000 ] || warn_opt="$warn_opt kb_index_thin"
test -s /opt/kb-index.json && echo "  kb-index.json: OK" || { echo "  kb-index.json: MISS(降级)"; warn_opt="$warn_opt kb-index.json"; }
MSF=$(python3 -c "import json;print(len(json.load(open('/opt/msf-index.json'))))" 2>/dev/null || echo 0); echo "  msf modules: $MSF"; [ "$MSF" -gt 1000 ] || warn_opt="$warn_opt msf_thin"
test -d /usr/share/seclists && echo "  SecLists: OK" || { echo "  SecLists: MISS(降级)"; warn_opt="$warn_opt seclists"; }
RY=$(wc -l < /usr/share/wordlists/rockyou.txt 2>/dev/null || echo 0); echo "  rockyou: $RY lines"
echo "--- 执行器 UID(61000,非 root)可访问性 ---"
setpriv --reuid 61000 --regid 61000 --clear-groups sh -c '
  python3 -c "import jwt" 2>/dev/null && echo "  OK   pyjwt 导入" || echo "  warn pyjwt 导入";
  (kb list >/dev/null 2>&1) && echo "  OK   kb 检索中间件" || echo "  warn kb 检索中间件";
  (expsearch nginx >/dev/null 2>&1) && echo "  OK   expsearch" || echo "  warn expsearch";
  (head -1 /opt/kb/INDEX.txt >/dev/null 2>&1) && echo "  OK   /opt/kb 读" || echo "  warn /opt/kb 读";
  (head -1 /usr/share/wordlists/rockyou.txt >/dev/null 2>&1) && echo "  OK   rockyou 读" || echo "  warn rockyou 读";
' 2>/dev/null
echo "--- 出口 / 入口 ---"
echo "  HXCTF_EGRESS=$HXCTF_EGRESS  HXCTF_LLM_EGRESS=$HXCTF_LLM_EGRESS"
[ "$HXCTF_LLM_EGRESS" = tsecbench ] && echo "  OK   LLM 出口=tsecbench(托管网关改写生效)" || { echo "  MISS LLM 出口!=tsecbench"; fail_p0="$fail_p0 llm_egress"; }
test -x /app/solver/run.sh && echo "  OK   入口 run.sh" || { echo "  MISS run.sh"; fail_p0="$fail_p0 run.sh"; }
test -s /app/engine/profiles/tsecbench.json && echo "  OK   profiles/tsecbench.json(网关数据)" || { echo "  MISS tsecbench.json"; fail_p0="$fail_p0 tsecbench.json"; }
echo "===== 结论 ====="
[ -z "$fail_p0" ] && echo "P0_MISSING: none" || echo "P0_MISSING:$fail_p0"
[ -z "$warn_opt" ] && echo "OPT_DEGRADED: none" || echo "OPT_DEGRADED:$warn_opt"
if [ -n "$fail_p0" ]; then echo "VERDICT: P0_MISSING"; elif [ -n "$warn_opt" ]; then echo "VERDICT: DEGRADED_ONLY"; else echo "VERDICT: ALL_OK"; fi
'''


def _parse_tail(out, key):
    for line in out.splitlines():
        s = line.strip()
        if s.startswith(key):
            return s[len(key):].strip()
    return ""


def function_check(args):
    print(c("\n=== [4/4] 全量功能检查(工具 / 库 / 弹药 / 执行器可访问性 / 出口)===", "y"))
    try:
        p = subprocess.run(["docker", "run", "--rm", "--entrypoint", "bash", args.tag, "-lc", _CHECK_SCRIPT],
                           capture_output=True, text=True, encoding="utf-8", errors="replace")
    except Exception as e:
        print(c(f"  ✗ 无法启动检查容器:{e}", "r"))
        return False
    out = p.stdout or ""
    print(out.rstrip())
    if p.returncode != 0 and p.stderr:
        print(c("  (stderr)", "y"), p.stderr.strip()[:500])

    verdict = _parse_tail(out, "VERDICT:")
    p0 = _parse_tail(out, "P0_MISSING:")
    opt = _parse_tail(out, "OPT_DEGRADED:")
    print(c("\n---------------- 结论 ----------------", "y"))
    if verdict == "ALL_OK":
        print(c("  ✅ 全部功能正常:P0 工具/库/弹药/执行器可访问性/出口 全部就位。", "g"))
        return True
    if verdict == "DEGRADED_ONLY":
        print(c("  ✅ 核心(P0)全部就位,镜像可用。", "g"))
        print(c(f"  ⚠ 以下为可选能力降级(非致命,通常是构建期网络抖动;重跑 build 多半能补回):\n      {opt}", "y"))
        return True
    if verdict == "P0_MISSING":
        print(c(f"  ❌ 缺少关键 P0 能力(镜像不可靠,需排查后重建):{p0}", "r"))
        if opt and opt != "none":
            print(c(f"  (另有可选降级:{opt})", "y"))
        return False
    print(c("  ⚠ 未能解析检查结论,请人工核对上面的逐项输出。", "y"))
    return False


def main():
    ap = argparse.ArgumentParser(description="从 0 构建 hxctf 镜像(Windows / Docker Desktop / Clash 7897)")
    ap.add_argument("--tag", default=DEFAULT_TAG, help=f"镜像 tag(默认 {DEFAULT_TAG})")
    ap.add_argument("--proxy-port", type=int, default=DEFAULT_PROXY_PORT, help=f"Clash 端口(默认 {DEFAULT_PROXY_PORT})")
    ap.add_argument("--no-proxy", action="store_true", help="不走代理(仅当能直连 github)")
    ap.add_argument("--marcio", action="store_true", help="纳入 marcio-cve 语料(~1.2GB)")
    ap.add_argument("--trickest", action="store_true", help="纳入 trickest-cve 语料(~1GB)")
    ap.add_argument("--no-check", action="store_true", help="跳过构建后的全量功能检查(默认会检查)")
    args = ap.parse_args()

    print(c("================ hxctf 镜像从-0 构建 ================", "y"))
    preflight(args)
    build(args)
    report(args)
    ok = True
    if not args.no_check:
        ok = function_check(args)
    print(c("\n全部完成。运行镜像示例(托管平台会注入 SOLVER_API_KEY 等):", "g"))
    print(c(f"    docker run --rm -e SOLVER_API_KEY=xxx {args.tag}", "b"))
    print(c("\n出 <3G 托管包(在 Linux / WSL / Git-Bash 里,镜像建好后):", "g"))
    print(c("    bash slimify_hosted.sh", "b"))
    sys.exit(0 if ok else 1)


if __name__ == "__main__":
    main()
