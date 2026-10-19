#!/usr/bin/env python3
import argparse
import gzip
import hashlib
import os
import subprocess
import sys
import time
from datetime import datetime

_CLEANUP = r'''
  set +e
  AGGR="${AGGR:-0}"
  before=$(du -sm / 2>/dev/null | cut -f1)

  echo "  [L1] 无损:缓存/文档/locale/pycache"
  rm -rf /usr/share/doc /usr/share/man /usr/share/locale /usr/share/info
  rm -rf /root/.cache /root/.npm /var/lib/apt/lists/* /var/cache/apt/* /tmp/* /var/tmp/* 2>/dev/null
  find / -type d -name __pycache__ -prune -exec rm -rf {} + 2>/dev/null
  find / -type f -name "*.pyc" -delete 2>/dev/null

  echo "  [L2] semgrep(finding-source 专用,benchmark 不用)"
  rm -rf /usr/local/lib/python3.*/dist-packages/semgrep* /usr/local/bin/semgrep* /root/.semgrep 2>/dev/null

  echo "  [L3] benchmark 用不到的重工具(保留 crypto/ghidra/jvm/KB)"
  for pp in /usr/local/lib/python3.*/dist-packages; do
    rm -rf "$pp"/angr* "$pp"/claripy* "$pp"/pyvex* "$pp"/cle* "$pp"/archinfo* "$pp"/ailment* \
           "$pp"/frida* "$pp"/_frida* \
           "$pp"/cv2 "$pp"/opencv* "$pp"/scipy* "$pp"/onnxruntime* \
           "$pp"/awscli* "$pp"/botocore* 2>/dev/null
  done
  rm -rf /usr/share/jadx /opt/dex-tools-* /usr/share/android-framework-res /root/.dotnet 2>/dev/null
  rm -rf /usr/share/dotnet /usr/lib/mono 2>/dev/null
  rm -rf /usr/share/pocl /usr/share/fonts 2>/dev/null

  echo "  [L3.5] 无损精修:KB 截图/文档/IDE补全/逆向模拟(情报文本与核心能力全保留)"
  find /opt/kb -type f \( -iname "*.gif" -o -iname "*.png" -o -iname "*.jpg" -o -iname "*.jpeg" -o -iname "*.svg" \) -delete 2>/dev/null
  rm -rf /opt/ghidra/docs 2>/dev/null
  find /opt/kb -type f \( -iname "*.war" -o -iname "*.zip" -o -iname "*.tar*" -o -iname "*.7z" \) -delete 2>/dev/null
  for pp in /usr/local/lib/python3.*/dist-packages; do rm -rf "$pp"/jedi* "$pp"/unicorn* "$pp"/pypcode* 2>/dev/null; done

  echo "  [L3.6] 死重/冗余精修(零调用 + 与全量 rockyou 重复 + DoS 废数据;能力/KB/词表覆盖零损失)"
  rm -f /usr/local/bin/cloudfox /usr/local/bin/gh 2>/dev/null
  for pp in /usr/local/lib/python3.*/dist-packages; do rm -rf "$pp"/playwright* "$pp"/pytest_playwright* 2>/dev/null; done
  rm -f /usr/share/seclists/Passwords/Leaked-Databases/rockyou*.txt.tar.gz \
        /usr/share/seclists/Passwords/Leaked-Databases/rockyou-*.txt 2>/dev/null
  rm -rf /usr/share/seclists/Payloads/Zip-Bombs 2>/dev/null
  rm -f /usr/share/seclists/Miscellaneous/*.csv.zip 2>/dev/null
  rm -f /opt/ghidra/Ghidra/Features/BSim/postgresql-*.tar.gz 2>/dev/null
  rm -rf /usr/share/seclists/Fuzzing/User-Agents 2>/dev/null
  rm -f /usr/share/seclists/Passwords/Leaked-Databases/md5decryptor-uk.txt \
        /usr/share/seclists/Passwords/Leaked-Databases/alleged-gmail-passwords.txt 2>/dev/null

  echo "  [L3.7] 过-3G 安全瘦身:砍冗余 exploitdb + SecLists 大冗余词表(爆破/fuzz/crack 能力零损)"
  # exploitdb(searchsploit):与 MSF/nuclei/kb 冗余(拿分镜像从无)——仅 hosted 去,完整 v1 仍保留
  rm -rf /usr/share/exploitdb /usr/local/bin/searchsploit /root/.searchsploit_rc 2>/dev/null
  # SecLists/Miscellaneous:杂项参考数据,非爆破/fuzz/利用核心
  rm -rf /usr/share/seclists/Miscellaneous 2>/dev/null
  # SecLists/Passwords:只留 Common-Credentials(含 10-million 口令表)+ Default-Credentials;
  #   泄露库/蜜罐/排列等与单独的全量 rockyou(/usr/share/wordlists/rockyou.txt,保留)冗余 → 删
  if [ -d /usr/share/seclists/Passwords ]; then
    find /usr/share/seclists/Passwords -mindepth 1 -maxdepth 1 \
      ! -name Common-Credentials ! -name Default-Credentials -exec rm -rf {} + 2>/dev/null
  fi
  # JDK jmods:仅 jlink 造精简运行时用;java 运行(ysoserial 等)/javac 编译都不需要(已实测)。
  #   删 jmods 子目录即可(/usr/lib/jvm 目录保留 → 过 sanity 的 jvm 存活检查)
  rm -rf /usr/lib/jvm/*/jmods 2>/dev/null
  # SecLists/Discovery/DNS:子域名枚举表(274M),靶场目标给定→非解题路径;Web-Content(目录爆破)保留
  rm -rf /usr/share/seclists/Discovery/DNS 2>/dev/null

  echo "  [L4] 出口策略:egress=tsecbench(数据化,零改代码)"
  python3 - <<PYEOF
import sys
sys.path.insert(0, "/app")
from engine.providers import egress_apply, load_egress_profile
prof = load_egress_profile("tsecbench")
if not prof:
    print("    FATAL: profiles/tsecbench.json 缺失(egress 数据文件未随镜像)"); raise SystemExit(2)
got = egress_apply("https://api.deepseek.com/anthropic", prof)
if got != "http://api.deepseek.com.tsecbench.gw/anthropic":
    print("    FATAL: egress 改写不符预期:" + got); raise SystemExit(2)
print("    egress=tsecbench 数据化改写 OK -> " + got)
PYEOF
  [ $? -ne 0 ] && { echo "  egress 校验失败"; exit 2; }

  if [ "$AGGR" -ge 1 ]; then
    echo "  [L5 AGGRESSIVE] 砍 ghidra/jvm/crypto(掉逆向/crypto 能力)"
    rm -rf /opt/ghidra /usr/lib/jvm 2>/dev/null
    for pp in /usr/local/lib/python3.*/dist-packages; do rm -rf "$pp"/fpylll* "$pp"/sympy* "$pp"/z3* 2>/dev/null; done
  fi
  if [ "$AGGR" -ge 2 ]; then
    echo "  [L6 AGGRESSIVE=2] KB 情报库瘦身(只留 web/注入类目录)"
    find /opt/kb -maxdepth 2 -type d \( -iname "*reverse*" -o -iname "*forensic*" -o -iname "*pwn*" -o -iname "*crypto*" \) -prune -exec rm -rf {} + 2>/dev/null
  fi

  echo "  [L4.5] 唯一构建指纹(每次打包随机 → 两次打包 sha256 必不同;注意:本段禁用单引号,与 slimify_hosted.sh 外层 bash -c 引用约定一致)"
  UUID=$(cat /proc/sys/kernel/random/uuid 2>/dev/null)
  [ -n "$UUID" ] || UUID=$(od -An -tx1 -N16 /dev/urandom | tr -d " \n")
  printf "time=%s\nuuid=%s\n" "$(date -u +%Y-%m-%dT%H:%M:%SZ)" "$UUID" > /app/.build_nonce
  echo "    nonce: $(tr "\n" " " < /app/.build_nonce)"

  echo "  [sanity] 核心必须存活"
  cd /app && python3 -c "import engine.run_bench, engine.providers, engine.loop, engine.prompts" \
    || { echo "  FATAL: engine import 挂了"; exit 1; }
  python3 -c "import z3, sympy" 2>/dev/null || { echo "  FATAL: crypto(z3/sympy)被误删 —— cybench/xbow 会挂"; exit 1; }
  [ -d /opt/ghidra/Ghidra ] || { echo "  FATAL: ghidra 反编译主体被误删"; exit 1; }
  [ -d /usr/lib/jvm ] || { echo "  FATAL: jvm 被误删(Java 反序列化题会挂)"; exit 1; }
  [ -f /app/engine/profiles/tsecbench.json ] || { echo "  FATAL: egress 数据文件 profiles/tsecbench.json 缺失"; exit 1; }
  python3 - <<PYCHK || { echo "  FATAL: egress 改写机制未生效"; exit 1; }
import sys
sys.path.insert(0, "/app")
from engine.providers import egress_apply, load_egress_profile as L
got = egress_apply("https://api.deepseek.com/anthropic", L("tsecbench"))
assert got == "http://api.deepseek.com.tsecbench.gw/anthropic", "egress 改写异常: " + got
PYCHK
  command -v nmap  >/dev/null || { echo "  FATAL: nmap 没了"; exit 1; }
  command -v curl  >/dev/null || { echo "  FATAL: curl 没了"; exit 1; }
  [ -f /opt/msf-index.json ] || { echo "  FATAL: msf-index 没了"; exit 1; }
  command -v claude >/dev/null || echo "  WARN: claude CLI 未在 PATH(确认执行器仍可用)"

  after=$(du -sm / 2>/dev/null | cut -f1)
  echo "  未压缩: ${before}MB -> ${after}MB  (省 $((before-after))MB)"
  echo CLEANUP_DONE
'''

_IMPORT_CONFIG = [
    "ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
    "ENV LANG=C.UTF-8",
    "ENV DEBIAN_FRONTEND=noninteractive",
    "ENV PYTHONUNBUFFERED=1",
    "ENV PIP_NO_CACHE_DIR=1",
    "ENV NODE_VERSION=20.18.1",
    "ENV IS_SANDBOX=1",
    "ENV HXCTF_EGRESS=open",
    "ENV HXCTF_LLM_EGRESS=tsecbench",
    "ENV TERM=xterm",
    "WORKDIR /app",
    'ENTRYPOINT ["/app/solver/run.sh"]',
]

_ROLE_ORDER = ("decide", "execute", "execute_high", "judge", "small")
_DEFAULT_ROLE_MODELS = {
    "decide": "deepseek:deepseek-v4-pro",
    "execute": "",
    "execute_high": "",
    "judge": "glm:glm-5.3-flash",
    "small": "",
}
_KNOWN_MODELS = ("deepseek:deepseek-flash", "deepseek:deepseek-v4-pro", "glm:glm-5.3", "glm:glm-5.3-flash")


def _build_import_config(role_models: dict) -> list:
    lines = []
    for role in _ROLE_ORDER:
        spec = (role_models.get(role) or "").strip()
        if spec:
            lines.append(f"ENV HXCTF_MODEL_{role.upper()}={spec}")
    cfg = list(_IMPORT_CONFIG)
    i = cfg.index("WORKDIR /app")
    return cfg[:i] + lines + cfg[i:]


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
    return f"\033[{codes.get(color,'')}m{msg}\033[0m" if (color and _COLOR) else msg


def _prompt_role_models(no_prompt=False):
    models = dict(_DEFAULT_ROLE_MODELS)
    if no_prompt or not sys.stdin.isatty():
        print(c("  [模型注入] 非交互(--no-prompt 或非 TTY)→ 用默认角色模型。", "y"))
        return models
    print(c("\n================ 模型注入(角色→模型)================", "y"))
    print(c("  已知可选: " + "  ".join(_KNOWN_MODELS), "b"))
    print(c("  回车=默认 | 输入 provider:model 覆盖 | 输入 base 清空(回落主模型 deepseek-flash + 容灾轮转)", "b"))
    print(c("  注:execute/execute_high/small 建议留空(走主力+deepseek故障时轮转到GLM);显式设会关掉该角色轮转。", "b"))
    role_desc = {"decide": "规划(旗舰)", "execute": "执行主力", "execute_high": "高难执行",
                 "judge": "校验(异模型)", "small": "轻任务"}
    for role in _ROLE_ORDER:
        cur = models[role]
        shown = cur if cur else "(空=base deepseek-flash + 轮转)"
        try:
            ans = input(c(f"  {role:13s} [{role_desc[role]}] 默认={shown}: ", "g")).strip()
        except EOFError:
            ans = ""
        if not ans:
            continue
        if ans.lower() in ("base", "none", "-", "空"):
            models[role] = ""
        else:
            models[role] = ans
    print(c("\n  将注入的角色模型:", "y"))
    for role in _ROLE_ORDER:
        spec = models[role]
        print(c(f"    HXCTF_MODEL_{role.upper()} = {spec if spec else '(不注入 → base deepseek-flash + 容灾轮转)'}",
                "g" if spec else "b"))
    try:
        ok = input(c("  确认以上模型配置?[Y/n] ", "y")).strip().lower()
    except EOFError:
        ok = "y"
    if ok in ("n", "no", "否"):
        print(c("  → 重新输入。", "y"))
        return _prompt_role_models(no_prompt=False)
    return models


def main():
    ap = argparse.ArgumentParser(description="把 hxctf:v1 压成 <3GB tar.gz(Windows 原生,免 WSL/bash)")
    ap.add_argument("--src", default="hxctf:v1", help="源镜像(默认 hxctf:v1)")
    ap.add_argument("--out", default="hxctf-hosted:latest", help="压缩后镜像 tag(默认 hxctf-hosted:latest)")
    ap.add_argument("--file", default=None, help="输出 tar.gz 名(默认带时间戳)")
    ap.add_argument("--aggressive", type=int, choices=[0, 1, 2], default=0, help="超 3G 才用:1 砍 ghidra/jvm/crypto,2 再砍 KB")
    ap.add_argument("--dryrun", action="store_true", help="只清理+量体积,不导出/压缩")
    ap.add_argument("--no-prompt", action="store_true", help="跳过模型注入交互,用默认角色模型(非 TTY/CI 自动跳过)")
    args = ap.parse_args()

    out_file = args.file or f"hxctf_hosted_{datetime.now().strftime('%Y%m%d-%H%M%S')}.tar.gz"
    tmp = f"hxctf_slim_{os.getpid()}"

    if not _docker_ok():
        print(c("✗ docker 不可用,请确认 Docker Desktop 已启动。", "r"))
        sys.exit(2)
    if not _image_exists(args.src):
        print(c(f"✗ 源镜像不存在:{args.src}(先用 build_image.py 构建)", "r"))
        sys.exit(2)

    _src_id = subprocess.run(["docker", "inspect", args.src, "--format", "{{.Id}}"],
                             capture_output=True, text=True).stdout.strip()
    _src_ct = subprocess.run(["docker", "inspect", args.src, "--format", "{{.Created}}"],
                             capture_output=True, text=True).stdout.strip()
    print(c(f"  源镜像解析:{_src_id[:19]}  created={_src_ct}", "b"))

    print(c("================ hxctf 托管包压缩 ================", "y"))
    print(c(f"  源={args.src}  出={args.out}  文件={out_file}  AGGRESSIVE={args.aggressive}  DRYRUN={args.dryrun}", "b"))

    role_models = {} if args.dryrun else _prompt_role_models(no_prompt=args.no_prompt)

    print(c(f"\n[1/4] 在一次性容器里清理(AGGRESSIVE={args.aggressive})", "y"))
    subprocess.call(["docker", "rm", "-f", tmp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    rc = subprocess.call(["docker", "run", "--name", tmp, "-e", f"AGGR={args.aggressive}",
                          "--entrypoint", "bash", args.src, "-c", _CLEANUP])
    if rc != 0:
        print(c("✗ 清理失败(见上方 FATAL)。", "r"))
        subprocess.call(["docker", "rm", "-f", tmp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sys.exit(1)

    if args.dryrun:
        print(c("\n[dryrun] 只估算:上面『未压缩 ...MB』÷ 2.2 ≈ tar.gz 体积。", "y"))
        print(c(f"[dryrun] 检查容器已保留:{tmp}(docker exec -it {tmp} bash;看完 docker rm -f {tmp})", "b"))
        sys.exit(0)

    print(c("\n[2/4] export | import 扁平化(重设 config;内置 HXCTF_EGRESS=open + HXCTF_LLM_EGRESS=tsecbench)", "y"))
    import_cmd = ["docker", "import"]
    for cfg in _build_import_config(role_models):
        import_cmd += ["-c", cfg]
    import_cmd += ["-", args.out]
    if not _pipe(["docker", "export", tmp], import_cmd):
        print(c("✗ export|import 失败。", "r"))
        subprocess.call(["docker", "rm", "-f", tmp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
        sys.exit(1)
    subprocess.call(["docker", "rm", "-f", tmp], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

    print(c(f"\n[3/4] save + gzip -9 -> {out_file}(几 GB 流,gzip -9 需几分钟~十几分钟)", "y"))
    if not _save_gzip(args.out, out_file):
        print(c("✗ save|gzip 失败。", "r"))
        sys.exit(1)

    print(c("\n[4/4] 结果", "y"))
    b = os.path.getsize(out_file)
    print(c(f"  tar.gz: {b} bytes  ({b/1e9:.2f} GB / {b/1073741824:.2f} GiB)", "b"))
    if b < 3_000_000_000:
        print(c("  ✅ < 3.0GB —— 可上传托管", "g"))
    else:
        print(c("  ⚠ >= 3.0GB —— 用 --aggressive 1(砍 ghidra/jvm/crypto)或 --aggressive 2(再砍 KB)重试", "y"))
    print(c(f"  产物:{os.path.abspath(out_file)}", "g"))

    print(c("  计算 sha256(~2.7G 需几十秒)...", "y"))
    digest = _sha256_file(out_file)
    with open(out_file + ".sha256", "w") as f:
        f.write(f"{digest}  {os.path.basename(out_file)}\n")
    print(c(f"  sha256: {digest}", "b"))
    print(c(f"  指纹文件:{os.path.abspath(out_file)}.sha256", "g"))


def _docker_ok():
    try:
        return subprocess.call(["docker", "version"], stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0
    except Exception:
        return False


def _image_exists(tag):
    return subprocess.call(["docker", "image", "inspect", tag],
                           stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL) == 0


def _pipe(cmd1, cmd2):
    p1 = subprocess.Popen(cmd1, stdout=subprocess.PIPE)
    p2 = subprocess.Popen(cmd2, stdin=p1.stdout)
    p1.stdout.close()
    p2.communicate()
    p1.wait()
    return p1.returncode == 0 and p2.returncode == 0


def _sha256_file(path, chunk=8 * 1024 * 1024):
    h = hashlib.sha256()
    with open(path, "rb") as f:
        while True:
            b = f.read(chunk)
            if not b:
                break
            h.update(b)
    return h.hexdigest()


def _save_gzip(image, file_path):
    t0 = time.time()
    sav = subprocess.Popen(["docker", "save", image], stdout=subprocess.PIPE)
    total = 0
    try:
        with gzip.open(file_path, "wb", compresslevel=9) as gz:
            while True:
                chunk = sav.stdout.read(8 * 1024 * 1024)
                if not chunk:
                    break
                gz.write(chunk)
                total += len(chunk)
                print(f"\r    读入 docker save 流 {total/1073741824:.2f} GB,压缩中...", end="", flush=True)
    finally:
        try:
            sav.stdout.close()
        except Exception:
            pass
    rc = sav.wait()
    print(f"\r    读入 docker save 流 {total/1073741824:.2f} GB,压缩完成(耗时 {int(time.time()-t0)}s)。", flush=True)
    return rc == 0


if __name__ == "__main__":
    main()
