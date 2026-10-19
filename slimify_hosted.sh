#!/usr/bin/env bash
set -euo pipefail
SRC="${1:-hxctf:v1}"
OUT="${2:-hxctf-hosted:latest}"
FILE="${3:-hxctf_hosted_$(date +%Y%m%d-%H%M%S).tar.gz}"
AGGR="${AGGRESSIVE:-0}"
DRYRUN="${DRYRUN:-0}"
NO_PROMPT="${NO_PROMPT:-0}"
TMP="hxctf_slim_$$"

ROLE_ORDER=(decide execute execute_high judge small)
ROLE_DESC=("规划(旗舰)" "执行主力" "高难执行" "校验(异模型)" "轻任务")
ROLE_VAL=("deepseek:deepseek-v4-pro" "" "" "glm:glm-5.3-flash" "")
MODEL_ENV_ARGS=()
if [ "$DRYRUN" != "1" ]; then
  if [ "$NO_PROMPT" = "1" ] || [ ! -t 0 ]; then
    echo "  [模型注入] 非交互(NO_PROMPT 或非 TTY)→ 用默认角色模型。"
  else
    echo "================ 模型注入(角色→模型)================"
    echo "  已知可选: deepseek:deepseek-flash  deepseek:deepseek-v4-pro  glm:glm-5.3  glm:glm-5.3-flash"
    echo "  回车=默认 | 输入 provider:model 覆盖 | 输入 base 清空(回落主模型 deepseek-flash + 容灾轮转)"
    echo "  注:execute/execute_high/small 建议留空(走主力+deepseek故障时轮转到GLM);显式设会关掉该角色轮转。"
    while true; do
      i=0
      for role in "${ROLE_ORDER[@]}"; do
        cur="${ROLE_VAL[$i]}"
        if [ -n "$cur" ]; then shown="$cur"; else shown="(空=base deepseek-flash + 轮转)"; fi
        printf "  %-13s [%s] 默认=%s: " "$role" "${ROLE_DESC[$i]}" "$shown"
        read -r ans || ans=""
        ans="$(printf '%s' "$ans" | sed 's/^ *//;s/ *$//')"
        if [ -n "$ans" ]; then
          case "$ans" in base|none|-|空) ROLE_VAL[$i]="";; *) ROLE_VAL[$i]="$ans";; esac
        fi
        i=$((i+1))
      done
      echo ""
      echo "  将注入的角色模型:"
      i=0
      for role in "${ROLE_ORDER[@]}"; do
        RU="$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')"
        if [ -n "${ROLE_VAL[$i]}" ]; then echo "    HXCTF_MODEL_$RU = ${ROLE_VAL[$i]}"
        else echo "    HXCTF_MODEL_$RU = (不注入 → base deepseek-flash + 容灾轮转)"; fi
        i=$((i+1))
      done
      printf "  确认以上模型配置?[Y/n] "; read -r ok || ok="y"
      ok="$(printf '%s' "$ok" | tr '[:upper:]' '[:lower:]')"
      case "$ok" in n|no|否) echo "  → 重新输入。";; *) break;; esac
    done
  fi
  i=0
  for role in "${ROLE_ORDER[@]}"; do
    RU="$(printf '%s' "$role" | tr '[:lower:]' '[:upper:]')"
    [ -n "${ROLE_VAL[$i]}" ] && MODEL_ENV_ARGS+=( -c "ENV HXCTF_MODEL_$RU=${ROLE_VAL[$i]}" )
    i=$((i+1))
  done
fi

echo "[1/4] cleanup pass in throwaway container from $SRC  (AGGRESSIVE=$AGGR, DRYRUN=$DRYRUN)"
docker rm -f "$TMP" >/dev/null 2>&1 || true
docker run --name "$TMP" --entrypoint bash "$SRC" -c '
  set +e
  AGGR="'"$AGGR"'"
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

  echo "  [L3.6] 死重/冗余精修(全量跑证据:零调用 + 与全量 rockyou 重复 + DoS 废数据;能力/KB/词表覆盖零损失)"
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
  rm -rf /usr/share/exploitdb /usr/local/bin/searchsploit /root/.searchsploit_rc 2>/dev/null
  rm -rf /usr/share/seclists/Miscellaneous 2>/dev/null
  if [ -d /usr/share/seclists/Passwords ]; then
    find /usr/share/seclists/Passwords -mindepth 1 -maxdepth 1 \
      ! -name Common-Credentials ! -name Default-Credentials -exec rm -rf {} + 2>/dev/null
  fi
  rm -rf /usr/lib/jvm/*/jmods 2>/dev/null
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

  echo "  [L4.5] 唯一构建指纹(每次打包随机 → 两次打包 sha256 必不同;本段禁用单引号:整段包在外层 bash -c 单引号里)"
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
' || { echo "cleanup 失败"; docker rm -f "$TMP" >/dev/null 2>&1 || true; exit 1; }

if [ "$DRYRUN" = "1" ]; then
  echo "[dryrun] 只估算,跳过 export/gzip。经验:gzip -9 对这类内容约压 2~2.5x → 上面未压缩 MB ÷ 2.2 ≈ tar.gz。"
  echo "[dryrun] 检查用容器保留: $TMP  (docker exec -it $TMP bash;看完 docker rm -f $TMP)"
  exit 0
fi

echo "[2/4] flatten via export | import (重设 config;内置 HXCTF_EGRESS=open + HXCTF_LLM_EGRESS=tsecbench 数据化网关 → 托管只填 SOLVER_API_KEY)"
docker export "$TMP" | docker import \
  -c 'ENV PATH=/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin' \
  -c 'ENV LANG=C.UTF-8' \
  -c 'ENV DEBIAN_FRONTEND=noninteractive' \
  -c 'ENV PYTHONUNBUFFERED=1' \
  -c 'ENV PIP_NO_CACHE_DIR=1' \
  -c 'ENV NODE_VERSION=20.18.1' \
  -c 'ENV IS_SANDBOX=1' \
  -c 'ENV HXCTF_EGRESS=open' \
  -c 'ENV HXCTF_LLM_EGRESS=tsecbench' \
  ${MODEL_ENV_ARGS[@]+"${MODEL_ENV_ARGS[@]}"} \
  -c 'ENV TERM=xterm' \
  -c 'WORKDIR /app' \
  -c 'ENTRYPOINT ["/app/solver/run.sh"]' \
  - "$OUT"
docker rm -f "$TMP" >/dev/null 2>&1 || true

echo "[3/4] save + gzip -9 -> $FILE"
docker save "$OUT" | gzip -9 -c > "$FILE"

echo "[4/4] result"
BYTES=$(wc -c < "$FILE")
printf 'tar.gz: %s bytes (%.2f GB decimal, %.2f GiB)\n' "$BYTES" \
  "$(echo "scale=2; $BYTES/1000000000" | bc)" "$(echo "scale=2; $BYTES/1073741824" | bc)"
if [ "$BYTES" -lt 3000000000 ]; then
  echo "OK  < 3.0GB(decimal)—— 可上传"
else
  echo "WARN >= 3.0GB —— 开 AGGRESSIVE=1(砍 ghidra/jvm/crypto)或 AGGRESSIVE=2(再砍 KB)重试"
fi
echo "产物: $(cd "$(dirname "$FILE")" && pwd)/$(basename "$FILE")"

if   command -v sha256sum >/dev/null 2>&1; then SHA=$(sha256sum "$FILE" | awk '{print $1}');
elif command -v shasum    >/dev/null 2>&1; then SHA=$(shasum -a 256 "$FILE" | awk '{print $1}');
else                                           SHA=$(openssl dgst -sha256 -r "$FILE" | awk '{print $1}'); fi
printf '%s  %s\n' "$SHA" "$(basename "$FILE")" > "$FILE.sha256"
echo "sha256: $SHA  (已写入 $FILE.sha256)"
