#!/usr/bin/env bash
set -euo pipefail

FOFA_KEY="${FOFA_KEY:?需要 FOFA_KEY env(fofaapi.txt)}"
DKEY="${DKEY:?需要 DKEY env(api.txt 的 deepseek key)}"
IMG=hxctf:v1
LIM="${TSCOPE_LIMIT:-10}"
HOURS="${HUNT_HOURS:-8}"
SCOPE_DIR="$HOME/tscope"
mkdir -p "$SCOPE_DIR"

PROD_ARGS=(); for p in "$@"; do PROD_ARGS+=(--product "$p"); done
[ ${#PROD_ARGS[@]} -eq 0 ] && PROD_ARGS=(--product 腾讯会议)

echo "═══ 1/3 资产收集(FOFA→腾讯归属确认)═══"
docker run --rm -e FOFA_KEY="$FOFA_KEY" -v "$SCOPE_DIR":/out \
  --entrypoint python3 "$IMG" /app/solver/fofa_scope.py \
  "${PROD_ARGS[@]}" --limit "$LIM" --out /out/tscope.json
echo "清单: $SCOPE_DIR/tscope.json"

echo
echo "═══ 2/3 任务书(放进容器给 agent 读)═══"
cat > "$SCOPE_DIR/TASK.md" <<'EOF'

本次测试范围仅限 CSIG 业务资产:腾讯会议、腾讯元宝、腾讯文档、电脑管家/手机管家、
腾讯云、腾讯地图及 CSIG 其他业务。目标清单见同目录 tscope.json(FOFA 收集+归属确认,
每个目标附产品名与归属证据)。**只打清单内目标;发现范围外资产一律跳过并记录。**

挖掘目标为高危及以上等级漏洞(可远程利用/数据泄露/权限绕过/RCE/SSRF 打内网等)。
每个漏洞 claim 必须附机检证据(L1 执行反证或 OOB 回调),自报不算数。

- 非破坏性:不 DoS、不删数据、不留后门;发现敏感数据只记录不外传。
- 逐目标侦察→攻击面分析→利用验证→claim 落盘(findings.jsonl)。
- 跨目标情报复用(同产品组件指纹/同类漏洞模式)。
EOF
echo "任务书: $SCOPE_DIR/TASK.md"

echo
echo "═══ 3/3 单容器挖掘全部资产(后台;日志 $SCOPE_DIR/hunt.log)═══"
URLS=$(python3 -c "import json;print(' '.join(t['url'] for t in json.load(open('$SCOPE_DIR/tscope.json'))))")
[ -z "$URLS" ] && { echo "清单为空,退出"; exit 1; }
echo "目标($(( $(echo $URLS | wc -w) )) 个): $URLS" | head -c 400; echo

docker run -d --name t3hunt \
  -e NODE_TLS_REJECT_UNAUTHORIZED=0 \
  -e SOLVER_API_KEY="$DKEY" \
  -e HXBAI_PROVIDER=deepseek \
  -e HXCTF_LLM_BASE_URL="${T3_GATEWAY:-https://1.14.221.73/PROJ2026_AISRC01/2846b57e45e062db/anthropic}" \
  -e HXCTF_TASK_DESC="腾讯CSIG授权漏洞挖掘,任务书见 /task/TASK.md,目标清单见 /task/tscope.json;先读任务书" \
  -e HXCTF_FINDING_TASK="$(cat "$SCOPE_DIR/TASK.md" | head -3 | tr '\n' ' ')" \
  -e HXCTF_LOG_ROOT=/task/logs \
  -v "$SCOPE_DIR":/task \
  "$IMG" $URLS > /dev/null && echo "容器 t3hunt 已启动"
echo "看进度: docker logs -f t3hunt | tail -50"
echo "收结果: $SCOPE_DIR/findings.jsonl + $SCOPE_DIR/logs/"
