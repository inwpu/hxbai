#!/usr/bin/env bash
set -euo pipefail

OVPN="${1:?用法: ./launch_bench.sh <path/to.ovpn> [题号...]}"; shift || true
CODES=("$@")
[ -f "${OVPN}" ] || { echo "FATAL: 找不到 VPN 配置: ${OVPN}" >&2; exit 1; }

if [ -z "${SOLVER_API_KEY:-}" ]; then
  API_FILE="${SOLVER_API_KEY_FILE:?需要 export SOLVER_API_KEY=sk-... 或指定 SOLVER_API_KEY_FILE=<含 sk- 开头 key 的文本文件>}"
  [ -f "${API_FILE}" ] || { echo "FATAL: 无 SOLVER_API_KEY,且找不到 ${API_FILE}" >&2; exit 1; }
  SOLVER_API_KEY="$(awk 'tolower($0) ~ /deepseek/{f=1} f && match($0,/sk-[A-Za-z0-9]{20,}/){print substr($0,RSTART,RLENGTH); exit}' "${API_FILE}")"
  [ -n "${SOLVER_API_KEY}" ] || SOLVER_API_KEY="$(grep -oE 'sk-[A-Za-z0-9]{20,}' "${API_FILE}" | head -1)"
  [ -n "${SOLVER_API_KEY}" ] || { echo "FATAL: 在 ${API_FILE} 里没找到 sk- 开头的 deepseek key" >&2; exit 1; }
fi
export SOLVER_API_KEY

: "${HXCTF_LLM_PROVIDER:=deepseek}"
: "${HXCTF_LLM_MODEL:=deepseek-flash}"
export HXCTF_LLM_PROVIDER HXCTF_LLM_MODEL
_HERE="${HERE:-$(cd "$(dirname "$0")" && pwd)}"
case "${HXCTF_LLM_PROVIDER}" in
  glm)  PROV_KEYFILE="${GLM_API_KEY_FILE:-${_HERE}/GLMhxctf.txt}"; PROV_KEYENV=GLM_API_KEY  ;;
  mimo) PROV_KEYFILE="${MIMO_API_KEY_FILE:-${_HERE}/mimoapi.txt}"; PROV_KEYENV=MIMO_API_KEY ;;
  *)    PROV_KEYFILE=""; PROV_KEYENV="" ;;
esac
if [ -n "${PROV_KEYENV}" ] && [ -z "$(eval "printf '%s' \"\${${PROV_KEYENV}:-}\"")" ]; then
  [ -f "${PROV_KEYFILE}" ] || { echo "FATAL: provider=${HXCTF_LLM_PROVIDER} 但找不到 ${PROV_KEYFILE}" >&2; exit 1; }
  PROV_KEY="$(grep -oE '(sk-)?[A-Za-z0-9._-]{20,}' "${PROV_KEYFILE}" | head -1)"
  [ -n "${PROV_KEY}" ] || { echo "FATAL: 在 ${PROV_KEYFILE} 里没找到 key" >&2; exit 1; }
  declare "${PROV_KEYENV}=${PROV_KEY}"
fi
[ -n "${PROV_KEYENV}" ] && export "${PROV_KEYENV}"
echo "[launch] LLM provider=${HXCTF_LLM_PROVIDER} model=${HXCTF_LLM_MODEL}"

: "${BENCHMARK_TOKEN:?需要 export BENCHMARK_TOKEN=...(随 VPN 一起发)}"
: "${BENCHMARK_BASE_URL:?需要 export BENCHMARK_BASE_URL=...(随 VPN 一起发)}"

TS="$(date +%Y%m%d-%H%M%S)"
HERE="$(cd "$(dirname "$0")" && pwd)"
RUN_DIR="${HERE}/runs/${TS}"
mkdir -p "${RUN_DIR}/tsg"
cp "${OVPN}" "${RUN_DIR}/client.ovpn"
chmod 600 "${RUN_DIR}/client.ovpn"

VPN_MOUNTS=(-v "${RUN_DIR}/client.ovpn:/vpn/client.ovpn:ro")
VPN_ENVS=(-e HXBAI_VPN_CONFIG=/vpn/client.ovpn)
if [ -n "${HXBAI_VPN_AUTH:-}" ] && [ -f "${HXBAI_VPN_AUTH}" ]; then
  cp "${HXBAI_VPN_AUTH}" "${RUN_DIR}/vpn.auth"; chmod 600 "${RUN_DIR}/vpn.auth"
  VPN_MOUNTS+=(-v "${RUN_DIR}/vpn.auth:/vpn/vpn.auth:ro")
  VPN_ENVS+=(-e HXBAI_VPN_AUTH=/vpn/vpn.auth)
fi

PERSIST_MOUNTS=()
if [ -n "${HXCTF_PERSIST_ROOT:-}" ]; then
  mkdir -p "${HXCTF_PERSIST_ROOT}"
  _PR="$(cd "${HXCTF_PERSIST_ROOT}" && pwd)"
  PERSIST_MOUNTS=(-v "${_PR}:/var/lib/hxctf/bench")
  echo "[launch] ⚠️  PERSIST-TSG 启用:/var/lib/hxctf/bench → ${_PR} (容器重开后同题复用 TSG,验证记忆接力)"
fi

echo "[launch] image   : hxctf:v1  (HEAD $(git -C "${HERE}" log -1 --format=%h))"
echo "[launch] run dir : ${RUN_DIR}"
echo "[launch] targets : ${CODES[*]:-ALL-未完成}"
echo "[launch] ---- 开始(Ctrl-C 停容器)----"

export BENCHMARK_TOKEN BENCHMARK_BASE_URL
export HXCTF_EGRESS="${HXCTF_EGRESS:-open}"
echo "[launch] egress  : ${HXCTF_EGRESS}  (open=执行器可出网[调模型+云可复现]; locked=封执行器非-tun出网[当前会封死模型,慎用])"
CONTAINER="hxctf-bench-${TS}"
docker run -d --init \
  --name "${CONTAINER}" \
  --cap-add NET_ADMIN --device /dev/net/tun \
  -e SOLVER_API_KEY \
  -e HXCTF_LLM_PROVIDER \
  -e HXCTF_LLM_MODEL \
  ${HXCTF_MODEL_DECIDE:+-e HXCTF_MODEL_DECIDE} \
  ${GLM_API_KEY:+-e GLM_API_KEY} \
  ${GLM_API_KEYS:+-e GLM_API_KEYS} \
  ${HXCTF_MODEL_EXECUTE:+-e HXCTF_MODEL_EXECUTE} \
  ${HXCTF_MODEL_EXECUTE_HIGH:+-e HXCTF_MODEL_EXECUTE_HIGH} \
  ${HXCTF_MODEL_JUDGE:+-e HXCTF_MODEL_JUDGE} \
  ${PROV_KEYENV:+-e ${PROV_KEYENV}} \
  -e BENCHMARK_TOKEN \
  -e BENCHMARK_BASE_URL \
  -e HXCTF_EGRESS \
  "${VPN_ENVS[@]}" "${VPN_MOUNTS[@]}" \
  ${PERSIST_MOUNTS[@]+"${PERSIST_MOUNTS[@]}"} \
  -v "${RUN_DIR}/tsg:/tmp/hxctf-bench" \
  hxctf:v1 bench-engine ${CODES[@]+"${CODES[@]}"} >/dev/null

nohup docker logs -f "${CONTAINER}" > "${RUN_DIR}/run.log" 2>&1 &
LOGGER=$!
disown "${LOGGER}" 2>/dev/null || true

trap 'echo; echo "[launch] 收到中断,停止容器 ${CONTAINER}…"; docker stop "${CONTAINER}" >/dev/null 2>&1 || true' INT TERM

python3 "${HERE}/runs/track_run.py" "${RUN_DIR}/run.log" -o "${RUN_DIR}/RUN_TRACKING.md" --watch >/dev/null 2>&1 &
TRACKER=$!
disown "${TRACKER}" 2>/dev/null || true

tail -n +1 -f "${RUN_DIR}/run.log" 2>/dev/null &
TAILER=$!
docker wait "${CONTAINER}" >/dev/null 2>&1 || true
docker cp "${CONTAINER}:/var/lib/hxctf/bench/." "${RUN_DIR}/tsg/" 2>/dev/null || true
kill "${TAILER}" 2>/dev/null || true
kill -TERM "${TRACKER}" 2>/dev/null || true

python3 "${HERE}/runs/track_run.py" "${RUN_DIR}/run.log" -o "${RUN_DIR}/RUN_TRACKING.md" >/dev/null 2>&1 || true

echo "[launch] ---- 结束 ----"
echo "[launch] 日志: ${RUN_DIR}/run.log"
echo "[launch] 实时记录: ${RUN_DIR}/RUN_TRACKING.md  (每 15min 自动刷新 + 终局兜底)"
echo "[launch] 决策图/事件: ${RUN_DIR}/tsg/  (每题一子目录,*.tsg.db + *.events.jsonl)"
echo "[launch] 本次得分:"; grep -E "\[engine\] (DONE|  )" "${RUN_DIR}/run.log" || true
