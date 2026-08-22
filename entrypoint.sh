#!/usr/bin/env bash
set -euo pipefail

echo "[hxbai] provider=${HXBAI_PROVIDER:-${SOLVER_PROVIDER:-deepseek}} gateway=${SOLVER_GATEWAY:-0}"
echo "[hxbai] BENCHMARK_BASE_URL=${BENCHMARK_BASE_URL:-<unset>}"

: "${BENCHMARK_TOKEN:?BENCHMARK_TOKEN must be provided}"
: "${BENCHMARK_BASE_URL:?BENCHMARK_BASE_URL must be provided}"

if [[ -z "${SOLVER_API_KEY:-}" && -z "${ANTHROPIC_AUTH_TOKEN:-}" && -z "${ANTHROPIC_API_KEY:-}" ]]; then
  echo "[hxbai] WARNING: no SOLVER_API_KEY / ANTHROPIC_AUTH_TOKEN set — the Claude Code solver cannot authenticate." >&2
fi

cd /app 2>/dev/null || true
PYTHONPATH=/app python3 -c "from hxbai.dnsfix import pin_api_host; import os; \
ip = pin_api_host(os.environ.get('BENCHMARK_BASE_URL', '')); \
print('[hxbai] dns pin (pre-VPN):', ip or '(no pin — layer 2 will re-pin on failure)')" || true

if [[ -n "${HXBAI_VPN_CONFIG:-}" ]]; then
  if [[ ! -f "${HXBAI_VPN_CONFIG}" ]]; then
    echo "[hxbai] FATAL: HXBAI_VPN_CONFIG=${HXBAI_VPN_CONFIG} not found (mount it into the container)." >&2
    exit 1
  fi
  ovpn_args=(--config "${HXBAI_VPN_CONFIG}" --daemon --log /tmp/openvpn.log --writepid /tmp/openvpn.pid)
  [[ -n "${HXBAI_VPN_AUTH:-}" && -f "${HXBAI_VPN_AUTH}" ]] && ovpn_args+=(--auth-user-pass "${HXBAI_VPN_AUTH}")
  if [[ "${HXBAI_VPN_KEEPALIVE:-1}" != "0" ]]; then
    ovpn_args+=(--ping "${HXBAI_VPN_PING_S:-10}" --ping-restart "${HXBAI_VPN_PING_RESTART_S:-60}")
    echo "[hxbai] VPN tunnel keepalive: ping ${HXBAI_VPN_PING_S:-10}s, restart after ${HXBAI_VPN_PING_RESTART_S:-60}s"
  fi
  echo "[hxbai] starting OpenVPN in-container: ${HXBAI_VPN_CONFIG}"
  openvpn "${ovpn_args[@]}" || { echo "[hxbai] FATAL: openvpn failed to launch" >&2; exit 1; }
  HC="${HXBAI_VPN_HEALTHCHECK:-http://10.0.100.58}"
  up=0
  for i in $(seq 1 60); do
    code=$(curl -s -m 5 -o /dev/null -w '%{http_code}' "${HC}" 2>/dev/null) || true; code=${code:-000}
    if [[ "$code" =~ ^[1-5][0-9][0-9]$ ]]; then echo "[hxbai] VPN up — internal healthcheck ${HC} HTTP $code after ${i}x2s"; up=1; break; fi
    sleep 2
  done
  if [[ "$up" != "1" ]]; then
    echo "[hxbai] FATAL: VPN did not establish the internal route (${HC}) in 120s. OpenVPN log tail:" >&2
    tail -n 30 /tmp/openvpn.log >&2 2>/dev/null || true
    exit 1
  fi
  sleep 3
fi

if [[ "${HXBAI_OOB:-0}" == "1" ]]; then
  export OOB_DOMAIN="${OOB_DOMAIN:-oob.hxbai}"
  ip="$(hostname -i 2>/dev/null | awk '{print $1}')"
  export OOB_HTTP_BASE="${OOB_HTTP_BASE:-http://${ip:-127.0.0.1}}"
  export OOB_RESOLVE_IP="${OOB_RESOLVE_IP:-${ip:-127.0.0.1}}"
  export OOB_POLL_SECRET="${OOB_POLL_SECRET:-$(openssl rand -hex 16)}"
  (python3 -m hxbai.oob >/tmp/oob.log 2>&1 &) && echo "[hxbai] OOB oracle on ${OOB_HTTP_BASE} (domain ${OOB_DOMAIN}, poll secured)" || echo "[hxbai] OOB oracle failed to start (non-fatal)"
fi

exec python3 /app/drivers/benchmark_driver.py
