#!/usr/bin/env bash
set -eu

if [ -n "${HXBAI_VPN_CONFIG:-}" ]; then
  [ -f "${HXBAI_VPN_CONFIG}" ] || { echo "[run] FATAL: VPN config not found: ${HXBAI_VPN_CONFIG}" >&2; exit 1; }
  echo "[run] connecting VPN: ${HXBAI_VPN_CONFIG}"
  ovpn=(--config "${HXBAI_VPN_CONFIG}" --daemon --log /tmp/openvpn.log --writepid /tmp/openvpn.pid
        --ping 10 --ping-restart 60)
  [ -n "${HXBAI_VPN_AUTH:-}" ] && [ -f "${HXBAI_VPN_AUTH}" ] && ovpn+=(--auth-user-pass "${HXBAI_VPN_AUTH}")
  openvpn "${ovpn[@]}" || { echo "[run] FATAL: openvpn failed" >&2; exit 1; }
  HC="${HXBAI_VPN_HEALTHCHECK:-http://10.0.100.58}"
  up=0
  for i in $(seq 1 60); do
    resp=$(curl -s -m 5 -w $'\n%{http_code}' "${HC}" 2>/dev/null) || true
    code=${resp##*$'\n'}
    if [ "${code}" = "200" ] && printf '%s' "${resp%$'\n'*}" | grep -q '"status"[[:space:]]*:[[:space:]]*"ok"'; then
      echo "[run] VPN up (healthcheck 200 ok)"; up=1; break
    fi
    ip addr show tun0 2>/dev/null | grep -q 'inet ' && { echo "[run] VPN tun0 up (has inet; healthcheck skipped)"; up=1; break; }
    sleep 2
  done
  [ "${up}" = 1 ] || { echo "[run] FATAL: VPN 请求了但未确认 up(healthcheck 非 200 且 tun0 无 inet)——拒绝脱离隧道运行" >&2; exit 1; }
fi

if [ -f /app/solver/egress_lock.sh ]; then
  if ! bash /app/solver/egress_lock.sh "${HXCTF_EGRESS:-open}" "${HXCTF_EXEC_UID:-61000}"; then
    echo "[run] FATAL: 显式 HXCTF_EGRESS=locked 但封不住(iptables 缺失/无 NET_ADMIN)→ fail-closed 拒绝起跑;" \
         "去掉 HXCTF_EGRESS(默认 open,自主可用)或补 iptables + --cap-add NET_ADMIN" >&2
    exit 1
  fi
fi

if [ "${1:-}" = "bench-engine" ]; then shift; exec python3 -m engine.run_bench "$@"; fi
if [ "${1:-}" = "finding-live" ]; then shift; exec python3 -m engine.run_finding "$@"; fi
if [ "${1:-}" = "koh" ]; then shift; exec python3 -m solver.run_koh "$@"; fi
if [ "${1:-}" = "finding-source" ]; then shift; exec python3 -m engine.run_source "$@"; fi
if [ "${1:-}" = "auto" ]; then shift; exec python3 -m engine.autoroute "$@"; fi
if [ "${1:-}" = "bench" ]; then shift; exec python3 -m solver.bench "$@"; fi
case "${1:-}" in
  -*) exec python3 -m solver.solve "$@" ;;
  *)  exec python3 -m engine.autoroute "$@" ;;
esac
