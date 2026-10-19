#!/usr/bin/env bash
set -u
POLICY="${1:-${HXCTF_EGRESS:-open}}"
EXEC_UID="${2:-${HXCTF_EXEC_UID:-61000}}"

_v4() { iptables "$@"; }
_v6() { command -v ip6tables >/dev/null 2>&1 && ip6tables "$@"; }

if [ "${POLICY}" = "open" ]; then
  if command -v iptables >/dev/null 2>&1; then
    _v4 -D OUTPUT -m owner --uid-owner "${EXEC_UID}" -j HXCTF_EGRESS 2>/dev/null || true
    _v4 -F HXCTF_EGRESS 2>/dev/null || true; _v4 -X HXCTF_EGRESS 2>/dev/null || true
    _v6 -D OUTPUT -m owner --uid-owner "${EXEC_UID}" -j HXCTF_EGRESS6 2>/dev/null || true
    _v6 -F HXCTF_EGRESS6 2>/dev/null || true; _v6 -X HXCTF_EGRESS6 2>/dev/null || true
  fi
  echo "[egress] OPEN (enterprise-assessment): executor may reach the internet for latest asset/PoC intel."
  exit 0
fi

if ! command -v iptables >/dev/null 2>&1; then
  echo "[egress] FAILED(locked): iptables 缺失,无法封执行器出网 → fail-closed 拒绝放开。装 iptables 或改 HXCTF_EGRESS=open。" >&2
  exit 1
fi

ok=1
_try() { if ! "$@" 2>/dev/null; then ok=0; fi; }

_v4 -F HXCTF_EGRESS 2>/dev/null || _v4 -N HXCTF_EGRESS 2>/dev/null || true
if ! _v4 -C OUTPUT -m owner --uid-owner "${EXEC_UID}" -j HXCTF_EGRESS 2>/dev/null; then
  _try _v4 -A OUTPUT -m owner --uid-owner "${EXEC_UID}" -j HXCTF_EGRESS
fi
_try _v4 -A HXCTF_EGRESS -o lo   -j ACCEPT
_try _v4 -A HXCTF_EGRESS -o tun+ -j ACCEPT
_try _v4 -A HXCTF_EGRESS -j DROP
_v4 -C HXCTF_EGRESS -j DROP 2>/dev/null || ok=0

if command -v ip6tables >/dev/null 2>&1; then
  _v6 -F HXCTF_EGRESS6 2>/dev/null || _v6 -N HXCTF_EGRESS6 2>/dev/null || true
  _v6 -C OUTPUT -m owner --uid-owner "${EXEC_UID}" -j HXCTF_EGRESS6 2>/dev/null \
    || _v6 -A OUTPUT -m owner --uid-owner "${EXEC_UID}" -j HXCTF_EGRESS6 2>/dev/null || true
  _v6 -A HXCTF_EGRESS6 -o lo   -j ACCEPT 2>/dev/null || true
  _v6 -A HXCTF_EGRESS6 -o tun+ -j ACCEPT 2>/dev/null || true
  _v6 -A HXCTF_EGRESS6 -j DROP 2>/dev/null || true
else
  echo "[egress] WARN: 无 ip6tables,IPv6 出网未封(IPv4 已封;当前靶标为 IPv4,影响小)。" >&2
fi

if [ "${ok}" != 1 ]; then
  echo "[egress] FAILED(locked): iptables 规则未能全部装上(需 --cap-add NET_ADMIN + 可用 netfilter 后端)" \
       "→ fail-closed 拒绝放开(绝不谎报 LOCKED)。" >&2
  exit 1
fi
echo "[egress] LOCKED: executor(uid ${EXEC_UID}) internet blocked (VPN tun + loopback only); engine(root) egress open."
