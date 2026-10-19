from __future__ import annotations

import ipaddress
import re
import threading
from urllib.parse import urlparse

_CIDR_RX = re.compile(r"\b(10\.\d{1,3}\.\d{1,3}\.\d{1,3}/\d{1,2}"
                      r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}/\d{1,2}"
                      r"|192\.168\.\d{1,3}\.\d{1,3}/\d{1,2})\b")
_INET_RX = re.compile(r"inet6?\s+((?:\d{1,3}\.){3}\d{1,3}/\d{1,2})")
_RFC1918 = (r"(?:10\.\d{1,3}\.\d{1,3}\.\d{1,3}"
            r"|172\.(?:1[6-9]|2\d|3[01])\.\d{1,3}\.\d{1,3}"
            r"|192\.168\.\d{1,3}\.\d{1,3})")
_NEIGH_RX = re.compile(r"\b(" + _RFC1918 + r")\s+dev\s+\S+")
_ARP_RX = re.compile(r"\((" + _RFC1918 + r")\)\s+at\s")
_ROUTE_HOST_RX = re.compile(r"\b(" + _RFC1918 + r")\s+via\s")
_ROUTE_CIDR_RX = re.compile(r"\b(" + _RFC1918 + r"/\d{1,2})\s+(?:via|dev|proto|scope|src|metric|onlink|table)\b", re.I)


def _ip(s: str):
    s = (s or "").strip()
    for cand in (s, s.strip("[]"), s.rsplit(":", 1)[0].strip("[]"), s.split("/")[0]):
        try:
            return ipaddress.ip_address(cand)
        except ValueError:
            continue
    return None


def _net(s: str):
    try:
        return ipaddress.ip_network(s, strict=False)
    except ValueError:
        return None


_MAX_LEARNED_NETS = 16


def _overlap(a, b) -> bool:
    return a.version == b.version and (a.subnet_of(b) or b.subnet_of(a))


def _authority_of(s: str) -> str:
    s = (s or "").strip()
    if "//" in s:
        s = urlparse(s).netloc or s
    return s.split("/", 1)[0]


def _host_of(authority: str) -> str:
    a = (authority or "").strip()
    if a.startswith("["):
        return a[1:].split("]", 1)[0]
    if a.count(":") == 1:
        return a.split(":", 1)[0]
    return a


class EngagementScope:

    def __init__(self, targets: list[str], infra_allow: list[str] | None = None,
                 reserved: list[str] | None = None, authorized: list[str] | None = None):
        self._lock = threading.RLock()
        self.nets: list = []
        self.infra = set(infra_allow or [])
        self.reserved: set[str] = {_authority_of(r) for r in (reserved or []) if _authority_of(r)}
        self.targets: set[str] = set()
        self._authorized_domains: list[str] = []
        auths = [_authority_of(t) for t in (targets or [])]
        self.authority = auths[0] if auths else ""
        self.host = _host_of(self.authority)
        for a in auths:
            h = _host_of(a)
            ip = _ip(h)
            if ip is not None:
                self.targets.add(str(ip))
            elif "." in (h or ""):
                self._authorized_domains.append(h.lower())
        self._foothold_hosts: set[str] = set()
        self._authorized_nets: list = []
        self._authorized: bool = False
        for ent in (authorized or []):
            e = (ent or "").strip()
            if not e:
                continue
            self._authorized = True
            n = _net(e)
            if n is not None:
                self._authorized_nets.append(n)
                if not any(_overlap(n, x) for x in self.nets):
                    self.nets.append(n)
            else:
                _h = _host_of(_authority_of(e))
                ip = _ip(_h)
                if ip is not None:
                    self.targets.add(str(ip))
                elif "." in (_h or ""):
                    self._authorized_domains.append(_h.lstrip("*.").lower())

    def _domain_ok(self, host: str) -> bool:
        h = (host or "").strip().lower().rstrip(".")
        if not h:
            return False
        return any(h == d or h.endswith("." + d) for d in self._authorized_domains)

    def _authorized_ok(self, net) -> bool:
        if not self._authorized:
            return True
        return any(net.version == a.version and net.subnet_of(a) for a in self._authorized_nets)

    def note_foothold(self, host_ip: str, *, verified: bool) -> None:
        ip = _ip(host_ip)
        if ip is not None and verified:
            with self._lock:
                self._foothold_hosts.add(str(ip))

    def learn_from_observation(self, host_ip: str, observation_text: str, *, verified: bool) -> list[str]:
        ip = _ip(host_ip)
        if ip is None or not verified:
            return []
        with self._lock:
            if str(ip) not in self._foothold_hosts:
                return []
            found: set = set()
            for _ln in observation_text.splitlines():
                found |= set(_INET_RX.findall(_ln))
                found |= set(_ROUTE_CIDR_RX.findall(_ln))
                for _nip in set(_NEIGH_RX.findall(_ln)) | set(_ARP_RX.findall(_ln)):
                    found.add(_nip.rsplit(".", 1)[0] + ".0/24")
                for _hip in set(_ROUTE_HOST_RX.findall(_ln)):
                    found.add(_hip + "/32")
            target_ips = [t for t in (_ip(x) for x in self.targets) if t is not None]
            external_nets = []
            for _inet in set(_INET_RX.findall(observation_text)):
                _en = _net(_inet)
                if _en is not None and any(t in _en for t in target_ips):
                    external_nets.append(_en)
            added = []
            for c in found:
                net = _net(c)
                if net is None or net.prefixlen < 16:
                    continue
                if not self._authorized_ok(net):
                    continue
                if any(t in net for t in target_ips):
                    continue
                if any(_overlap(net, ext) for ext in external_nets):
                    continue
                if any(_overlap(net, n) for n in self.nets):
                    continue
                if len(self.nets) >= _MAX_LEARNED_NETS:
                    break
                self.nets.append(net)
                added.append(str(net))
            return added

    def learn_foothold_net(self, host_ip: str, observation_text: str) -> list[str]:
        with self._lock:
            self.note_foothold(host_ip, verified=True)
            return self.learn_from_observation(host_ip, observation_text, verified=True)

    def learn_reachable_dst(self, dst: str, *, verified: bool) -> list[str]:
        if not verified:
            return []
        ip = _ip(dst)
        if ip is None or ip.version != 4 or not ip.is_private:
            return []
        with self._lock:
            cidr = str(ip).rsplit(".", 1)[0] + ".0/24"
            net = _net(cidr)
            if net is None or net.prefixlen < 16:
                return []
            target_ips = [t for t in (_ip(x) for x in self.targets) if t is not None]
            if any(t in net for t in target_ips):
                return []
            reserved_ips = [ip2 for ip2 in (_ip(_host_of(a)) for a in self.reserved) if ip2 is not None]
            if any(rip in net for rip in reserved_ips):
                return []
            if not self._authorized_ok(net):
                return []
            if any(net.subnet_of(n) or n.subnet_of(net) for n in self.nets):
                return []
            if len(self.nets) >= _MAX_LEARNED_NETS:
                return []
            self.nets.append(net)
            return [str(net)]

    def unexploited_surface(self) -> list[str]:
        with self._lock:
            fh_ips = [ip for ip in (_ip(h) for h in self._foothold_hosts) if ip is not None]
            return [str(n) for n in self.nets if not any(ip in n for ip in fh_ips)]

    def rehydrate(self, footholds: list[str], nets: list[str]) -> None:
        with self._lock:
            for h in footholds:
                ip = _ip(h)
                if ip is not None:
                    self._foothold_hosts.add(str(ip))
            target_ips = [t for t in (_ip(x) for x in self.targets) if t is not None]
            for c in nets:
                net = _net(c)
                if net is None or net.prefixlen < 16:
                    continue
                if not self._authorized_ok(net):
                    continue
                if any(t in net for t in target_ips):
                    continue
                if any(_overlap(net, n) for n in self.nets):
                    continue
                if len(self.nets) >= _MAX_LEARNED_NETS:
                    break
                self.nets.append(net)

    def is_in_scope(self, target: str) -> bool:
        ip = _ip(target)
        if ip is None:
            return self._domain_ok(_host_of(target) or target)
        with self._lock:
            if str(ip) in self.targets or str(ip) in self.infra:
                return True
            return any(ip in n for n in self.nets)

    def reserved_ports_on(self, host: str) -> set:
        h = _host_of(host) or host
        out = set()
        with self._lock:
            for a in self.reserved:
                rh, _, rp = str(a).rpartition(":")
                if rh.strip("[]") == h and rp.isdigit():
                    out.add(int(rp))
        return out

    def is_reserved_host(self, ip: str) -> bool:
        h = _host_of(ip) or ip
        with self._lock:
            return any((_host_of(a) or "") == h for a in self.reserved)

    def source_in_scope(self, cmd_target: str | None) -> bool:
        if not cmd_target:
            return True
        host = _host_of(cmd_target)
        ip = _ip(host)
        if ip is None:
            return self._domain_ok(host) or True
        hp = _authority_of(cmd_target) if ":" in cmd_target else None
        with self._lock:
            if hp is not None and hp in self.reserved:
                return False
            if any(ip in n for n in self.nets):
                return True
            if host == self.host:
                return True
        return False

    def reserved_list(self) -> list[str]:
        with self._lock:
            return sorted(self.reserved)

    def boundary(self) -> list[str]:
        with self._lock:
            others = [t for t in sorted(self.targets) if t != self.host]
            nets = [str(n) for n in self.nets]
            infra = sorted(self.infra)
            domains = [f"*.{d} (and {d} itself)" for d in sorted(set(self._authorized_domains))]
        return ([self.authority] if self.authority else []) + others + nets + infra + domains

    def describe(self) -> dict:
        with self._lock:
            return {"targets": sorted(self.targets), "learned_nets": [str(n) for n in self.nets],
                    "footholds": sorted(self._foothold_hosts), "infra": sorted(self.infra),
                    "authority": self.authority,
                    "authorized_domains": sorted(set(self._authorized_domains))}
