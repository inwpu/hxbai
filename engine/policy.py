from __future__ import annotations

from dataclasses import dataclass
from typing import Callable


@dataclass(frozen=True)
class MissionCtx:
    has_foothold: bool = False
    missing_flags: int = 0
    open_leads: int = 0
    has_login_surface: bool = False


@dataclass(frozen=True)
class PolicySpec:
    name: str
    text: str
    precedence: int
    trigger: Callable[[MissionCtx], bool]


_CRED_SPRAY = (
    "\nIDENTIFIED-PRODUCT CREDENTIALS — when a service that needs auth (SSH, an admin panel, a login, a "
    "DB/mgmt port) sits on a host you've fingerprinted to a specific product/vendor (especially an "
    "internal host reached by pivoting), that product's OWN well-known/default credentials — and guesses "
    "derived from the product/vendor/product-line name — are a FIRST-CLASS path: try them FIRST or "
    "alongside a generic wordlist brute, not after it. Look the product's defaults up in the KB "
    "(kb search <product> default credentials) and build name-derived guesses yourself. Keep it to a low "
    "rate (the rate discipline above still holds).")

_FLAG_HARVEST = (
    "\nHARVEST EVERY FLAG, SUBMIT EACH IMMEDIATELY — the deliverable is captured+submitted flags, NOT "
    "'I have a shell' or 'I cracked a secret'. The MOMENT you have command execution on ANY host (entry or "
    "an internal host you pivoted to), hunt exhaustively for flags and submit each the instant you find it: "
    "`grep -rna 'flag{' / 2>/dev/null`, `find / -iname '*flag*' 2>/dev/null`, check /challenge/flag*, /flag*, "
    "/root/flag*, and each service's own data; a root-only flag may need a quick local privesc "
    "(`find / -perm -4000 2>/dev/null`). Submit each real flag you ACTUALLY recover/observe the moment you "
    "see it — the platform dedups and tells you which count/index it filled; do NOT batch, do NOT "
    "re-submit an accepted one. (Skip obvious doc placeholders — an example `flag{...}` printed in a README/"
    "comment/help text — those are not real captures.) Keep going until the task's flag ledger is FULL "
    "(the STILL-MISSING count hits 0).")

_SEGMENT_SWEEP = (
    "\nMAP & SWEEP THE WHOLE SEGMENT — once you have ANY internal foothold, do not work only the host you "
    "landed on. Read /etc/hosts, `ip route`, `arp -a`, and any leaked host map (an init SQL / config / "
    "inventory often lists every internal node), then sweep the local /24 for live hosts and open ports "
    "(a concurrent /dev/tcp probe or an installed scanner) and resolve service names to IPs. Then pivot to "
    "and harvest EACH reachable internal host in turn — treat the task as one network to punch through, not "
    "one flag per attempt.")

_TARGET_MINING = (
    "\nWHEN A STEP STALLS, MINE THE TARGET (don't conclude you're stuck) — the target itself usually plants "
    "the next lead in-band: `cat` entrypoint/startup scripts, ~/.bash_history, app configs, and HTML/JS "
    "comments; `grep -rniE 'pass|secret|cred|token' /var/www /home /opt /app 2>/dev/null` — these routinely "
    "leak the next credential/path. When you do brute a service's auth (with the product-specific set noted "
    "above), run it over a SINGLE direct tunnel in small batches with pauses: services commonly rate-limit "
    "and LOCK YOU OUT if you hammer a big wordlist, so a small directed spray that respects the lockout "
    "beats a huge blind brute through a slow multi-hop proxy.")


def _net(ctx: MissionCtx) -> bool:
    return ctx.has_foothold


_MINIMAL_TEXT = (
    "\nDATA MINIMIZATION — fetch only what the current lead actually needs. Do not bulk-mirror, "
    "recursive-download, or mass-crawl when a single targeted read answers the question. "
    "Minimality is speed and cover: less data in transit, fewer requests, faster convergence."
)
_finding_live_ctx = lambda c: getattr(c, 'has_foothold', False)

POLICIES: tuple[PolicySpec, ...] = (
    PolicySpec("flag-harvest", _FLAG_HARVEST, 20,
               lambda c: _net(c) and c.missing_flags > 0),
    PolicySpec("segment-sweep", _SEGMENT_SWEEP, 30,
               lambda c: _net(c) and c.open_leads == 0),
    PolicySpec("cred-spray", _CRED_SPRAY, 40, lambda c: _net(c) or c.has_login_surface),
    PolicySpec("target-mining", _TARGET_MINING, 50, lambda c: _net(c) or c.has_login_surface),
    PolicySpec("data-minimization", _MINIMAL_TEXT, 55, _finding_live_ctx),
)

PRECEDENCE_HEADER = (
    "POLICY PRECEDENCE (when two directives seem to conflict, the higher wins):\n"
    "1. LEAD-CONSUMPTION — a concrete lead from committed facts outranks all breadth.\n"
    "2. FLAG-HARVEST — only when you hold execution AND no open lead.\n"
    "3. SEGMENT-SWEEP — only when the segment has unexplored hosts AND no open lead AND harvest is drained.\n"
    "A directive that is not in this session's policy list does not apply — do not act on it from memory.")


def select_policies(ctx: MissionCtx) -> list[PolicySpec]:
    return sorted((p for p in POLICIES if p.trigger(ctx)), key=lambda p: p.precedence)
