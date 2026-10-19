from __future__ import annotations

from collections import Counter

MIN_PERSIST = 3


def consolidate_foothold(tsg, host_id: str, host_ukey: str, *, access: str,
                         payload: str = "", evidence_ref: str | None = None,
                         verified: bool = False, entry: str | None = None,
                         grammar: str | None = None, failures: str | None = None,
                         attest: str = "") -> tuple[str, str | None]:
    _cap_ukey = f"{access}@{host_ukey}"
    import json as _json
    _prev = tsg.q1("SELECT verified, extra FROM nodes WHERE type='capability' AND ukey=?", (_cap_ukey,))
    _pv = bool(_prev and _prev["verified"])
    _pe = {}
    if _prev and _prev["extra"]:
        try:
            _pe = _json.loads(_prev["extra"]) if isinstance(_prev["extra"], str) else dict(_prev["extra"] or {})
        except Exception:
            _pe = {}
    eff_verified = bool(verified or _pv)
    _prev_att = _pe.get("attestation") or {}
    if eff_verified and (verified or _pv):
        _att = ({"level": "verified", "by": attest or "machine-verified", "at": __import__("datetime").datetime.now().isoformat(timespec="seconds")}
                if (verified or _prev_att.get("level") != "verified") else _prev_att)
    else:
        _att = _prev_att if _prev_att.get("level") == "verified" else {
            "level": "claimed", "by": attest or "executor-declared"}
    merged_extra = {"access": access, "consumed": _pe.get("consumed", False),
                    "payload": payload or _pe.get("payload", ""),
                    "evidence_ref": evidence_ref or _pe.get("evidence_ref"),
                    "verified": eff_verified,
                    "attestation": _att,
                    "entry": entry or _pe.get("entry"),
                    "grammar": grammar or _pe.get("grammar"),
                    "failures": failures or _pe.get("failures")}
    cap_id = tsg.upsert_node(
        "capability", _cap_ukey,
        title=f"{access} on {host_ukey}", verified=eff_verified, extra=merged_extra)
    fh_id = None
    if verified:
        fh_id = tsg.upsert_node(
            "foothold", host_ukey, title=f"foothold {host_ukey} ({access})", verified=True,
            extra={"access": access})
        tsg.add_edge(host_id, fh_id, "produced_by")
        sg_id = derive_exploit_subgoal(tsg, host_ukey, access)
        tsg.add_edge(cap_id, sg_id, "enables")
    tsg.add_edge(host_id, cap_id, "enables")
    return cap_id, fh_id


def derive_exploit_subgoal(tsg, host_ukey: str, access: str) -> str:
    ukey = f"exploit:@{host_ukey}"
    return tsg.upsert_node(
        "subgoal", ukey, state="active",
        title=f"leverage the obtained access on {host_ukey} to locate and capture the flag / deliverable",
        extra={"derived_from": "foothold", "access": access, "expects": {"kind": "flag", "host": host_ukey}})


def consume_capability(tsg, cap_id: str) -> None:
    row = tsg.q1("SELECT type,ukey,title,extra FROM nodes WHERE id=?", (cap_id,))
    if not row:
        return
    import json
    ex = json.loads(row["extra"] or "{}")
    ex["consumed"] = True
    tsg.upsert_node(row["type"], row["ukey"], title=row["title"], verified=True, extra=ex)


def unconsumed_capabilities(tsg, *, verified_only: bool = False) -> list[dict]:
    import json
    out = []
    where = "type='capability'" + (" AND verified=1" if verified_only else "")
    for r in tsg.q(f"SELECT id,title,extra,verified FROM nodes WHERE {where} ORDER BY updated_ts DESC"):
        ex = json.loads(r["extra"] or "{}")
        if not ex.get("consumed"):
            out.append({"id": r["id"], "title": r["title"], "access": ex.get("access"),
                        "payload": ex.get("payload", ""), "verified": bool(r["verified"]),
                        "entry": ex.get("entry"), "grammar": ex.get("grammar"),
                        "failures": ex.get("failures")})
    return out


_RECON = {"kind": "recon"}


def source_seed_title(dist: str) -> str:
    return ("Download and unpack the distributed source bundle (" + (dist or "src.zip / apk")[:80] + ") to "
            "/workspace/att/src/, then audit it for validation-vs-implementation mismatches: sibling "
            "endpoints with differing sanitization, hidden DTO/flag fields, integer width mismatches "
            "between check and settlement, signature/canonicalization downgrades, and secrets served "
            "from public endpoints — then drive each mismatch to its flag.")


def bypass_seed_title(rule: str, blocked: str, variants: str) -> str:
    return ("The WAF rule '" + (rule or "?")[:30] + "' blocked payload '" + (blocked or "")[:80] +
            "'. Explore bypasses across THREE dimensions: (a) syntax transforms (encoding/double-encoding/"
            "equivalent-quote/whitespace), (b) ORACLE CHANNEL SWITCH — if the timing token is blocked, "
            "switch channel entirely: boolean differential, error-based, file-read primitives "
            "(COPY FROM PROGRAM / pg_read_file), out-of-band (dblink/SSRF/DNS) — and (c) stacked-statement "
            "template integrity for this DB (trailing absorbing statement + $$ dollar-quoting; check KB). "
            "Candidate directions: " + (variants or "")[:300])


def enum_seed_title(primitive: str, context: str = "") -> str:
    return ("You hold a '" + (primitive or "file-read")[:40] + "' primitive" +
            (" against " + context[:80] if context else "") +
            ". Run a SYSTEMATIC credential-filename dictionary sweep across likely directories "
            "(service data dirs, config dirs, home dirs): generate candidates from "
            "service-name × {credentials, secrets, vault, keys, tokens, .env, backup} × "
            "{conf, json, yaml, txt, bak} plus common absolute paths — hundreds to thousands of "
            "probes, scripted, not hand-picked. Read every hit.")


def decoy_seed_title(flag: str) -> str:
    return ("The value '" + (flag or "")[:60] + "' was rejected — it is a DECOY. Enumerate ALL "
            "schemas/tables/config stores reachable from your current access for the REAL flag "
            "(information_schema enumeration, config files, app_config/release fields, random-named "
            "tables) — the decoy's existence proves a real one is elsewhere in this data set.")


def deception_seed_title() -> str:
    from engine.koh import deception_seed
    return deception_seed()


def recon_seed_title(recon_summary: str = "") -> str:
    base = ("Enumerate and exploit the target end-to-end: map every reachable endpoint, parameter and input plus "
            "the technology stack, then test each exposed input for the common vulnerability classes it enables — "
            "SQL/command/template injection, path traversal / arbitrary file read (LFI), broken access control / "
            "IDOR, unrestricted file upload, SSRF, insecure deserialization — and drive each confirmed weakness "
            "straight to the flag; do NOT stop at reconnaissance.")
    rs = (recon_summary or "").strip()
    if rs:
        base += f"  Known recon to build on: {rs[:220]}"
    return base


def add_subgoal(tsg, title: str, wave: int, *, expects: dict | None = None) -> str:
    return tsg.upsert_node("subgoal", title, title=title, state="active",
                           extra={"activated_wave": wave, "expects": dict(expects) if expects else dict(_RECON)})


def expects_of(extra) -> dict:
    import json
    try:
        e = json.loads(extra) if isinstance(extra, str) else dict(extra or {})
    except (TypeError, ValueError):
        e = {}
    return e.get("expects") or dict(_RECON)


def _bare_host(h: str | None) -> str:
    s = str(h or "")
    if s.startswith("[") and "]" in s:
        return s[1:s.index("]")]
    if s.count(":") == 1:
        return s.split(":")[0]
    return s


def _host_in_face(host: str | None, face: str | None) -> bool:
    import ipaddress
    if not host or not face:
        return False
    try:
        return ipaddress.ip_address(_bare_host(host)) in ipaddress.ip_network(str(face), strict=False)
    except (ValueError, TypeError):
        return _bare_host(host) == _bare_host(face)


def net_match(a: str | None, b: str | None) -> bool:
    import ipaddress
    if not a or not b:
        return False
    try:
        na = ipaddress.ip_network(str(a), strict=False)
        nb = ipaddress.ip_network(str(b), strict=False)
        if na.version != nb.version:
            return False
        return na == nb or na.subnet_of(nb) or nb.subnet_of(na)
    except (ValueError, TypeError):
        return str(a) == str(b)


def _confirmed_flag_origins(tsg) -> list:
    import json
    out = []
    for r in tsg.q("SELECT extra FROM nodes WHERE type='flag' AND state='confirmed'"):
        try:
            ex = json.loads(r["extra"] or "{}")
        except (TypeError, ValueError):
            ex = {}
        out.append(ex.get("origin"))
    return out


def _met_flag(tsg, e: dict) -> bool:
    face, host, need = e.get("face"), e.get("host"), e.get("need")
    count = max(1, int(e.get("count") or 1))
    origins = _confirmed_flag_origins(tsg)
    if host:
        hits = [o for o in origins if _host_in_face(o, host)]
        return len(hits) >= count
    if face:
        hits = [o for o in origins if _host_in_face(o, face)]
        return len(hits) >= count
    if need:
        return (tsg.q1("SELECT COUNT(*) c FROM nodes WHERE type='flag' AND state='confirmed'") or {"c": 0})["c"] >= int(need)
    n_any = (tsg.q1("SELECT COUNT(*) c FROM nodes WHERE type='flag' AND state='confirmed'") or {"c": 0})["c"]
    return n_any >= count


def _met_capability(tsg, e: dict) -> bool:
    host = e.get("host")
    if host:
        return bool(tsg.q1("SELECT 1 FROM nodes WHERE type='capability' AND verified=1 AND ukey LIKE ?", (f"%@{host}",)))
    return bool(tsg.q1("SELECT 1 FROM nodes WHERE type='capability' AND verified=1"))


_MET = {
    "recon":      lambda tsg, e, got: bool(got),
    "flag":       lambda tsg, e, got: _met_flag(tsg, e),
    "capability": lambda tsg, e, got: _met_capability(tsg, e),
}


def deliverable_met(tsg, expects: dict, *, got_progress: bool) -> bool:
    e = expects or _RECON
    return _MET.get(e.get("kind", "recon"), _MET["recon"])(tsg, e, got_progress)


def can_abandon(activated_wave: int, current_wave: int, *, refuted: bool,
                min_persist: int = MIN_PERSIST) -> bool:
    if refuted:
        return True
    return (current_wave - activated_wave) >= min_persist


def achieve_subgoal(tsg, subgoal_id: str) -> None:
    r = tsg.q1("SELECT ukey,title,extra FROM nodes WHERE id=?", (subgoal_id,))
    if r:
        import json
        tsg.upsert_node("subgoal", r["ukey"], title=r["title"], state="achieved",
                        extra=json.loads(r["extra"] or "{}"))


def is_stuck(recent_sigs: list[str], threshold: int = 2) -> bool:
    if not recent_sigs:
        return False
    return max(Counter(recent_sigs).values()) >= threshold


def bridge_step(tsg, subgoal_id: str, *, state_context: str, milestone_gap: str,
                action_correction: str) -> str:
    sid = tsg.upsert_node(
        "step", f"bridge:{subgoal_id}:{milestone_gap[:24]}",
        title=f"[bridge] {action_correction[:60]}", state="open",
        extra={"bridge": True, "state_context": state_context,
               "milestone_gap": milestone_gap, "action_correction": action_correction})
    tsg.add_edge(sid, subgoal_id, "serves")
    return sid
