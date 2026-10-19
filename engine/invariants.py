from __future__ import annotations


def _faces_with_active_target(active) -> set:
    return {(e or {}).get("face") for _uk, e in active
            if (e or {}).get("kind") == "flag" and (e or {}).get("face")}


def i1_direction_lost(*, achieved: bool, unexploited, active) -> list:
    if achieved:
        return []
    targeted = _faces_with_active_target(active)
    return [f"I1 方向丢失:未拿下面 {f} 无指向它的活子目标" for f in unexploited if f not in targeted]


def i2_agent_achieved(tsg, achieved_targets) -> list:
    from engine import subgoal as SG
    return [f"I2 代理达成:{uk} 期望 {e} 但账本无对应事件"
            for uk, e in achieved_targets
            if (e or {}).get("kind") in ("flag", "capability")
            and not SG.deliverable_met(tsg, e, got_progress=False)]


def i3_clock_pollution(*, gap_open: bool, clock_reset_by_other_face: bool) -> list:
    return ["I3 钟污染:缺口未闭合的桶其干旱钟被异面/诱饵事件清零"] if (gap_open and clock_reset_by_other_face) else []


def i4_prefix_collision(active, n: int = 40) -> list:
    seen: dict = {}
    out = []
    for uk, _e in active:
        p = (uk or "")[:n]
        if p in seen and seen[p] != uk:
            out.append(f"I4 碰撞未遂:'{seen[p][:44]}…' 与 '{(uk or '')[:44]}…' 共享前 {n} 字符 LIKE 前缀")
        seen[p] = uk
    return out


def i5_route_face_direction_lost(route_unmet_faces, active) -> list:
    have = {e.get("face") for _uk, e in active
            if isinstance(e, dict) and e.get("kind") == "flag" and e.get("face")}
    return [f"I5 route面方向丢失:已建 route 到未夺旗面 {f} 却无活 flag 方向指向它"
            for f in (route_unmet_faces or []) if f not in have]


def check(tsg, *, achieved: bool, unexploited, active, achieved_targets=(),
          route_unmet_faces=(), gap_open: bool = False, clock_reset_by_other_face: bool = False) -> list:
    return (i1_direction_lost(achieved=achieved, unexploited=unexploited, active=active)
            + i2_agent_achieved(tsg, achieved_targets)
            + i3_clock_pollution(gap_open=gap_open, clock_reset_by_other_face=clock_reset_by_other_face)
            + i4_prefix_collision(active)
            + i5_route_face_direction_lost(route_unmet_faces, active))
