"""⑤ 冷却：同 (用户+主机+规则) 的低/中危告警连续推送 N 次 → 静默 1h。

- 高危不冷却（漏报代价 > 打扰代价）
- 超过 reset_window 小时未再出现 → 计数重置（避免长尾累计误触发）
- 静默留痕：写 run/silenced.log，可审计"哪些告警被冷却了"
- 关键边界：全部静默时 runner 不推送、不写 push_log——
  否则冷却恢复后的告警会被②的 12h 去重吞掉，造成漏报
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import common


def cooldown_key(result: dict) -> str:
    p = result["parsed"]
    user = p.get("用户") or result["alert"].get("user", "")
    host = p.get("host") or result["alert"].get("host", "")
    rule = p.get("规则") or result["alert"].get("rule", "")
    return f"{user}|{host}|{rule}"


def _load(state_path: Path) -> dict:
    return common.read_json(state_path, default={}) or {}


def _save(state_path: Path, state: dict) -> None:
    common.write_json(state_path, state)


def _append_trace(run_d: Path, line: str) -> None:
    with open(run_d / "silenced.log", "a", encoding="utf-8") as f:
        f.write(line + "\n")


def filter_silenced(results: list[dict], state_path: Path, cfg: dict,
                    run_d: Optional[Path] = None,
                    now_ts: Optional[float] = None) -> tuple[list[dict], list[dict]]:
    """把处于静默期内的低/中危告警过滤掉。返回 (保留, 被静默的)，静默留痕。"""
    now_ts = now_ts if now_ts is not None else common.now_ts()
    state = _load(state_path)
    kept, silenced = [], []
    for r in results:
        if r["parsed"].get("risk_level") == "高危":
            kept.append(r)  # 高危永不冷却
            continue
        key = cooldown_key(r)
        st = state.get(key) or {}
        if now_ts < float(st.get("silenced_until") or 0):
            silenced.append(r)
            run_d = run_d or state_path.parent
            _append_trace(run_d, f"[{common.fmt_ts(now_ts)}] SILENCE {key} "
                                 f"until {common.fmt_ts(st['silenced_until'])}")
            continue
        kept.append(r)
    return kept, silenced


def update_after_push(kept: list[dict], state_path: Path, cfg: dict,
                      now_ts: Optional[float] = None) -> None:
    """推送完成后更新冷却计数：达到阈值则布防静默窗口（第 N 次仍推送，之后静默）。"""
    now_ts = now_ts if now_ts is not None else common.now_ts()
    cd = cfg.get("cooldown", {})
    threshold = int(cd.get("threshold", 5))
    silence_s = float(cd.get("silence_minutes", 60)) * 60
    reset_s = float(cd.get("reset_window_hours", 2)) * 3600

    state = _load(state_path)
    changed = False
    for r in kept:
        if r["parsed"].get("risk_level") == "高危":
            continue  # 高危不计入冷却
        key = cooldown_key(r)
        st = state.get(key) or {}
        if now_ts - float(st.get("window_start") or 0) > reset_s:
            st = {"count": 0, "window_start": now_ts}
        st["count"] = int(st.get("count", 0)) + 1
        if st["count"] >= threshold:
            st["silenced_until"] = now_ts + silence_s
            st["count"] = 0
            _append_trace(state_path.parent,
                          f"[{common.fmt_ts(now_ts)}] COOLDOWN_ARMED {key} "
                          f"after {threshold} pushes, silent until {common.fmt_ts(st['silenced_until'])}")
        state[key] = st
        changed = True
    if changed:
        _save(state_path, state)
