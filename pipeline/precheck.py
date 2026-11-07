"""② 一级门控（no_agent，纯脚本、零 token）：

- 12h 去重：同 (IP + 命令前200字符 + 告警类型) 三元组在窗口内已推送过 → 跳过
- 白名单：告警用户 / 规则名 / 资产 IP 命中 → 跳过
- 自动清理：push_log 超过保留期的老数据删除

门控协议：survivors 为空 → runner 静默退出（不进 AI、零 token、零推送）。
"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

import common


def dedup_key(alert: dict) -> str:
    """去重三元组：IP + 命令前 200 字符 + 告警类型。"""
    return f"{alert.get('ip', '')}|{str(alert.get('command', ''))[:200]}|{alert.get('alert_type', '')}"


def whitelist_hit(alert: dict, cfg: dict) -> bool:
    wl = cfg.get("precheck", {}).get("whitelist", {})
    if alert.get("user") in (wl.get("users") or []):
        return True
    if alert.get("rule") in (wl.get("rules") or []):
        return True
    if alert.get("ip") in (wl.get("ips") or []):
        return True
    return False


def _cleanup_old(conn: sqlite3.Connection, retention_days: int, now_ts: float) -> int:
    """删除超过保留期的 push_log 老数据，防止库无限膨胀。"""
    cutoff = now_ts - retention_days * 86400
    cur = conn.execute("DELETE FROM push_log WHERE pushed_ts < ?", (cutoff,))
    return cur.rowcount


def _recently_pushed(conn: sqlite3.Connection, key: str, dedup_hours: float, now_ts: float) -> bool:
    cutoff = now_ts - dedup_hours * 3600
    row = conn.execute(
        "SELECT 1 FROM push_log WHERE dedup_key = ? AND pushed_ts >= ? LIMIT 1",
        (key, cutoff),
    ).fetchone()
    return row is not None


def run_precheck(alerts: list[dict], cfg: dict,
                 db: Optional[Path] = None, now_ts: Optional[float] = None) -> dict:
    """执行一级门控。返回统计 dict：

    {"has_alerts": bool, "survivors": [...], "deduped": n, "whitelisted": n, "cleaned_rows": n}
    """
    now_ts = now_ts if now_ts is not None else common.now_ts()
    db = Path(db) if db else common.db_path(cfg)
    conn = common.init_db(db)
    try:
        pc = cfg.get("precheck", {})
        cleaned = _cleanup_old(conn, int(pc.get("log_retention_days", 30)), now_ts)
        conn.commit()

        survivors, n_dup, n_wl = [], 0, 0
        for a in alerts:
            if whitelist_hit(a, cfg):
                n_wl += 1
                continue
            if _recently_pushed(conn, dedup_key(a), float(pc.get("dedup_hours", 12)), now_ts):
                n_dup += 1
                continue
            survivors.append(a)
        return {
            "has_alerts": len(survivors) > 0,
            "survivors": survivors,
            "deduped": n_dup,
            "whitelisted": n_wl,
            "cleaned_rows": cleaned,
        }
    finally:
        conn.close()
