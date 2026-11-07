"""⑨ 留痕：推送结果写 push_log.db（②的 12h 去重依据）+ 运行计数。"""
from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Optional

import common
from pipeline.precheck import dedup_key


def record(results: list[dict], db: Optional[Path] = None,
           counters_path: Optional[Path] = None,
           now_ts: Optional[float] = None,
           stats: Optional[dict] = None) -> int:
    """把实际推送过的告警写入 push_log，并累加 counters.json。

    只记录"真实推送"的告警：被冷却静默的不写——
    否则冷却恢复后，同三元组会被②的 12h 去重吞掉（漏报）。
    """
    now_ts = now_ts if now_ts is not None else common.now_ts()
    conn = common.init_db(db) if db else common.init_db()
    try:
        rows = []
        for r in results:
            a = r["alert"]
            p = r["parsed"]
            rows.append((
                a.get("alert_id", ""), dedup_key(a), a.get("ip", ""),
                str(a.get("command", ""))[:200], a.get("alert_type", ""),
                p.get("用户") or a.get("user", ""),
                p.get("host") or a.get("host", ""),
                p.get("规则") or a.get("rule", ""),
                p.get("risk_level", "中危"),
                p.get("verdict", ""),
                common.fmt_ts(now_ts), now_ts,
            ))
        conn.executemany(
            "INSERT INTO push_log (alert_id, dedup_key, ip, cmd_prefix, alert_type, "
            "user, host, rule, risk, verdict, pushed_at, pushed_ts) "
            "VALUES (?,?,?,?,?,?,?,?,?,?,?,?)", rows)
        conn.commit()
    finally:
        conn.close()

    _bump_counters(counters_path, stats or {}, len(results))
    return len(results)


def _bump_counters(counters_path: Optional[Path], stats: dict, pushed: int) -> None:
    path = counters_path or (common.run_dir() / "counters.json")
    c = common.read_json(path, default={}) or {}
    c["runs"] = int(c.get("runs", 0)) + 1
    for k, v in stats.items():
        c[k] = int(c.get(k, 0)) + int(v)
    c["pushed"] = int(c.get("pushed", 0)) + pushed
    common.write_json(path, c)


def read_counters(counters_path: Optional[Path] = None) -> dict:
    path = counters_path or (common.run_dir() / "counters.json")
    return common.read_json(path, default={}) or {}
