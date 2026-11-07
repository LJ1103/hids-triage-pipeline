"""工具：查询某资产近 N 天的已推送告警历史（push_log.db + 种子历史）。

既供 AI 研判参考（是否重复风险场景），也是⑥补历史告警情况的数据来源。
"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import common

# 测试/自定义 run 目录时由 tools.get_tools() 注入覆盖
_DB_OVERRIDE: Optional[Path] = None


def set_db_override(path: Optional[Path]) -> None:
    global _DB_OVERRIDE
    _DB_OVERRIDE = Path(path) if path else None


def _load_history(ip: str, days: int, now_ts: float) -> list[dict]:
    """合并 push_log.db 与种子历史，返回该 IP 近 N 天已推送告警（新→旧）。"""
    items: list[dict] = []

    seed = common.read_json(common.data_dir() / "history_seed.json", default=[])
    for h in seed:
        if h.get("ip") == ip:
            items.append({"time": h["time"], "ip": h.get("ip", ip), "host": h.get("host", ""),
                          "rule": h.get("rule", ""), "risk": h.get("risk", ""), "verdict": h.get("verdict", ""),
                          "ts": None})

    db = _DB_OVERRIDE or common.db_path()
    if Path(db).exists():
        conn = common.init_db(db)
        try:
            cutoff = now_ts - days * 86400
            rows = conn.execute(
                "SELECT pushed_at, ip, host, rule, risk, verdict FROM push_log "
                "WHERE ip = ? AND pushed_ts >= ? ORDER BY pushed_ts DESC LIMIT 20",
                (ip, cutoff),
            ).fetchall()
            for r in rows:
                items.append({"time": r[0], "ip": r[1], "host": r[2], "rule": r[3],
                              "risk": r[4], "verdict": r[5], "ts": None})
        finally:
            conn.close()

    # 有 ts 的按 ts 排序，种子数据保持原序，整体取前 10
    return items[:10]


def query_alert_history(ip: str, days: int = 7) -> str:
    """查询某资产近 N 天内已推送过的告警记录（含风险等级与研判结论）。

    Args:
        ip: 资产内网 IP
        days: 回溯天数，默认 7

    Returns:
        JSON 字符串：ip / days / count / recent
    """
    now_ts = common.now_ts()
    recent = _load_history(ip, days, now_ts)
    out = {
        "ip": ip, "days": days, "count": len(recent), "recent": recent,
        "summary": f"{ip} 近{days}天已推送 {len(recent)} 条告警" if recent
                   else f"{ip} 近{days}天无已推送告警记录",
    }
    return json.dumps(out, ensure_ascii=False)
