"""⑥ 补历史告警情况：为待推送告警追加"该资产近7天的推送历史"上下文。"""
from __future__ import annotations

import json
from pathlib import Path
from typing import Optional

import common
from tools import history as history_mod


def enrich(results: list[dict], run_d: Optional[Path] = None) -> list[dict]:
    """在 parsed 里补 history_note 字段（推送正文会带上，帮值班同学判断是否重复场景）。"""
    if run_d is not None:
        history_mod.set_db_override(Path(run_d) / "push_log.db")
    for r in results:
        ip = r["parsed"].get("ip") or r["alert"].get("ip", "")
        try:
            data = json.loads(history_mod.query_alert_history(ip))
        except Exception:
            data = {}
        count = int(data.get("count") or 0)
        if count:
            recent = (data.get("recent") or [{}])[0]
            r["parsed"]["history_note"] = (f"该主机近7天已推送 {count} 条告警"
                                           f"（最近一次：{recent.get('time', '-')} {recent.get('rule', '-')}）")
        else:
            r["parsed"]["history_note"] = "该主机近7天无已推送告警（首次/久违场景）"
    return results
