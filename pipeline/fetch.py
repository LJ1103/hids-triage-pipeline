"""① 拉取告警：读取告警源，规范化后写入 run/_latest_alerts.json。

这是全流水线与外部 HIDS 的唯一集成点：对接真实青藤 HIDS 时，
只需把 _load_raw() 换成调用其 OpenAPI，其余流程零改动。
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import common

# 规范化后的必填字段；payload/uri/file_path/user_agent/referer/query 为不可信字段
_CANONICAL_FIELDS = [
    "alert_id", "alert_type", "severity", "time", "host", "ip", "user",
    "source", "command", "rule",
]
_UNTRUSTED_FIELDS = ["payload", "uri", "file_path", "user_agent", "referer", "query"]
_SEVERITIES = {"info", "low", "medium", "high", "critical"}


def _normalize(raw: dict) -> dict:
    """补默认值、截断超长命令、校验枚举，输出统一结构。"""
    a = {k: raw.get(k, "") for k in _CANONICAL_FIELDS}
    for k in _UNTRUSTED_FIELDS:
        if raw.get(k):
            a[k] = str(raw[k])
    a["alert_id"] = str(a["alert_id"] or "UNKNOWN")
    a["severity"] = str(a["severity"]).lower()
    if a["severity"] not in _SEVERITIES:
        a["severity"] = "medium"
    # 命令保留前 500 字符（去重只用前 200，研判展示也足够）
    a["command"] = str(a["command"])[:500]
    return a


def _load_raw(source_file: Path) -> list[dict]:
    data = common.read_json(source_file, default=None)
    if data is None:
        return []
    if isinstance(data, dict):
        return data.get("alerts", []) or []
    return data if isinstance(data, list) else []


def fetch_alerts(cfg: dict, source_file: Optional[Path] = None,
                 run_d: Optional[Path] = None) -> list[dict]:
    """拉取告警源并写 run/_latest_alerts.json，返回规范化告警列表。"""
    run_d = run_d or common.run_dir(cfg)
    src_cfg = Path(cfg["fetch"]["source_file"])
    if source_file is not None:
        src = Path(source_file)
    elif src_cfg.is_absolute():
        src = src_cfg
    else:
        src = common.ROOT / src_cfg
    raw = _load_raw(src)
    alerts = [_normalize(a) for a in raw]
    common.write_json(run_d / "_latest_alerts.json", {
        "fetched_at": common.fmt_ts(common.now_ts()),
        "count": len(alerts),
        "alerts": alerts,
    })
    return alerts
