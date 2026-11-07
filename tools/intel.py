"""工具：查询威胁情报（mock 数据，对应真实环境里的内部情报平台 / 微步在线等 API）。"""
from __future__ import annotations

import json

import common


def _load_intel() -> dict:
    return common.read_json(common.data_dir() / "intel.json", default={})


def query_threat_intel(indicator: str) -> str:
    """查询 IP/域名/哈希是否命中已知威胁情报。

    Args:
        indicator: 待查询的 IP、域名或文件哈希

    Returns:
        JSON 字符串：queried / malicious / confidence / source / tags
    """
    intel = _load_intel()
    hit = intel.get(indicator)
    if hit:
        out = {"queried": indicator, **hit,
               "summary": f"{indicator} 命中威胁情报：{hit['source']}，置信度 {hit['confidence']}，"
                          f"标签 {','.join(hit['tags'])}"}
    else:
        out = {"queried": indicator, "malicious": False, "confidence": 0.0,
               "source": "-", "tags": [],
               "summary": f"{indicator} 未命中已知恶意情报"}
    return json.dumps(out, ensure_ascii=False)
