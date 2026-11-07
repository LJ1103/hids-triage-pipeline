"""工具：查询资产归属信息（mock 数据，对应真实环境里的 CMDB / 资产管理平台 API）。"""
from __future__ import annotations

import json

import common


def _load_assets() -> dict:
    return common.read_json(common.data_dir() / "assets.json", default={})


def get_asset_info(ip: str) -> str:
    """查询资产归属：负责人、部门、环境、业务用途。

    Args:
        ip: 资产内网 IP

    Returns:
        JSON 字符串：known / hostname / owner / department / env / role / summary
    """
    assets = _load_assets()
    info = assets.get(ip)
    if info:
        out = {"known": True, **info,
               "summary": f"{ip} 为{info['env']}环境 {info['role']}（{info['business']}），"
                          f"资产负责人 {info['owner']}（{info['department']}）"}
    else:
        out = {"known": False, "hostname": "", "owner": "", "department": "", "env": "", "role": "",
               "summary": f"{ip} 未在资产台账中登记（未纳管资产），无法定位负责人"}
    return json.dumps(out, ensure_ascii=False)
