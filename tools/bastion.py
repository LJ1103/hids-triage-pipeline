"""工具：查询堡垒机近 24h 登录记录（mock 数据，对应真实环境里的堡垒机审计 API）。

AI 研判的硬性第一步：任何告警结论前必须先核实"这个用户是否经堡垒机合规登录过这台机器"。
"""
from __future__ import annotations

import json

import common


def _load_records() -> list[dict]:
    return common.read_json(common.data_dir() / "bastion_logs.json", default=[])


def query_bastion_log(user: str, ip: str) -> str:
    """查询指定用户在指定主机的堡垒机近24小时登录记录。

    Args:
        user: 告警中触发命令的用户名
        ip: 告警主机的内网 IP

    Returns:
        JSON 字符串：found / records / summary
    """
    records = [r for r in _load_records() if r.get("user") == user and r.get("ip") == ip]
    if records:
        r = records[-1]
        summary = (f"用户 {user} 近24h曾通过堡垒机登录 {ip}（{r['login_time']}，"
                   f"{r['method']}，源IP {r['source_ip']}，MFA={'通过' if r.get('mfa') else '未启用'}）")
        out = {"found": True, "records": records, "summary": summary}
    else:
        summary = (f"近24h无用户 {user} 经堡垒机登录 {ip} 的记录；"
                   f"若该用户确在主机上执行了命令，则登录路径未纳管（绕过堡垒机直接登录），需警惕")
        out = {"found": False, "records": [], "summary": summary}
    return json.dumps(out, ensure_ascii=False)
