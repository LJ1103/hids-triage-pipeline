"""MCP server：把 4 个研判工具暴露给 Hermes Agent（stdio 传输）。

Hermes 侧一次性配置（~/.hermes/config.yaml）：
    mcpServers:
      hids-tools:
        command: python
        args: ["<本项目绝对路径>/mcp_server.py"]

之后 runner.py 内嵌的 AIAgent 即可通过 MCP 调用这 4 个工具，
且只能调用这 4 个——"AI 只研判、不执行"的边界由此落地。
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp.server.fastmcp import FastMCP

from tools import asset as asset_mod
from tools import bastion as bastion_mod
from tools import history as history_mod
from tools import intel as intel_mod

mcp = FastMCP("hids-tools")


@mcp.tool()
def query_bastion_log(user: str, ip: str) -> str:
    """查询指定用户在指定主机的堡垒机近24小时登录记录（登录时间/源IP/MFA）。研判告警时必须先核实此项。"""
    return bastion_mod.query_bastion_log(user, ip)


@mcp.tool()
def get_asset_info(ip: str) -> str:
    """查询资产归属信息：主机名、资产负责人、部门、环境、业务用途。处置建议必须落到具体负责人。"""
    return asset_mod.get_asset_info(ip)


@mcp.tool()
def query_threat_intel(indicator: str) -> str:
    """查询 IP/域名/哈希是否命中已知威胁情报（恶意标签、置信度、来源）。"""
    return intel_mod.query_threat_intel(indicator)


@mcp.tool()
def query_alert_history(ip: str, days: int = 7) -> str:
    """查询某资产近 N 天已推送过的告警记录（风险等级与研判结论），判断是否重复风险场景。"""
    return history_mod.query_alert_history(ip, days)


if __name__ == "__main__":
    mcp.run()
