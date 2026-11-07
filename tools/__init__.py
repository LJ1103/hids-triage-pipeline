"""研判工具集：堡垒机 / 资产 / 威胁情报 / 历史告警。

纯函数实现，两个消费方：
- mcp_server.py 把它们挂成 MCP 工具给 Hermes 调用（生产路径）
- hermes_client.py 的确定性降级模式直接调用（演示/CI 路径）
"""
from tools import asset, bastion, history, intel

__all__ = ["asset", "bastion", "history", "intel"]
