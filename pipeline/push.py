"""⑧ 推送通道：console（默认演示）/ file / webhook（企微机器人格式）。

真实环境走企微 webhook；开源演示默认 console，零外部依赖。
通道与 webhook 地址支持环境变量覆盖：PUSH_CHANNEL / WECOM_WEBHOOK_URL
——密钥只进环境变量不进 git，开源仓库零泄露风险。
"""
from __future__ import annotations

import os
from datetime import datetime
from pathlib import Path

import common


def send(body: str, cfg: dict, run_d: Path | None = None) -> bool:
    """推送正文。返回是否成功（失败由 runner 记录，不影响⑨写库——留痕优先）。"""
    pc = cfg.get("push", {})
    channel = os.getenv("PUSH_CHANNEL") or pc.get("channel", "console")

    if channel == "console":
        print(body)
        return True

    if channel == "file":
        try:
            path = Path(pc.get("file_path", "push_out.txt"))
            if not path.is_absolute():
                path = (run_d or common.run_dir(cfg)) / path.name
            path.parent.mkdir(parents=True, exist_ok=True)
            with open(path, "a", encoding="utf-8") as f:
                f.write(f"\n===== {datetime.now().strftime('%Y-%m-%d %H:%M:%S')} =====\n")
                f.write(body + "\n")
            return True
        except Exception as e:
            print(f"[push] file 通道失败: {e}")
            return False

    if channel == "webhook":
        url = os.getenv("WECOM_WEBHOOK_URL") or pc.get("webhook_url", "")
        if not url:
            print("[push] webhook 通道未配置 webhook_url，降级 console 输出")
            print(body)
            return False
        try:
            import requests
            # 企微机器人 markdown 消息格式
            resp = requests.post(url, json={"msgtype": "markdown",
                                            "markdown": {"content": body}}, timeout=10)
            ok = resp.status_code == 200 and resp.json().get("errcode") == 0
            if not ok:
                print(f"[push] 企微返回异常: {resp.status_code} {resp.text[:200]}")
            return ok
        except Exception as e:
            print(f"[push] webhook 通道失败: {e}")
            return False

    print(f"[push] 未知通道 {channel}，降级 console 输出")
    print(body)
    return False
