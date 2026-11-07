"""⑦ 详情页服务：http://host:8080/alert/{id}（24h 有效）。

走 http 而非 https：企微内置浏览器不信任自签证书（同事踩过的坑）。
数据来自 run/reports/{alert_id}.json（format_push 落盘）。

启动：python -m server.alert_server
"""
from __future__ import annotations

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import common
from fastapi import FastAPI
from fastapi.responses import HTMLResponse

app = FastAPI(title="HIDS 告警详情页")

_PAGE = """<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title}</title>
<style>
 body{{font-family:-apple-system,"Segoe UI","Microsoft YaHei",sans-serif;background:#f5f6f7;margin:0;padding:24px;color:#222}}
 .card{{max-width:760px;margin:0 auto;background:#fff;border-radius:10px;padding:24px 28px;box-shadow:0 1px 4px rgba(0,0,0,.08)}}
 h1{{font-size:18px;margin:0 0 4px}}
 .meta{{color:#888;font-size:13px;margin-bottom:16px}}
 pre{{background:#0f172a;color:#e2e8f0;padding:18px;border-radius:8px;font-size:13px;line-height:1.7;white-space:pre-wrap;word-break:break-all}}
 .badge{{display:inline-block;padding:2px 10px;border-radius:12px;font-size:12px;color:#fff;margin-left:8px;vertical-align:2px}}
 .low{{background:#16a34a}}.mid{{background:#d97706}}.high{{background:#dc2626}}
 .expired{{text-align:center;padding:60px 0;color:#999}}
</style></head><body><div class="card">{content}</div></body></html>"""


def _risk_class(risk: str) -> str:
    return {"低危": "low", "中危": "mid"}.get(risk, "high")


@app.get("/healthz")
def healthz():
    return {"ok": True}


@app.get("/alert/{alert_id}", response_class=HTMLResponse)
def alert_detail(alert_id: str):
    # 防路径穿越：只取文件名部分
    rid = Path(alert_id).name
    cfg = common.get_config()
    detail = common.read_json(common.reports_dir(cfg) / f"{rid}.json", default=None)
    if detail is None:
        return HTMLResponse(_PAGE.format(
            title="未找到", content='<div class="expired">告警不存在或已被清理</div>'), status_code=404)

    ttl = float(cfg.get("server", {}).get("detail_ttl_hours", 24)) * 3600
    if common.now_ts() - float(detail.get("created_ts", 0)) > ttl:
        return HTMLResponse(_PAGE.format(
            title="已过期", content='<div class="expired">该详情页已超过有效期（24h），请从告警平台重新获取</div>'),
            status_code=410)

    p = detail.get("parsed", {})
    risk = p.get("risk_level", "中危")
    engine = detail.get("engine", "")
    badge = f'<span class="badge {_risk_class(risk)}">{risk}' \
            + ('（需人工确认）' if p.get("needs_manual_confirm") else '') + '</span>'
    meta = (f"告警ID {detail.get('alert_id')} · 生成于 {detail.get('created_at')}"
            + (f" · 研判引擎 {engine}" if engine else ""))
    content = (f'<h1>{p.get("规则", "HIDS 告警")}{badge}</h1>'
               f'<div class="meta">{meta}</div>'
               f'<pre>{detail.get("report_text", "")}</pre>')
    return HTMLResponse(_PAGE.format(title=f"{p.get('规则', '告警详情')} - HIDS 研判", content=content))


if __name__ == "__main__":
    import uvicorn
    sc = common.get_config().get("server", {})
    uvicorn.run(app, host=sc.get("host", "127.0.0.1"), port=int(sc.get("port", 8080)))
