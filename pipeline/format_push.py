"""④⑦ 报告落盘与推送正文组装。

④ AI 只写报告、不执行推送：完整研判写 run/alert_to_push.md（留档）。
⑦ 生成详情页数据 + 精简推送正文；精简版生成失败时回退完整版，
   保证"宁可推长文，不可不推送"。
"""
from __future__ import annotations

from pathlib import Path
from typing import Optional

import common


def write_full_report(results: list[dict], run_d: Path) -> Path:
    """④ 把本轮全部研判结果（含被冷却静默的）写入 run/alert_to_push.md。"""
    path = run_d / "alert_to_push.md"
    lines = [f"# HIDS 告警研判报告（{common.fmt_ts(common.now_ts())}）", ""]
    for i, r in enumerate(results, 1):
        p = r["parsed"]
        lines.append(f"## {i}. [{p.get('risk_level', '?')}] {p.get('规则', r['alert'].get('rule', ''))}"
                     f" @ {p.get('host', r['alert'].get('host', ''))}")
        lines.append("")
        lines.append("```")
        lines.append(r["report_text"].strip())
        lines.append("```")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")
    return path


def _condense(r: dict, link: str) -> str:
    """⑦ 单条精简正文（企微群里一眼能看完的量级）。"""
    p = r["parsed"]
    risk = p.get("risk_level", "中危")
    if p.get("needs_manual_confirm"):
        risk += "（需人工确认）"
    verdict = p.get("verdict", "需人工确认")
    summary = p.get("verdict_summary", "")
    head = f"【{risk}】{verdict}" + (f" - {summary}" if summary else "")
    body = (f"主机 {p.get('host', '?')}({p.get('ip', '?')}) "
            f"用户 {p.get('用户', '?')} 规则 {p.get('规则', '?')}")
    # 触发命令单行截断展示：值班第一眼要知道"到底执行了什么"
    cmd = " ".join(str(r["alert"].get("command", "")).split())
    if cmd:
        cmd = cmd[:80] + ("…" if len(cmd) > 80 else "")
    out = [head, body]
    if cmd:
        out.append(f"命令: {cmd}")
    hist = p.get("history_note", "")
    advice = str(p.get("处置建议", ""))[:80]
    if hist:
        out.append(f"历史: {hist}")
    if advice:
        out.append(f"处置: {advice}")
    out.append(f"详情(24h内有效): {link}")
    return "\n".join(out)


def build_push(results: list[dict], cfg: dict, run_d: Optional[Path] = None) -> dict:
    """⑦ 组装推送负载：详情页数据落盘 + 精简正文（失败回退完整版）。

    返回 {"body": str, "links": [str], "detail_files": [Path], "fallback": bool}
    """
    run_d = run_d or common.run_dir(cfg)
    reports_d = run_d / "reports"
    reports_d.mkdir(parents=True, exist_ok=True)
    sc = cfg.get("server", {})
    base = sc.get("public_base", "http://127.0.0.1:8080").rstrip("/")

    links, files, blocks = [], [], []
    try:
        now_ts = common.now_ts()
        for r in results:
            rid = r["alert"].get("alert_id") or f"AL-{int(now_ts)}"
            detail = {
                "alert_id": rid,
                "created_ts": now_ts,
                "created_at": common.fmt_ts(now_ts),
                "alert": r["alert"],
                "report_text": r["report_text"],
                "parsed": r["parsed"],
                "engine": r.get("engine", ""),
            }
            f = reports_d / f"{rid}.json"
            common.write_json(f, detail)
            files.append(f)
            link = f"{base}/alert/{rid}"
            links.append(link)
            blocks.append(_condense(r, link))
        header = f"🔔 HIDS 告警研判（{len(results)} 条待处置）"
        body = header + "\n\n" + "\n\n".join(blocks)
        fallback_used = False
    except Exception:
        # 精简版生成失败 → 回退完整报告，绝不因格式化问题丢推送
        body = "\n\n---\n\n".join(r["report_text"] for r in results)
        fallback_used = True

    return {"body": body, "links": links, "detail_files": files, "fallback": fallback_used}
