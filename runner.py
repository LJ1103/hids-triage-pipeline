"""管道总编排（cron 每 3 分钟拉起一次，等价于同事的巡检脚本入口）。

9 步流水线：
  ① fetch     拉告警源 → run/_latest_alerts.json
  ② precheck  12h 去重 + 白名单（no_agent，零 token 门控）
  ③ triage    Hermes Agent 研判（不可用时确定性降级）
  ④ report    完整研判写 run/alert_to_push.md（AI 只写报告，不执行推送）
  ⑤ cooldown  同 用户+主机+规则 低/中危连续 N 次 → 静默（高危不冷却，留痕）
  ⑥ enrich    补该资产近 7 天推送历史
  ⑦ format    详情页数据 + 精简推送正文（失败回退完整版）
  ⑧ push      推送（console/file/企微 webhook）
  ⑨ record    写 push_log.db + 计数

两条关键边界：
  - ②后无存活告警 → 静默退出（零 token、零推送）
  - ⑤后全部静默 → 不推送、不写 push_log（否则冷却恢复后的告警
    会被②的 12h 去重吞掉，造成漏报）

用法：
  python runner.py                    # 有 Hermes 用 Hermes，否则自动降级
  python runner.py --fallback         # 强制确定性降级（离线演示 / CI）
  python runner.py --source x.json    # 覆盖告警源文件
cron 示例（Linux）：*/3 * * * * cd /opt/hids-triage && timeout 300 python runner.py
"""
from __future__ import annotations

import argparse
import sys
import time
from pathlib import Path
from typing import Optional

sys.path.insert(0, str(Path(__file__).resolve().parent))

import common
import hermes_client
from pipeline import cooldown as cooldown_mod
from pipeline import enrich_history, fetch, format_push, precheck, push, record


class Budget:
    """总时间预算：超时前保证已完成部分的推送落地（同事踩过 120s 被杀丢告警的坑）。"""

    def __init__(self, total_s: float):
        self._t0 = time.monotonic()
        self.total = float(total_s)

    def left(self) -> float:
        return self.total - (time.monotonic() - self._t0)


def _log(msg: str) -> None:
    print(f"[{common.fmt_ts(common.now_ts())}] {msg}", flush=True)


def run_pipeline(cfg: dict, run_d: Optional[Path] = None,
                 force_fallback: bool = False, source: Optional[Path] = None,
                 timeout_s: float = 300.0, lock: bool = True) -> dict:
    """执行一轮完整管道，返回摘要（测试直接调用此函数）。

    stage: "silent"（无存活告警）/ "all_silenced"（全被冷却）/ "pushed"
    """
    run_d = run_d or common.run_dir(cfg)
    db = run_d / "push_log.db"
    state_path = run_d / "cooldown_state.json"
    summary = {"stage": "silent", "fetched": 0, "deduped": 0, "whitelisted": 0,
               "analyzed": 0, "pushed": 0, "silenced": 0, "engine": "",
               "push_body": "", "links": [], "error": ""}

    if lock:
        try:
            with common.FileLock(run_d / ".lock"):
                return _run_locked(cfg, run_d, db, state_path, summary,
                                   force_fallback, source, timeout_s)
        except RuntimeError as e:
            summary["error"] = str(e)
            _log(f"SKIP {e}")
            return summary
    return _run_locked(cfg, run_d, db, state_path, summary,
                       force_fallback, source, timeout_s)


def _run_locked(cfg, run_d, db, state_path, summary,
                force_fallback, source, timeout_s) -> dict:
    budget = Budget(timeout_s)

    # ① 拉取告警
    alerts = fetch.fetch_alerts(cfg, source_file=source, run_d=run_d)
    summary["fetched"] = len(alerts)
    if not alerts:
        _log("SILENT_EXIT 告警源为空")
        return summary

    # ② 一级门控（纯脚本，零 token）
    pre = precheck.run_precheck(alerts, cfg, db=db)
    summary["deduped"] = pre["deduped"]
    summary["whitelisted"] = pre["whitelisted"]
    survivors = pre["survivors"]
    _log(f"HAS_ALERTS {len(survivors)} (fetched={len(alerts)} "
         f"deduped={pre['deduped']} whitelisted={pre['whitelisted']})")
    if not survivors:
        _log("SILENT_EXIT 全部被一级门控拦截，不进入 AI（零 token）")
        return summary

    # ③④ 逐条 AI 研判（预算不足时剩余告警留待下一轮）
    results, engine = [], ""
    for a in survivors:
        if budget.left() < 15:
            _log(f"BUDGET_STOP 剩余预算 {budget.left():.0f}s < 15s，"
                 f"剩余 {len(survivors) - len(results)} 条留待下一轮")
            break
        r = hermes_client.triage_alert(a, cfg, run_d=run_d, force_fallback=force_fallback)
        engine = r["engine"]
        if r["error"]:
            _log(f"TRIAGE_WARN {a.get('alert_id')}: {r['error']}")
        results.append(r)
    summary["analyzed"] = len(results)
    summary["engine"] = engine
    if engine == "fallback" and not force_fallback:
        _log("ENGINE=fallback（未检测到 Hermes，确定性降级；配置见 README）")
    if not results:
        summary["error"] = "本轮无告警完成研判（时间预算耗尽）"
        return summary

    # ④ 完整研判报告落盘（含被静默的，留档不推送）
    report_path = format_push.write_full_report(results, run_d)
    _log(f"REPORT_WRITTEN {report_path.name} ({len(results)} 条)")

    # ⑤ 冷却过滤
    kept, silenced = cooldown_mod.filter_silenced(results, state_path, cfg, run_d=run_d)
    summary["silenced"] = len(silenced)
    if not kept:
        _log("ALL_SILENCED 本轮不推送、不写 push_log（防止冷却恢复后被 12h 去重吞掉）")
        summary["stage"] = "all_silenced"
        return summary

    # ⑥ 补历史告警情况
    enrich_history.enrich(kept, run_d=run_d)

    # ⑦ 详情页数据 + 精简推送正文
    payload = format_push.build_push(kept, cfg, run_d=run_d)
    summary["push_body"] = payload["body"]
    summary["links"] = payload["links"]

    # ⑧ 推送
    ok = push.send(payload["body"], cfg, run_d=run_d)
    _log(f"PUSH {'ok' if ok else 'FAILED'} channel={cfg.get('push', {}).get('channel')}")

    # ⑨ 写 push_log + 计数（只记真实推送的）
    record.record(kept, db=db, counters_path=run_d / "counters.json",
                  stats={"fetched": summary["fetched"], "deduped": summary["deduped"],
                         "whitelisted": summary["whitelisted"], "analyzed": summary["analyzed"],
                         "silenced": summary["silenced"]})
    cooldown_mod.update_after_push(kept, state_path, cfg)

    summary["stage"] = "pushed"
    summary["pushed"] = len(kept)
    return summary


def main() -> int:
    ap = argparse.ArgumentParser(description="HIDS 告警智能分诊流水线")
    ap.add_argument("--config", default=None, help="config.yaml 路径（默认项目根目录）")
    ap.add_argument("--fallback", action="store_true",
                    help="强制确定性降级研判（离线演示 / CI，不依赖 Hermes 与 API Key）")
    ap.add_argument("--source", default=None, help="覆盖告警源文件路径")
    ap.add_argument("--timeout", type=float, default=300.0,
                    help="总时间预算秒数（默认 300，cron 侧请配同量级 timeout）")
    args = ap.parse_args()

    cfg = common.load_config(args.config)
    if args.fallback:
        cfg.setdefault("push", {}).setdefault("channel", "console")

    summary = run_pipeline(cfg, force_fallback=args.fallback,
                           source=Path(args.source) if args.source else None,
                           timeout_s=args.timeout)
    _log(f"DONE stage={summary['stage']} fetched={summary['fetched']} "
         f"analyzed={summary['analyzed']} pushed={summary['pushed']} "
         f"silenced={summary['silenced']} engine={summary['engine'] or '-'}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
