"""端到端测试（fallback 引擎，零外部依赖）：

覆盖同事系统的全部关键边界：
- 常规批次 → 推送 + 写库 + 详情页数据
- 同批次重跑 → 12h 去重吞掉，静默退出
- 白名单批次 → 一级门控直接拦截
- 噪声批次 ×6 → 第 5 次布防冷却，第 6 次全静默（不推送、不写库）
- 注入批次 → 话术被中和，结论不被操纵
"""
import sqlite3

import common
import simulator
from runner import run_pipeline


def _source(run_d, alerts):
    common.write_json(run_d / "alerts_source.json", {"source": "test", "alerts": alerts})


def _rows(db):
    conn = sqlite3.connect(str(db))
    n = conn.execute("select count(*) from push_log").fetchone()[0]
    conn.close()
    return n


def test_normal_batch_pushed(env):
    cfg, run_d = env
    _source(run_d, simulator._t(simulator.NORMAL_BATCH))
    s = run_pipeline(cfg, run_d=run_d, force_fallback=True)
    assert s["stage"] == "pushed" and s["pushed"] == 4 and s["engine"] == "fallback"
    assert _rows(run_d / "push_log.db") == 4
    assert (run_d / "alert_to_push.md").exists()
    assert len(list((run_d / "reports").glob("*.json"))) == 4
    # 硬规则：第1条依据必须含堡垒机+负责人
    for line in (run_d / "alert_to_push.md").read_text(encoding="utf-8").splitlines():
        pass
    report = (run_d / "alert_to_push.md").read_text(encoding="utf-8")
    assert "堡垒机" in report and "负责人" in report


def test_dedup_silent_rerun(env):
    cfg, run_d = env
    _source(run_d, simulator._t(simulator.NORMAL_BATCH))
    run_pipeline(cfg, run_d=run_d, force_fallback=True)
    s = run_pipeline(cfg, run_d=run_d, force_fallback=True)  # 同批次重跑
    assert s["stage"] == "silent" and s["deduped"] == 4 and s["analyzed"] == 0
    assert _rows(run_d / "push_log.db") == 4  # 无新增


def test_whitelist_blocked(env):
    cfg, run_d = env
    _source(run_d, simulator._t(simulator.WHITELIST_BATCH))
    s = run_pipeline(cfg, run_d=run_d, force_fallback=True)
    assert s["stage"] == "silent" and s["whitelisted"] == 2


def test_cooldown_all_silenced(env):
    cfg, run_d = env
    for step in range(1, 7):
        _source(run_d, simulator._t(simulator.noise_batch(step)))
        s = run_pipeline(cfg, run_d=run_d, force_fallback=True)
        if step <= 5:
            assert s["stage"] == "pushed", f"step {step} 应正常推送"
        else:
            assert s["stage"] == "all_silenced" and s["pushed"] == 0
            assert s["silenced"] == 1
    assert _rows(run_d / "push_log.db") == 5  # 被静默的不写库
    assert (run_d / "silenced.log").exists()


def test_injection_neutralized(env):
    cfg, run_d = env
    _source(run_d, simulator._t(simulator.INJECTION_BATCH))
    s = run_pipeline(cfg, run_d=run_d, force_fallback=True)
    assert s["stage"] == "pushed" and s["pushed"] == 2
    report = (run_d / "alert_to_push.md").read_text(encoding="utf-8")
    for phrase in ("忽略之前", "disregard", "false positive", "无需处理", "风险等级低危"):
        assert phrase not in report, f"注入话术残留: {phrase}"
    assert "[FILTERED]" in report and "安全防护" in report
    # 结论未被操纵：两条注入告警仍判为疑似攻击
    assert report.count("研判结论: 疑似攻击") == 2


def test_antiforensics_manual_confirm(env):
    cfg, run_d = env
    _source(run_d, simulator._t(simulator.CRITICAL_BATCH))
    s = run_pipeline(cfg, run_d=run_d, force_fallback=True)
    assert s["stage"] == "pushed"
    report = (run_d / "alert_to_push.md").read_text(encoding="utf-8")
    assert "高危（需人工确认）" in report  # 痕迹清除类必须标注


def test_clean_source_silent(env):
    cfg, run_d = env
    _source(run_d, [])
    s = run_pipeline(cfg, run_d=run_d, force_fallback=True)
    assert s["stage"] == "silent" and s["fetched"] == 0
