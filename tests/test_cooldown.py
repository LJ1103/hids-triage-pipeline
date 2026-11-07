"""⑤ 冷却单测：阈值布防 / 静默过滤 / 高危豁免 / 2h 窗口重置。"""
from pipeline import cooldown

CFG = {"cooldown": {"threshold": 5, "silence_minutes": 60, "reset_window_hours": 2}}


def mk(user="u1", host="h1", rule="r1", risk="低危"):
    return {"alert": {"user": user, "host": host, "rule": rule},
            "parsed": {"用户": user, "host": host, "规则": rule, "risk_level": risk}}


def test_armed_after_threshold(tmp_path):
    state = tmp_path / "cooldown_state.json"
    t0 = 1_000_000_000.0
    for i in range(5):
        cooldown.update_after_push([mk()], state, CFG, now_ts=t0 + i * 60)
    st = __import__("common").read_json(state)["u1|h1|r1"]
    assert st["silenced_until"] >= t0 + 4 * 60 + 3600  # 第 5 次推送(t0+240s)后布防 1h


def test_silenced_filtered_with_trace(tmp_path):
    state = tmp_path / "cooldown_state.json"
    t0 = 1_000_000_000.0
    cooldown.update_after_push([mk()], state, CFG, now_ts=t0)
    __import__("common").write_json(state, {"u1|h1|r1": {"count": 0, "window_start": t0,
                                                         "silenced_until": t0 + 3600}})
    kept, silenced = cooldown.filter_silenced([mk()], state, CFG, run_d=tmp_path, now_ts=t0 + 60)
    assert not kept and len(silenced) == 1
    assert (tmp_path / "silenced.log").exists()  # 静默留痕


def test_high_risk_exempt(tmp_path):
    state = tmp_path / "cooldown_state.json"
    t0 = 1_000_000_000.0
    __import__("common").write_json(state, {"u1|h1|r1": {"count": 9, "window_start": t0,
                                                         "silenced_until": t0 + 3600}})
    # 静默期内的高危告警照常放行
    kept, silenced = cooldown.filter_silenced([mk(risk="高危")], state, CFG,
                                              run_d=tmp_path, now_ts=t0 + 60)
    assert len(kept) == 1 and not silenced
    # 高危不计入冷却计数
    before = __import__("common").read_json(state)["u1|h1|r1"]["count"]
    cooldown.update_after_push([mk(risk="高危")], state, CFG, now_ts=t0 + 61)
    after = __import__("common").read_json(state)["u1|h1|r1"]["count"]
    assert before == after


def test_window_reset(tmp_path):
    state = tmp_path / "cooldown_state.json"
    t0 = 1_000_000_000.0
    # 4 次推送后中断超过 2h → 计数应重置，不累计误触发
    for i in range(4):
        cooldown.update_after_push([mk()], state, CFG, now_ts=t0 + i * 60)
    cooldown.update_after_push([mk()], state, CFG, now_ts=t0 + 3 * 3600)
    st = __import__("common").read_json(state)["u1|h1|r1"]
    assert st["count"] == 1 and "silenced_until" not in st


def test_not_armed_below_threshold(tmp_path):
    state = tmp_path / "cooldown_state.json"
    t0 = 1_000_000_000.0
    for i in range(4):
        cooldown.update_after_push([mk()], state, CFG, now_ts=t0 + i * 60)
    st = __import__("common").read_json(state)["u1|h1|r1"]
    assert st["count"] == 4 and "silenced_until" not in st
