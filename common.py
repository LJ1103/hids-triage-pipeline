"""公共基础设施：路径解析、配置加载、push_log.db 初始化、时间工具。

所有模块统一从这里拿配置与路径，测试时可通过显式传参覆盖 run 目录。
"""
from __future__ import annotations

import json
import sqlite3
import time
from datetime import datetime
from pathlib import Path
from typing import Any, Optional

import yaml

ROOT = Path(__file__).resolve().parent

_CONFIG: Optional[dict] = None


def load_config(path: Optional[str] = None) -> dict:
    """加载 config.yaml（带缓存；测试可用 reload_config 强制重载）。"""
    global _CONFIG
    if _CONFIG is None or path is not None:
        cfg_path = Path(path) if path else ROOT / "config.yaml"
        with open(cfg_path, "r", encoding="utf-8") as f:
            _CONFIG = yaml.safe_load(f)
    return _CONFIG


def reload_config(path: Optional[str] = None) -> dict:
    global _CONFIG
    _CONFIG = None
    return load_config(path)


def get_config() -> dict:
    return load_config()


def run_dir(cfg: Optional[dict] = None) -> Path:
    """运行时产物目录（绝对路径），并确保存在。"""
    cfg = cfg or get_config()
    d = Path(cfg.get("run", {}).get("data_dir", "run"))
    if not d.is_absolute():
        d = ROOT / d
    d.mkdir(parents=True, exist_ok=True)
    return d


def data_dir() -> Path:
    return ROOT / "data"


def db_path(cfg: Optional[dict] = None, run_d: Optional[Path] = None) -> Path:
    """push_log.db 路径。"""
    return (run_d or run_dir(cfg)) / "push_log.db"


def reports_dir(cfg: Optional[dict] = None, run_d: Optional[Path] = None) -> Path:
    """详情页报告目录 run/reports/。"""
    d = (run_d or run_dir(cfg)) / "reports"
    d.mkdir(parents=True, exist_ok=True)
    return d


# ------------------------------------------------------------------
# push_log.db
# ------------------------------------------------------------------
_PUSH_LOG_DDL = """
CREATE TABLE IF NOT EXISTS push_log (
    id         INTEGER PRIMARY KEY AUTOINCREMENT,
    alert_id   TEXT,
    dedup_key  TEXT,
    ip         TEXT,
    cmd_prefix TEXT,
    alert_type TEXT,
    user       TEXT,
    host       TEXT,
    rule       TEXT,
    risk       TEXT,
    verdict    TEXT,
    pushed_at  TEXT,
    pushed_ts  REAL
);
CREATE INDEX IF NOT EXISTS idx_dedup ON push_log(dedup_key, pushed_ts);
CREATE INDEX IF NOT EXISTS idx_ip_ts ON push_log(ip, pushed_ts);
"""


def init_db(path: Optional[Path] = None) -> sqlite3.Connection:
    """打开（必要时建表）push_log.db，返回连接。"""
    path = Path(path) if path else db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(path))
    conn.executescript(_PUSH_LOG_DDL)
    return conn


# ------------------------------------------------------------------
# 时间工具（测试通过注入 now_ts 实现确定性）
# ------------------------------------------------------------------
def now_ts() -> float:
    return time.time()


def fmt_ts(ts: float) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def read_json(path: Path | str, default: Any = None) -> Any:
    p = Path(path)
    if not p.exists():
        return default
    with open(p, "r", encoding="utf-8") as f:
        return json.load(f)


def write_json(path: Path | str, obj: Any) -> None:
    p = Path(path)
    p.parent.mkdir(parents=True, exist_ok=True)
    with open(p, "w", encoding="utf-8") as f:
        json.dump(obj, f, ensure_ascii=False, indent=2)


# ------------------------------------------------------------------
# 文件锁（防 cron 重入：上一轮没跑完时本轮直接退出）
# ------------------------------------------------------------------
import os  # noqa: E402


class FileLock:
    """跨平台排它锁：O_CREAT|O_EXCL 原子创建；超过 stale_s 视为残留锁自动清除。"""

    def __init__(self, path: Path | str, stale_s: float = 600):
        self.path = Path(path)
        self.stale_s = stale_s
        self._fd: Optional[int] = None

    def acquire(self) -> bool:
        self.path.parent.mkdir(parents=True, exist_ok=True)
        for _ in range(2):
            try:
                self._fd = os.open(str(self.path), os.O_CREAT | os.O_EXCL | os.O_WRONLY)
                os.write(self._fd, f"{os.getpid()}|{time.time()}".encode())
                return True
            except FileExistsError:
                try:
                    age = time.time() - self.path.stat().st_mtime
                    if age > self.stale_s:
                        self.path.unlink(missing_ok=True)  # 残留锁，清除后重试
                        continue
                except FileNotFoundError:
                    continue
                return False
        return False

    def release(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None
        try:
            self.path.unlink(missing_ok=True)
        except FileNotFoundError:
            pass

    def __enter__(self) -> "FileLock":
        if not self.acquire():
            raise RuntimeError(f"获取锁失败：{self.path}（上一轮运行未结束？）")
        return self

    def __exit__(self, *exc) -> None:
        self.release()
