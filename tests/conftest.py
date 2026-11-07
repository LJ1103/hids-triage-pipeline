"""pytest 公共夹具：项目根加入 sys.path，提供隔离的临时运行目录。"""
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import pytest

import common


@pytest.fixture
def env(tmp_path):
    """返回 (cfg, run_d)：配置指向临时目录，推送走 console，互不污染。"""
    cfg = common.reload_config()
    cfg["run"]["data_dir"] = str(tmp_path)
    cfg["fetch"]["source_file"] = str(tmp_path / "alerts_source.json")
    cfg["push"]["channel"] = "console"
    return cfg, tmp_path
