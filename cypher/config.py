from __future__ import annotations
import os, pathlib
from typing import Any, Dict

try:
    import tomllib  # py311+
except Exception:
    import tomli as tomllib  # py310-

DEFAULTS: Dict[str, Any] = {
    "paths": {
        "models_dir": "models",
        "reports_dir": "reports",
    },
    "train": {
        "contamination": 0.02,
        "n_estimators": 200,
        "max_samples": "auto",
        "random_state": 42,
    },
    "score": {
        "score_threshold": -0.2
    },
    "features": {
        "enable_time": True,
        "enable_srcip": True,
        "enable_geo": False,
        "enable_http": True,
        "enable_auth": True,
        "enable_counts": True,
    },
    "rules": {
        "failed_ssh_per_min": 8,
        "invalid_user_per_min": 5,
        "sudo_fail_per_min": 3,
        "http_5xx_per_min": 20,
    }
}

def load_config(path: str | None = None) -> Dict[str, Any]:
    cfg = DEFAULTS.copy()
    p = pathlib.Path(path or "cypher.toml")
    if p.exists():
        with p.open("rb") as f:
            user_cfg = tomllib.load(f)
        for k, v in user_cfg.items():
            if isinstance(v, dict) and k in cfg:
                cfg[k].update(v)
            else:
                cfg[k] = v
    return cfg
