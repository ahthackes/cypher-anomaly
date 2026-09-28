from __future__ import annotations
import pandas as pd

def burst_rules(df: pd.DataFrame, thresholds: dict) -> pd.DataFrame:
    # Compute per-minute counts of suspicious events and flag rows that fall in bursty minutes
    d = df.copy()
    d["minute"] = d["ts"].dt.floor("min")
    flags = pd.DataFrame(index=d.index)
    if "is_failed_ssh" in d.columns:
        per_min = d.groupby("minute")["is_failed_ssh"].sum()
        burst_minutes = set(per_min[per_min >= thresholds.get("failed_ssh_per_min", 8)].index)
        flags["rule_failed_ssh_burst"] = d["minute"].isin(burst_minutes).astype(int)
    if "is_invalid_user" in d.columns:
        per_min = d.groupby("minute")["is_invalid_user"].sum()
        burst_minutes = set(per_min[per_min >= thresholds.get("invalid_user_per_min", 5)].index)
        flags["rule_invalid_user_burst"] = d["minute"].isin(burst_minutes).astype(int)
    if "is_sudo_fail" in d.columns:
        per_min = d.groupby("minute")["is_sudo_fail"].sum()
        burst_minutes = set(per_min[per_min >= thresholds.get("sudo_fail_per_min", 3)].index)
        flags["rule_sudo_fail_burst"] = d["minute"].isin(burst_minutes).astype(int)
    if "status" in d.columns:
        d["is_5xx"] = (d["status"] >= 500) & (d["status"] < 600)
        per_min = d.groupby("minute")["is_5xx"].sum()
        burst_minutes = set(per_min[per_min >= thresholds.get("http_5xx_per_min", 20)].index)
        flags["rule_http_5xx_burst"] = d["minute"].isin(burst_minutes).astype(int)
    return pd.concat([d, flags], axis=1)
