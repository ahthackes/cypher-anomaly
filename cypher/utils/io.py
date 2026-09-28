from __future__ import annotations
import pandas as pd
from pathlib import Path

def write_parquet(df: pd.DataFrame, path: str):
    Path(path).parent.mkdir(parents=True, exist_ok=True)
    df.to_parquet(path, index=False)

def read_parquet_many(paths: list[str]) -> pd.DataFrame:
    dfs = [pd.read_parquet(p) for p in paths]
    if not dfs:
        return pd.DataFrame()
    return pd.concat(dfs, ignore_index=True)
