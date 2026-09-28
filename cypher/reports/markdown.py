from __future__ import annotations
import pandas as pd
from pathlib import Path

def generate_markdown(scores: pd.DataFrame, out_path: str, top_n: int = 50):
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    d = scores.sort_values("anom_score").head(top_n)
    lines = ["# Cypher Anomaly Report", "", f"Top {top_n} most anomalous lines by IsolationForest score", ""]
    cols = ["ts","log_type","host","proc","src_ip","status","size","anom_score","anom_pred","raw"]
    for _, row in d.iterrows():
        parts = [f"**ts**: {row.get('ts')}", f"**type**: {row.get('log_type')}",
                 f"**host**: {row.get('host','')}", f"**proc**: {row.get('proc','')}",
                 f"**src_ip**: {row.get('src_ip','')}", f"**status**: {row.get('status','')}",
                 f"**size**: {row.get('size','')}", f"**score**: {row.get('anom_score'):.4f}",
                 f"**pred**: {'ANOM' if row.get('anom_pred')==-1 else 'OK'}",
                 f"```
{row.get('raw')}
```"]
        lines.append("- " + " | ".join(parts))
    Path(out_path).write_text("\n".join(lines), encoding="utf-8")
