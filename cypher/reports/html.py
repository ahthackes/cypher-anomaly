from __future__ import annotations
import pandas as pd
from jinja2 import Template
from pathlib import Path

HTML_TPL = Template("""
<!DOCTYPE html>
<html>
<head>
<meta charset="utf-8">
<title>Cypher Anomaly Report</title>
<style>
body { font-family: system-ui, -apple-system, Segoe UI, Roboto, sans-serif; margin: 2rem; }
.card { border: 1px solid #ddd; padding: 1rem; border-radius: 0.5rem; margin-bottom: 1rem; }
.badge { padding: 0.2rem 0.5rem; border-radius: 0.25rem; }
.badge-red { background: #ffe5e5; color: #a00; }
.badge-green { background: #e5ffe5; color: #0a0; }
.mono { font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace; white-space: pre-wrap; }
</style>
</head>
<body>
<h1>Cypher Anomaly Report</h1>
<p>Top {{ top_n }} most anomalous lines by IsolationForest score.</p>
{% for r in rows %}
<div class="card">
  <div><strong>{{ r.ts }}</strong> — {{ r.log_type }} — {{ r.host or '' }} {{ r.proc or '' }}</div>
  <div>IP: {{ r.src_ip or '' }} | HTTP: {{ r.status or '' }} {{ r.size or '' }}</div>
  <div>Score: {{ "%.4f"|format(r.anom_score) }} | 
    {% if r.anom_pred == -1 %}<span class="badge badge-red">ANOMALY</span>{% else %}<span class="badge badge-green">OK</span>{% endif %}
  </div>
  <div class="mono">{{ r.raw }}</div>
</div>
{% endfor %}
</body>
</html>
""")

def generate_html(scores: pd.DataFrame, out_path: str, top_n: int = 50):
    Path(out_path).parent.mkdir(parents=True, exist_ok=True)
    d = scores.sort_values("anom_score").head(top_n)
    html = HTML_TPL.render(rows=d.to_dict(orient="records"), top_n=top_n)
    Path(out_path).write_text(html, encoding="utf-8")
