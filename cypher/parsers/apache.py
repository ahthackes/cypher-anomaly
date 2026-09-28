from __future__ import annotations
import re, datetime as dt
from typing import Optional, Dict, Any

# Common/Combined Log Format example:
# 127.0.0.1 - - [10/Oct/2025:13:55:36 +0000] "GET /index.html HTTP/1.1" 200 2326 "-" "Mozilla/5.0"

LOG_RE = re.compile(
    r'^(\S+)\s+(\S+)\s+(\S+)\s+\[(.*?)\]\s+"(\S+)\s(.*?)\s(HTTP/\d\.\d)"\s+(\d{3})\s+(\S+)\s+"(.*?)"\s+"(.*?)"$'
)

def _parse_dt(s: str) -> Optional[dt.datetime]:
    try:
        return dt.datetime.strptime(s.split()[0], "%d/%b/%Y:%H:%M:%S")
    except Exception:
        return None

def parse_apache_line(line: str) -> Optional[Dict[str, Any]]:
    m = LOG_RE.match(line.strip())
    if not m: return None
    ip, ident, user, tstamp, method, path, proto, status, size, ref, ua = m.groups()
    ts = _parse_dt(tstamp)
    size_i = int(size) if size.isdigit() else 0
    return {
        "ts": ts,
        "src_ip": ip,
        "method": method,
        "path": path,
        "status": int(status),
        "size": size_i,
        "ref": ref,
        "ua": ua,
        "raw": line.strip(),
        "log_type": "http"
    }
