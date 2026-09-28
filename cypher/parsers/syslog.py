from __future__ import annotations
import re, datetime as dt
from typing import Optional, Dict, Any

MONTHS = {m:i for i,m in enumerate(['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'], 1)}
BASE_RE = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(\S+?):\s+(.*)$")

def _ts(mon:str, day:str, hh:str, mm:str, ss:str) -> Optional[dt.datetime]:
    try:
        year = dt.datetime.now().year
        return dt.datetime(year, MONTHS[mon], int(day), int(hh), int(mm), int(ss))
    except Exception:
        return None

def parse_syslog_line(line: str) -> Optional[Dict[str, Any]]:
    m = BASE_RE.match(line.strip())
    if not m: return None
    mon, day, hh, mm, ss, host, proc, msg = m.groups()
    ts = _ts(mon, day, hh, mm, ss)
    return {"ts": ts, "host": host, "proc": proc, "message": msg, "raw": line.strip(), "log_type": "syslog"}
