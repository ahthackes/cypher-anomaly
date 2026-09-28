from __future__ import annotations
import re, datetime as dt
from typing import Optional, Dict, Any

# Typical auth.log lines:
# Jan  1 12:34:56 host sshd[1234]: Failed password for invalid user admin from 1.2.3.4 port 5555 ssh2
# Jan  1 12:34:59 host sudo:  user : TTY=pts/0 ; PWD=/home/user ; USER=root ; COMMAND=/bin/ls

MONTHS = {m:i for i,m in enumerate(['Jan','Feb','Mar','Apr','May','Jun','Jul','Aug','Sep','Oct','Nov','Dec'], 1)}
BASE_RE = re.compile(r"^(\w{3})\s+(\d{1,2})\s+(\d{2}):(\d{2}):(\d{2})\s+(\S+)\s+(\S+?):\s+(.*)$")

def _ts(mon:str, day:str, hh:str, mm:str, ss:str) -> Optional[dt.datetime]:
    try:
        year = dt.datetime.now().year
        return dt.datetime(year, MONTHS[mon], int(day), int(hh), int(mm), int(ss))
    except Exception:
        return None

def parse_auth_line(line: str) -> Optional[Dict[str, Any]]:
    m = BASE_RE.match(line.strip())
    if not m: return None
    mon, day, hh, mm, ss, host, proc, msg = m.groups()
    ts = _ts(mon, day, hh, mm, ss)
    rec = {"ts": ts, "host": host, "proc": proc, "raw": line.strip(), "log_type": "auth"}
    # Simple tags
    rec["is_failed_ssh"] = int("Failed password" in msg)
    rec["is_invalid_user"] = int("invalid user" in msg)
    rec["is_sudo"] = int(proc.startswith("sudo"))
    rec["is_sudo_fail"] = int("authentication failure" in msg.lower() or "incorrect password" in msg.lower())
    rec["message"] = msg
    return rec
