from __future__ import annotations
import re, ipaddress, math
from typing import Dict, Any, Optional

IP_RE = re.compile(r"(?:\d{1,3}\.){3}\d{1,3}")

def extract_ip(s: str) -> Optional[str]:
    m = IP_RE.search(s or "")
    if not m: return None
    ip = m.group(0)
    try:
        ipaddress.ip_address(ip)
        return ip
    except Exception:
        return None

def ip_octets(ip: str | None) -> Dict[str, int]:
    if not ip: 
        return {"ip_o1":0,"ip_o2":0,"ip_o3":0,"ip_o4":0, "is_private":0}
    try:
        parts = [int(x) for x in ip.split(".")]
        is_priv = 1 if ipaddress.ip_address(ip).is_private else 0
        return {"ip_o1":parts[0], "ip_o2":parts[1], "ip_o3":parts[2], "ip_o4":parts[3], "is_private": is_priv}
    except Exception:
        return {"ip_o1":0,"ip_o2":0,"ip_o3":0,"ip_o4":0, "is_private":0}

def parse_timestamp_to_fields(ts) -> Dict[str,int]:
    # Expect pandas datetime or None
    if ts is None: 
        return {"hour":0,"weekday":0,"month":0}
    return {"hour": int(ts.hour), "weekday": int(ts.weekday()), "month": int(ts.month)}
