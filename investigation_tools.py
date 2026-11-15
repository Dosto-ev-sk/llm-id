import json
import subprocess
from typing import Any

from storage import recent_alerts
from sysmon_reader import get_recent_process_events


def recent_host_events(host: str, limit: int = 10) -> list[dict[str, Any]]:
    limit = max(1, min(int(limit), 25))
    events = get_recent_process_events(max_events=200)
    return [event.to_dict() for event in events if event.host.lower() == host.lower()][:limit]


def alert_history(host: str = "", limit: int = 10) -> list[dict[str, Any]]:
    return recent_alerts(limit=limit, host=host or None)


def running_processes(process_name: str = "") -> dict[str, Any]:
    result = subprocess.run(["tasklist", "/FO", "CSV", "/NH"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, shell=False)
    if result.returncode != 0:
        return {"status": "error", "error": result.stderr.strip() or result.stdout.strip()}
    rows = [line for line in result.stdout.splitlines() if line.strip()]
    if process_name:
        rows = [line for line in rows if process_name.lower() in line.lower()]
    return {"status": "success", "count": len(rows), "processes": rows[:50]}


def network_connections(pid: str = "") -> dict[str, Any]:
    result = subprocess.run(["netstat", "-ano"], capture_output=True, text=True, encoding="utf-8", errors="replace", timeout=15, shell=False)
    if result.returncode != 0:
        return {"status": "error", "error": result.stderr.strip() or result.stdout.strip()}
    rows = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if pid:
        rows = [line for line in rows if line.split() and line.split()[-1] == str(pid)]
    return {"status": "success", "count": len(rows), "connections": rows[:100]}


def as_tool_result(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False)
