from typing import Any

from risk_engine import calculate_risk
from rules import detect
from sysmon_reader import get_recent_process_events


def run_recent_scan(max_events: int = 100) -> dict[str, Any]:
    max_events = max(1, min(int(max_events), 500))
    events = get_recent_process_events(max_events=max_events)
    findings = []
    for event in events:
        detections = detect(event)
        if not detections:
            continue
        findings.append({
            "event": event.to_dict(),
            "detections": [item.to_dict() for item in detections],
            "deterministic_risk": calculate_risk(event, detections),
        })
    return {
        "status": "success",
        "events_examined": len(events),
        "findings_count": len(findings),
        "findings": findings[:25],
        "limitations": [
            "This scan currently covers recent Sysmon Event ID 1 process creation events only."
        ],
    }
