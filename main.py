import json

from ids_agent import ids_agent
from models import SecurityEvent
from risk_engine import calculate_risk
from rules import detect
from storage import save_alert
from sysmon_reader import watch_sysmon


def handle_event(event: SecurityEvent) -> None:
    detections = detect(event)
    if not detections:
        return
    risk = calculate_risk(event, detections)
    context = {"event": event.to_dict(), "detections": [item.to_dict() for item in detections], "deterministic_risk": risk}
    assessment = ids_agent(context)
    payload = {**context, "assessment": assessment}
    created = save_alert(event.deduplication_key, event.host, event.user, risk["score"], payload)
    print("\n=== STRUCTURED IDS ALERT ===")
    print(json.dumps(payload, indent=2, ensure_ascii=False))
    print("[STORAGE] Saved." if created else "[STORAGE] Duplicate ignored.")


if __name__ == "__main__":
    watch_sysmon(handle_event)
