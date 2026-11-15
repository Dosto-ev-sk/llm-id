from models import SecurityEvent
from rules import Detection


def calculate_risk(event: SecurityEvent, detections: list[Detection]) -> dict:
    if not detections:
        return {"score": 0, "severity": "low", "factors": []}
    score = max(item.score for item in detections)
    factors = [f"base:{max(detections, key=lambda item: item.score).rule_id}={score}"]
    unique_rules = len({item.rule_id for item in detections})
    if unique_rules > 1:
        bonus = min(15, (unique_rules - 1) * 5)
        score += bonus
        factors.append(f"multiple_rules=+{bonus}")
    if event.integrity_level.lower() in {"high", "system"}:
        score += 10
        factors.append("elevated_integrity=+10")
    score = min(100, score)
    severity = "critical" if score >= 90 else "high" if score >= 70 else "medium" if score >= 40 else "low"
    return {"score": score, "severity": severity, "factors": factors}
