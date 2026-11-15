from dataclasses import asdict, dataclass
import re

from models import SecurityEvent


@dataclass(frozen=True)
class Detection:
    rule_id: str
    title: str
    severity: str
    score: int
    reason: str
    mitre: list[str]

    def to_dict(self) -> dict:
        return asdict(self)


def detect(event: SecurityEvent) -> list[Detection]:
    process = event.process.lower()
    command = event.command_line.lower()
    detections: list[Detection] = []
    if "powershell.exe" in process and re.search(r"(?i)(?:^|\s)-(?:enc|encodedcommand)\s+\S+", event.command_line):
        detections.append(Detection("LLMID-PS-001", "Encoded PowerShell execution", "high", 80, "PowerShell was started with an encoded command.", ["T1059.001", "T1027"]))
    if "mshta.exe" in process and any(x in command for x in ("http://", "https://", "javascript:", "vbscript:")):
        detections.append(Detection("LLMID-LOL-001", "Suspicious mshta execution", "high", 75, "Mshta was given remote or script content.", ["T1218.005"]))
    if "rundll32.exe" in process and any(x in command for x in ("javascript:", "url.dll,fileprotocolhandler")):
        detections.append(Detection("LLMID-LOL-002", "Suspicious rundll32 execution", "high", 75, "Rundll32 used a proxy-execution pattern.", ["T1218.011"]))
    return detections
