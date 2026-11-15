from dataclasses import asdict, dataclass, field
import json
from typing import Any


@dataclass
class SecurityEvent:
    timestamp: str
    source: str
    source_event_id: int
    record_id: str
    event_type: str
    host: str
    user: str
    process_guid: str
    process: str
    process_id: str
    parent_process: str
    parent_process_id: str
    command_line: str
    parent_command_line: str
    integrity_level: str
    hashes: str
    raw_event: dict[str, Any] = field(default_factory=dict)

    @property
    def deduplication_key(self) -> str:
        return self.process_guid or f"{self.host}|{self.record_id}|{self.timestamp}"

    def to_dict(self, include_raw: bool = False) -> dict[str, Any]:
        value = asdict(self)
        if not include_raw:
            value.pop("raw_event", None)
        return value

    def to_json(self) -> str:
        return json.dumps(self.to_dict(), ensure_ascii=False)
