import subprocess
import time
import xml.etree.ElementTree as ET
from collections.abc import Callable

from models import SecurityEvent

SYSMON_LOG = "Microsoft-Windows-Sysmon/Operational"


def parse_sysmon_event(xml_text: str) -> SecurityEvent | None:
    root = ET.fromstring(xml_text)
    namespace = {"e": "http://schemas.microsoft.com/win/2004/08/events/event"}
    system = root.find("e:System", namespace)
    event_data = root.find("e:EventData", namespace)
    if event_data is None:
        return None
    data = {item.attrib.get("Name"): item.text or "" for item in event_data if item.attrib.get("Name")}
    computer = ""
    record_id = ""
    if system is not None:
        computer_node = system.find("e:Computer", namespace)
        record_node = system.find("e:EventRecordID", namespace)
        computer = computer_node.text or "" if computer_node is not None else ""
        record_id = record_node.text or "" if record_node is not None else ""
    return SecurityEvent(
        timestamp=data.get("UtcTime", ""), source="sysmon", source_event_id=1,
        record_id=record_id, event_type="process_creation", host=computer,
        user=data.get("User", ""), process_guid=data.get("ProcessGuid", ""),
        process=data.get("Image", ""), process_id=data.get("ProcessId", ""),
        parent_process=data.get("ParentImage", ""), parent_process_id=data.get("ParentProcessId", ""),
        command_line=data.get("CommandLine", ""), parent_command_line=data.get("ParentCommandLine", ""),
        integrity_level=data.get("IntegrityLevel", ""), hashes=data.get("Hashes", ""), raw_event=data,
    )


def get_recent_process_events(max_events: int = 30) -> list[SecurityEvent]:
    max_events = max(1, min(int(max_events), 500))
    ps_command = (
        f'Get-WinEvent -LogName "{SYSMON_LOG}" -MaxEvents {max_events} | '
        'Where-Object { $_.Id -eq 1 } | ForEach-Object { $_.ToXml() }'
    )
    result = subprocess.run(
        ["powershell.exe", "-NoProfile", "-Command", ps_command], capture_output=True,
        text=True, encoding="utf-8", errors="replace", timeout=30, shell=False,
    )
    if result.returncode != 0:
        raise RuntimeError(result.stderr.strip() or "Could not read Sysmon")
    events = []
    for part in result.stdout.split("</Event>"):
        if not part.strip():
            continue
        try:
            event = parse_sysmon_event(part.strip() + "</Event>")
            if event:
                events.append(event)
        except ET.ParseError:
            continue
    return events


def watch_sysmon(on_event: Callable[[SecurityEvent], None], interval_seconds: int = 2, max_seen: int = 5000) -> None:
    print("LLM-IDS - SYSMON LIVE MONITOR")
    print("Watching Sysmon Event ID 1. Press CTRL+C to stop.")
    seen: set[str] = set()
    order: list[str] = []
    try:
        for event in get_recent_process_events():
            if event.deduplication_key:
                seen.add(event.deduplication_key)
                order.append(event.deduplication_key)
        print(f"[READY] Ignoring {len(seen)} existing recent events.")
    except Exception as error:
        print(f"[WARNING] Initial Sysmon read failed: {error}")
    try:
        while True:
            try:
                for event in reversed(get_recent_process_events()):
                    key = event.deduplication_key
                    if not key or key in seen:
                        continue
                    seen.add(key)
                    order.append(key)
                    if len(order) > max_seen:
                        seen.discard(order.pop(0))
                    on_event(event)
            except Exception as error:
                print(f"[HEALTH] Sysmon collection failed: {error}")
            time.sleep(max(1, interval_seconds))
    except KeyboardInterrupt:
        print("\n[STOPPED] Sysmon monitor stopped.")


if __name__ == "__main__":
    watch_sysmon(lambda event: print(event.to_json()))
