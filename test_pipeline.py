import base64

from ids_agent import decode_powershell_command
from models import SecurityEvent
from rules import detect


def sample(command_line: str) -> SecurityEvent:
    return SecurityEvent(
        timestamp="2026-01-01T00:00:00Z", source="sysmon", source_event_id=1,
        record_id="1", event_type="process_creation", host="TEST-PC", user="TEST\\user",
        process_guid="guid-1", process=r"C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe",
        process_id="10", parent_process=r"C:\Windows\System32\cmd.exe", parent_process_id="9",
        command_line=command_line, parent_command_line="cmd.exe", integrity_level="Medium", hashes="",
    )


def test_encoded_powershell_rule() -> None:
    encoded = base64.b64encode('Write-Output "LLM IDS test"'.encode("utf-16le")).decode()
    results = detect(sample(f"powershell.exe -EncodedCommand {encoded}"))
    assert results and results[0].rule_id == "LLMID-PS-001"
    assert decode_powershell_command(encoded) == 'Write-Output "LLM IDS test"'


def test_normal_powershell_is_not_forwarded() -> None:
    assert detect(sample('powershell.exe -Command "Get-Date"')) == []
