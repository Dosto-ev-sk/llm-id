# LLM-ID

Local Windows Sysmon IDS prototype with deterministic filtering and Qwen-assisted investigation.

## Architecture at a glance (manager summary)

**One-sentence pitch:** LLM-ID watches which programs start on a Windows computer, uses fast fixed rules to pick out the suspicious ones, and then asks a local AI model to investigate only those and explain what it found. Everything runs on the machine itself.

```text
  WINDOWS COMPUTER
  +------------------------+
  |  Sysmon event log      |   1. SEE      Records every program that starts
  +-----------+------------+
              |
              v
  +------------------------+
  |  Normalize             |   2. CLEAN    One standard format per event
  +-----------+------------+
              |
              v
  +------------------------+
  |  Rules + risk score    |   3. FILTER   Fast, fixed, explainable checks
  +-----+-------------+----+
        |             |
   no match         match
   (ignored)          |
                      v
  +------------------------+
  |  Qwen AI (local, via   |   4. THINK    Investigates with read-only tools:
  |  Ollama) + tools       |               processes, network, events, alerts
  +-----------+------------+
              |
              v
  +------------------------+
  |  JSON alert in SQLite  |   5. RECORD   Verdict, evidence, risk, advice
  +-----------+------------+
              |
              v
   ANALYST: chat in terminal (interactive_agent.py)
            or browser dashboard (web_app.py)
```

### Who does what

| Part | Job | Why it is built this way |
|------|-----|--------------------------|
| Sysmon | Collects process-creation events | Reliable source of what actually ran |
| Rules (`rules.py`) | Flag known suspicious patterns | Fast, predictable, easy to audit |
| Risk engine (`risk_engine.py`) | Gives a repeatable score | Same input always gives the same score |
| Qwen AI (local) | Investigates flagged events and explains them in plain language | Adds judgment and readable explanations where rules alone cannot |
| Investigation tools | Read-only checks of processes, network, events and alert history | The AI can look but cannot change the system |
| SQLite (`alerts.db`) | Stores alert history | Simple, local, easy to review |

### Why the AI is not used for everything

- **Speed:** the AI is slow on a laptop, so it only sees events that rules already flagged.
- **Accuracy:** exact work (decoding, scoring, matching) is done by code, not guessed by the AI.
- **Safety:** the AI only has read-only tools and does not block or delete anything automatically.
- **Privacy:** the model runs locally through Ollama, and the web interface is only reachable at `127.0.0.1`.

### What it covers today (and what it does not)

- Covers: recent Sysmon Event ID 1 (process creation) and the rules currently in `rules.py`.
- Zero matches means the configured rules did not match. It does **not** prove the computer is clean.
- Next steps: more event types and rules, correlation of related events, and measured accuracy testing.

### 30-second talk track

1. "Windows logs every program that starts; we read those logs."
2. "Simple rules instantly filter out the normal activity."
3. "Only the suspicious events go to a local AI, which investigates with read-only tools and explains the risk."
4. "The result is a saved alert with evidence and recommended next steps. A person decides what to do."

## Pipeline

`Sysmon Event ID 1 -> normalized event -> deterministic rules -> Qwen tool loop -> JSON alert -> SQLite`

Run PowerShell as Administrator because reading the Sysmon Operational log normally requires elevation.

## Components

- `main.py`: continuous automatic Sysmon monitoring.
- `interactive_agent.py`: conversational Qwen analyst connected to the IDS engines.
- `detection_engine.py`: scans recent normalized events with deterministic rules.
- `rules.py`: transparent process-detection rules.
- `risk_engine.py`: reproducible risk scoring.
- `investigation_tools.py`: read-only process, network, event, and alert tools.
- `alerts.db`: SQLite alert history.

## Ordered setup and run commands

### 1. Open an Administrator terminal

Open Start, search for **PowerShell**, right-click it, and select **Run as administrator**.

All remaining commands should be executed from that Administrator PowerShell window unless a step says to open another terminal.

### 2. Go to the project directory

```powershell
cd C:\Users\Administrator\Desktop\LLM-ID
```

### 3. Install the Python dependencies

```powershell
.\.venv\Scripts\python.exe -m pip install -r requirements.txt
```

### 4. Install Ollama if it is not installed

```powershell
irm https://ollama.com/install.ps1 | iex
```

Close and reopen the Administrator PowerShell window after installation, then return to the project:

```powershell
cd C:\Users\Administrator\Desktop\LLM-ID
```

### 5. Download the local model

```powershell
ollama pull qwen3:1.7b
```

### 6. Start or verify Ollama

Ollama normally starts automatically on Windows. Verify the installed model:

```powershell
ollama list
```

If the Ollama API is not running, start it and leave that terminal open:

```powershell
ollama serve
```

### 7. Verify access to Sysmon

```powershell
Get-WinEvent `
  -LogName "Microsoft-Windows-Sysmon/Operational" `
  -MaxEvents 5 |
Select-Object TimeCreated, Id, ProviderName
```

If the log cannot be found, check whether Sysmon and its event log are available:

```powershell
Get-Service Sysmon, Sysmon64 -ErrorAction SilentlyContinue
```

```powershell
Get-WinEvent -ListLog "*Sysmon*" |
Select-Object LogName, IsEnabled, RecordCount
```

### 8. Start the conversational IDS

Open another Administrator PowerShell window:

```powershell
cd C:\Users\Administrator\Desktop\LLM-ID
.\.venv\Scripts\python.exe interactive_agent.py
```

Ask naturally, for example:

```text
Can you check my computer for suspicious activity?
```

For a broader investigation:

```text
Please perform a broader security investigation. Scan recent Sysmon events, inspect running processes and active network connections, and check stored alert history. Clearly distinguish confirmed evidence from limitations.
```

Real engine execution is displayed with lines such as:

```text
[ENGINE] run_intrusion_detection_scan(...)
[ENGINE] inspect_running_processes(...)
[ENGINE] inspect_network_connections(...)
[ENGINE] get_alert_history(...)
```

If no `[ENGINE]` line appears, the model discussed or recommended an action but did not execute that engine.

### 9. Start continuous automatic monitoring

Use this instead of the conversational interface when you want continuous monitoring:

```powershell
cd C:\Users\Administrator\Desktop\LLM-ID
.\.venv\Scripts\python.exe main.py
```

Leave the terminal open. New Sysmon process events are normalized and checked automatically. Only events matching a configured rule are sent to Qwen for investigation.

### 10. Generate a harmless encoded-PowerShell test

While `main.py` is running, open another PowerShell window and execute:

```powershell
$text = 'Write-Output "LLM IDS integration test"'
$encoded = [Convert]::ToBase64String(
    [Text.Encoding]::Unicode.GetBytes($text)
)
powershell.exe -EncodedCommand $encoded
```

Expected flow:

```text
Sysmon event -> normalization -> encoded-PowerShell rule -> Qwen decoder tool
-> structured assessment -> SQLite alert
```

Encoding is suspicious evidence, but it does not by itself prove malicious intent. The decoded test command only writes text.

### 11. Test the tool-enabled agent directly

```powershell
cd C:\Users\Administrator\Desktop\LLM-ID
.\.venv\Scripts\python.exe ids_agent.py
```

This executes the built-in sample event and tests the Qwen tool loop without starting continuous monitoring.

### 12. Check stored alerts

```powershell
cd C:\Users\Administrator\Desktop\LLM-ID
.\.venv\Scripts\python.exe -c "import sqlite3; c=sqlite3.connect('alerts.db'); print(c.execute('SELECT id, created_at, host, user, risk_score FROM alerts ORDER BY id DESC LIMIT 10').fetchall())"
```

The database is located at:

```text
C:\Users\Administrator\Desktop\LLM-ID\alerts.db
```

### 13. Stop the programs

Use `Ctrl+C` in the terminal running `main.py`, `interactive_agent.py`, or `ollama serve`.

In the interactive agent, you can also enter:

```text
exit
```

## Result interpretation

A successful scan with zero rule matches means:

```text
The configured deterministic rules did not match the examined events.
```

It does not prove that the computer is free of threats. The current scan primarily covers recent Sysmon Event ID 1 process-creation events and the rules currently implemented in `rules.py`.

An authorization or collection error means the events were not examined. Run the application as Administrator and verify Sysmon access before drawing a security conclusion.

## Web frontend

The browser must not call Ollama at `http://localhost:11434/api/chat` directly. Start the local Python bridge as Administrator:

```powershell
cd C:\Users\Administrator\Desktop\LLM-ID
.\.venv\Scripts\python.exe web_app.py
```

Then open:

```text
http://127.0.0.1:8080
```

The browser sends same-origin requests to `http://127.0.0.1:8080/api/chat`. The Python bridge privately calls Ollama and connects the model to the IDS tools. Keep both Ollama and `web_app.py` running.
