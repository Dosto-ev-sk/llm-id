import json
import ctypes
import os
import subprocess
import sys
import threading
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import urlparse

import requests

from interactive_agent import MODEL, ask_agent, new_history


HOST = "127.0.0.1"
PORT = 8765
MAX_BODY_SIZE = 64 * 1024


def is_administrator() -> bool:
    if os.name != "nt":
        return os.geteuid() == 0
    try:
        return bool(ctypes.windll.shell32.IsUserAnAdmin())
    except (AttributeError, OSError):
        return False


IS_ADMIN = is_administrator()

_sessions: dict[str, list[dict[str, Any]]] = {}
_session_locks: dict[str, threading.Lock] = {}
_sessions_lock = threading.Lock()


HTML = r"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width,initial-scale=1">
  <title>LLM-ID Analyst</title>
  <style>
    :root { color-scheme: dark; --bg:#07110f; --panel:#0d1c18; --line:#25423a; --text:#e9f5f0; --muted:#93aaa2; --accent:#39d98a; --danger:#ff7a7a; }
    * { box-sizing:border-box; }
    body { margin:0; min-height:100vh; background:radial-gradient(circle at top,#123127 0,var(--bg) 48%); color:var(--text); font:15px/1.5 Inter,Segoe UI,sans-serif; }
    main { width:min(920px,100%); height:100vh; margin:auto; display:grid; grid-template-rows:auto 1fr auto; padding:20px; gap:14px; }
    header { display:flex; align-items:center; justify-content:space-between; gap:16px; }
    h1 { font-size:20px; margin:0; letter-spacing:.04em; }
    .status { color:var(--muted); font-size:13px; }
    .dot { display:inline-block; width:9px; height:9px; margin-right:7px; border-radius:50%; background:var(--accent); box-shadow:0 0 12px var(--accent); }
    #messages { overflow:auto; border:1px solid var(--line); border-radius:16px; background:rgba(8,22,18,.8); padding:20px; box-shadow:0 18px 50px #0006; }
    .message { max-width:84%; margin:0 0 16px; padding:12px 14px; border-radius:14px; white-space:pre-wrap; overflow-wrap:anywhere; }
    .assistant { background:#142a24; border:1px solid #294a40; }
    .user { margin-left:auto; background:#205f46; }
    .error { border-color:#7a3535; color:#ffd7d7; }
    .label { display:block; color:var(--muted); font-size:11px; font-weight:700; letter-spacing:.08em; text-transform:uppercase; margin-bottom:5px; }
    form { display:grid; grid-template-columns:1fr auto; gap:10px; }
    textarea { resize:none; min-height:54px; max-height:160px; padding:14px; border-radius:13px; border:1px solid var(--line); background:var(--panel); color:var(--text); font:inherit; outline:none; }
    textarea:focus { border-color:var(--accent); box-shadow:0 0 0 3px #39d98a22; }
    button { border:0; border-radius:13px; padding:0 22px; background:var(--accent); color:#052016; font-weight:800; cursor:pointer; }
    button:disabled { opacity:.45; cursor:wait; }
    @media (max-width:600px) { main{padding:12px}.message{max-width:94%}form{grid-template-columns:1fr}button{height:46px} }
  </style>
</head>
<body>
<main>
  <header><h1>LLM-ID <span style="color:#39d98a">Analyst</span></h1><div class="status"><span class="dot"></span><span id="status">Ready · __MODEL__ · __ACCESS__</span></div></header>
  <section id="messages" aria-live="polite"><div class="message assistant"><span class="label">Analyst</span>Connected to the local IDS tools. Ask me to scan recent events, inspect suspicious activity, or review alert history.</div></section>
  <form id="chat"><textarea id="prompt" placeholder="Ask about this computer's security…" required></textarea><button id="send">Send</button></form>
</main>
<script>
  const form=document.querySelector('#chat'), prompt=document.querySelector('#prompt'), send=document.querySelector('#send'), messages=document.querySelector('#messages'), status=document.querySelector('#status');
  let sessionId=localStorage.getItem('llmid-session') || crypto.randomUUID(); localStorage.setItem('llmid-session',sessionId);
  function add(role,text,error=false){ const el=document.createElement('div'); el.className=`message ${role}${error?' error':''}`; const label=document.createElement('span'); label.className='label'; label.textContent=role==='user'?'You':'Analyst'; el.append(label,document.createTextNode(text)); messages.append(el); messages.scrollTop=messages.scrollHeight; }
  form.addEventListener('submit',async e=>{ e.preventDefault(); const message=prompt.value.trim(); if(!message)return; add('user',message); prompt.value=''; send.disabled=true; status.textContent='Thinking…';
    try { const response=await fetch('/api/chat',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({session_id:sessionId,message})}); const data=await response.json(); if(!response.ok)throw new Error(data.error||`Request failed (${response.status})`); add('assistant',data.answer); }
    catch(error){ add('assistant',error.message,true); }
    finally { send.disabled=false; status.textContent='Ready · __MODEL__ · __ACCESS__'; prompt.focus(); }
  });
  prompt.addEventListener('keydown',e=>{ if(e.key==='Enter'&&!e.shiftKey){e.preventDefault();form.requestSubmit();} });
</script>
</body>
</html>""".replace("__MODEL__", MODEL).replace("__ACCESS__", "Administrator" if IS_ADMIN else "Limited access")


def relaunch_as_administrator() -> bool:
    """Request a normal Windows UAC elevation for this exact local launcher."""
    if os.name != "nt" or IS_ADMIN:
        return False
    script = os.path.abspath(__file__)
    parameters = subprocess.list2cmdline([script, "--elevated"])
    result = ctypes.windll.shell32.ShellExecuteW(
        None, "runas", sys.executable, parameters, os.path.dirname(script), 1
    )
    if result <= 32:
        raise OSError(f"Windows elevation request failed with code {result}")
    return True


def _session(session_id: str) -> tuple[list[dict[str, Any]], threading.Lock]:
    with _sessions_lock:
        if session_id not in _sessions:
            _sessions[session_id] = new_history()
            _session_locks[session_id] = threading.Lock()
        return _sessions[session_id], _session_locks[session_id]


class AgentHandler(BaseHTTPRequestHandler):
    def _json(self, status: int, payload: dict[str, Any]) -> None:
        body = json.dumps(payload).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self) -> None:
        path = urlparse(self.path).path
        if path == "/":
            body = HTML.encode("utf-8")
            self.send_response(200)
            self.send_header("Content-Type", "text/html; charset=utf-8")
            self.send_header("Content-Length", str(len(body)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(body)
        elif path == "/api/health":
            self._json(200, {"status": "ok", "model": MODEL, "administrator": IS_ADMIN})
        else:
            self._json(404, {"error": "Not found"})

    def do_POST(self) -> None:
        if urlparse(self.path).path != "/api/chat":
            self._json(404, {"error": "Not found"})
            return
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length <= 0 or length > MAX_BODY_SIZE:
                self._json(413, {"error": "Invalid request size"})
                return
            payload = json.loads(self.rfile.read(length))
            message = payload.get("message", "")
            session_id = payload.get("session_id", "")
            if not isinstance(message, str) or not message.strip():
                self._json(400, {"error": "Message is required"})
                return
            if not isinstance(session_id, str) or not session_id or len(session_id) > 100:
                session_id = str(uuid.uuid4())
            history, lock = _session(session_id)
            with lock:
                answer = ask_agent(message.strip(), history)
            self._json(200, {"answer": answer, "session_id": session_id})
        except requests.RequestException as error:
            self._json(502, {"error": f"Ollama request failed: {error}"})
        except (json.JSONDecodeError, ValueError, TypeError) as error:
            self._json(400, {"error": f"Invalid request: {error}"})
        except Exception as error:
            self._json(500, {"error": f"Agent error: {error}"})

    def log_message(self, format: str, *args: Any) -> None:
        print(f"[WEB] {self.address_string()} - {format % args}")


def main() -> None:
    if "--elevated" not in sys.argv and relaunch_as_administrator():
        print("Administrator access requested. Approve the Windows UAC prompt to continue.")
        return
    if os.name == "nt" and not IS_ADMIN:
        print("WARNING: Running without administrator access; Sysmon scans may fail.")
    server = ThreadingHTTPServer((HOST, PORT), AgentHandler)
    url = f"http://{HOST}:{PORT}"
    print(f"LLM-ID web analyst ({MODEL})")
    print(f"Open {url} (Ctrl+C to stop)")
    threading.Timer(0.6, lambda: webbrowser.open(url)).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nStopped.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
