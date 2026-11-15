import json
import threading
from http.client import HTTPConnection
from http.server import ThreadingHTTPServer

import web_agent


def _request(server, method, path, payload=None):
    connection = HTTPConnection(*server.server_address, timeout=5)
    body = json.dumps(payload) if payload is not None else None
    headers = {"Content-Type": "application/json"} if body else {}
    connection.request(method, path, body=body, headers=headers)
    response = connection.getresponse()
    data = response.read()
    connection.close()
    return response.status, response.getheader("Content-Type"), data


def test_web_routes(monkeypatch):
    monkeypatch.setattr(web_agent, "ask_agent", lambda question, history: f"Echo: {question}")
    web_agent._sessions.clear()
    web_agent._session_locks.clear()
    server = ThreadingHTTPServer(("127.0.0.1", 0), web_agent.AgentHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, content_type, body = _request(server, "GET", "/")
        assert status == 200
        assert "text/html" in content_type
        assert b"LLM-ID" in body

        status, _, body = _request(server, "GET", "/api/health")
        assert status == 200
        health = json.loads(body)
        assert health["status"] == "ok"
        assert isinstance(health["administrator"], bool)

        status, _, body = _request(
            server,
            "POST",
            "/api/chat",
            {"session_id": "test-session", "message": "hello"},
        )
        assert status == 200
        assert json.loads(body)["answer"] == "Echo: hello"
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)


def test_chat_rejects_empty_message():
    server = ThreadingHTTPServer(("127.0.0.1", 0), web_agent.AgentHandler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        status, _, body = _request(server, "POST", "/api/chat", {"message": ""})
        assert status == 400
        assert "required" in json.loads(body)["error"].lower()
    finally:
        server.shutdown()
        server.server_close()
        thread.join(timeout=5)
