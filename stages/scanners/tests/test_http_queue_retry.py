import http.server
import socket
import threading

import pytest

from scanners.jobqueue.http_queue import HttpQueue


class _Server:
    def __init__(self, responses):
        self.responses = list(responses)
        self.calls = 0
        s = socket.socket(); s.bind(("127.0.0.1", 0)); self.port = s.getsockname()[1]; s.close()
        outer = self

        class H(http.server.BaseHTTPRequestHandler):
            def do_POST(self):
                code, body = outer.responses[min(outer.calls, len(outer.responses) - 1)]
                outer.calls += 1
                self.send_response(code)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def log_message(self, *a, **kw):
                pass

        self.httpd = http.server.HTTPServer(("127.0.0.1", self.port), H)
        self.t = threading.Thread(target=self.httpd.serve_forever, daemon=True)
        self.t.start()

    def stop(self):
        self.httpd.shutdown(); self.httpd.server_close()


def test_5xx_retries_indefinitely_until_success():
    srv = _Server([(500, b""), (500, b""), (502, b""), (200, b'{"ok":true}')])
    sleeps = []
    try:
        q = HttpQueue(f"http://127.0.0.1:{srv.port}", backoff=0.01, sleeper=sleeps.append)
        out = q._req("POST", "/heartbeat", {"job_id": 1, "worker_id": "w"})
        assert out == {"ok": True}
        assert srv.calls == 4
        assert sleeps and all(s <= 30.0 for s in sleeps)
    finally:
        srv.stop()


def test_4xx_is_fatal_no_retry():
    srv = _Server([(404, b'{"error":"not found"}')])
    try:
        q = HttpQueue(f"http://127.0.0.1:{srv.port}", backoff=0.01, sleeper=lambda _s: None)
        with pytest.raises(RuntimeError, match="404"):
            q._req("POST", "/heartbeat", {})
        assert srv.calls == 1
    finally:
        srv.stop()


def test_backoff_is_capped_at_30s():
    sleeps = []
    fake_now = [0.0]

    def clock():
        return fake_now[0]

    def sleeper(s):
        sleeps.append(s); fake_now[0] += s

    srv = _Server([(500, b"")] * 12 + [(200, b"{}")])
    try:
        q = HttpQueue(f"http://127.0.0.1:{srv.port}", backoff=1.0, sleeper=sleeper, clock=clock)
        q._req("POST", "/heartbeat", {})
        assert max(sleeps) <= 30.0
        assert sleeps[-1] == 30.0           # late attempts saturated
    finally:
        srv.stop()
