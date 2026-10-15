"""Tiny local HTTP server for tests. Nothing here touches the internet."""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


class FakeServer:
    def __init__(self):
        self.routes = {}
        self.default = (404, [("Content-Type", "text/plain")], b"not found")
        self.banner = "fake"
        self.requests = []  # (method, path, headers)
        self._httpd = None
        self.url = ""
        self.add("/", "<html><body>ok</body></html>", headers=[("Content-Type", "text/html")])

    def add(self, path, body="", status=200, headers=None):
        if isinstance(body, str):
            body = body.encode()
        if isinstance(headers, dict):
            headers = list(headers.items())
        self.routes[path] = (status, list(headers or []), body)

    def set_default(self, body="", status=200, headers=None):
        if isinstance(body, str):
            body = body.encode()
        if isinstance(headers, dict):
            headers = list(headers.items())
        self.default = (status, list(headers or []), body)

    def start(self):
        outer = self

        class Handler(BaseHTTPRequestHandler):
            def version_string(self):
                return outer.banner

            def _serve(self, head_only):
                path = self.path.split("?")[0]
                outer.requests.append((self.command, path, dict(self.headers)))
                status, headers, body = outer.routes.get(path, outer.default)
                self.send_response(status)
                for key, value in headers:
                    self.send_header(key, value)
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                if not head_only:
                    self.wfile.write(body)

            def do_GET(self):
                self._serve(False)

            def do_HEAD(self):
                self._serve(True)

            def log_message(self, *args):
                pass

        self._httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.port = self._httpd.server_address[1]
        self.url = f"http://127.0.0.1:{self.port}"
        threading.Thread(target=self._httpd.serve_forever, daemon=True).start()

    def stop(self):
        self._httpd.shutdown()
        self._httpd.server_close()
