from unittest import TestCase
from pathlib import Path
import subprocess
from time import sleep
import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread

NGINX_PORT = 8080
NGINX_PROXY_PORT = 8081
NGINX_START_WAIT_TIME = 0.1 # Try increasing this time if connection refused

class NginxTestCase(TestCase):
    """
    Base testcase class for all nginx test cases.
    Manages nginx lifecycle, tests configuration and enables debug logging.
    All testcases must start with: test_file = __file__
    """
    test_file = __file__

    def setUp(self):
        self.test_root_dir = Path(self.test_file).parent.parent
        self.nginx_path = self.test_root_dir / "build" / "nginx"
        self.nginx_prefix = self.test_root_dir / "build"
        self.conf_path = self.test_root_dir / "tests" / (Path(self.test_file).stem + ".conf")

        subprocess.run(["pkill", "-x", "nginx"])

        nginx_test = subprocess.run(
            [self.nginx_path, "-t", "-p", self.nginx_prefix, "-c", self.conf_path, "-g", "error_log logs/error.log debug;"],
            capture_output=True,
            text=True,
        )
        if nginx_test.returncode != 0:
            raise AssertionError(f"Configuration file {self.conf_path} test failed [return code {nginx_test.returncode}]:\n{nginx_test.stderr}")

        # Over 150k tokens have been wasted on this daemon directive.
        self.nginx_process = subprocess.Popen([self.nginx_path, "-p", self.nginx_prefix, "-c", self.conf_path, "-g", f"daemon off; error_log logs/error.log debug;"])

        sleep(NGINX_START_WAIT_TIME)

    def tearDown(self):
        self.nginx_process.terminate()
        self.nginx_process.wait()



class NginxProxyTestCase(NginxTestCase):
    """
    Testcase class for proxy testcases.
    This subclass provides a proxy backend http://localhost:8081 with header extraction functionality.
    The headers of the last proxied request are available in the self.proxied_headers attribute.
    Also consider inspecting raw response in debug logs.
    This class also provides a b64url_decode_json method to decode base64url encoded JSON strings.
    All testcases must start with: test_file = __file__
    """
    def setUp(self):
        super().setUp()
        self.proxied_headers = {}
        self.backend = _ReusableHTTPServer(
            ("localhost", NGINX_PROXY_PORT),
            self._headerEchoHandlerFactoryFactory(self.proxied_headers),
        )
        self.backend_thread = Thread(target=self.backend.serve_forever, daemon=True)
        self.backend_thread.start()

    def tearDown(self):
        self.backend.shutdown()
        self.backend_thread.join()
        self.backend.server_close()
        super().tearDown()

    @staticmethod
    def _headerEchoHandlerFactoryFactory(captured):
        def _headerEchoHandlerFactory(*args, **kwargs):
            class HeaderEchoHandler(BaseHTTPRequestHandler):
                def do_GET(self):
                    captured.clear()
                    captured.update(
                        (k.lower(), v) for k, v in self.headers.items()
                    )
                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"ok")
                def log_message(self, format, *args):
                    pass  # Shut it up
            return HeaderEchoHandler(*args, **kwargs)
        return _headerEchoHandlerFactory

    # Actually only proxy testcase uses this. So we're gatekeeping NginxTestCase as a basic nginx lifecycle manager.
    @staticmethod
    def b64url_decode_json(value):
        padding = "=" * (-len(value) % 4)
        return json.loads(base64.urlsafe_b64decode(value + padding))

class _JSONServer(BaseHTTPRequestHandler):
    """
    JSONServer's supporting server.
    """
    def __init__(self, json_path, json_data, *args, **kwargs):
        self.json_path = json_path
        self.json_data = json_data
        super().__init__(*args, **kwargs)

    def do_GET(self):
        print(self.path) # Debug
        if self.json_path != self.path:
            self.send_response(404)
            self.end_headers()
            return
        self.send_response(200)
        self.end_headers()
        self.wfile.write(self.json_data.encode())

    def log_message(self, format, *args):
        pass  # Shut it up

    @staticmethod
    def _JSONServerFactoryFactory(json_path, json_data):
        def _JSONServerFactory(*args, **kwargs):
            return _JSONServer(json_path, json_data, *args, **kwargs)
        return _JSONServerFactory

class _ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True


class JSONServer(Thread):
    """
    Starts a minimal JSON server that serves the given JSON data on the given endpoint.
    """
    def __init__(self, port, json_path, json_data):
        super().__init__(daemon=True)
        self.server = _ReusableHTTPServer(("localhost", port), _JSONServer._JSONServerFactoryFactory(json_path, json_data))

    def run(self):
        self.server.serve_forever(poll_interval=0.1)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()