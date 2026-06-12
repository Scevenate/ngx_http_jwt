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
NGINX_START_WAIT_TIME = 0.1 # Increase this time if connection refused

class NginxTestCase(TestCase):
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
            raise RuntimeError(f"Configuration file {self.conf_path} test failed:\n{nginx_test.stderr}")

        # Over 150k tokens have been wasted on this daemon directive.
        self.nginx_process = subprocess.Popen([self.nginx_path, "-p", self.nginx_prefix, "-c", self.conf_path, "-g", f"daemon off; error_log logs/error.log debug;"])

        sleep(NGINX_START_WAIT_TIME)

    def tearDown(self):
        self.nginx_process.terminate()
        self.nginx_process.wait()



class NginxProxyTestCase(NginxTestCase):
    def setUp(self):
        super().setUp()
        self.proxied_headers = {}
        self.backend = HTTPServer(
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

    # Actually only proxy testcase uses this. So we're gatekeeping NginxTestCase as a basic nginx lifespan manager.
    @staticmethod
    def b64url_decode_json(value):
        padding = "=" * (-len(value) % 4)
        return json.loads(base64.urlsafe_b64decode(value + padding))
