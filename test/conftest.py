import pytest
import subprocess
import shutil
from pathlib import Path
from time import sleep
from threading import Thread
import os
import base64
import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from threading import Thread
from typing import Literal
from dataclasses import dataclass

MODE: Literal["dev", "container"]

match os.environ.get("MODE"):
    case "dev":
        MODE = "dev"
    case "container":
        MODE = "container"
    case "None":
        raise ValueError("No test mode provided.")
    case _:
        raise ValueError("Invalid test mode.")

# Try increase this value if connection refused
NGINX_START_WAIT_TIME = 0.2

TEST_ROOT = Path(__file__).parent
NGINX_PATH =   TEST_ROOT / "nginx" / "objs" / "nginx"
NGINX_PREFIX = TEST_ROOT / "prefix"
NGINX_CONF =   TEST_ROOT / "tests" / "nginx.conf"

# Remove previous logs
subprocess.run(['rm', '-r', TEST_ROOT / "prefix" / "logs"])
os.mkdir(TEST_ROOT / "prefix" / "logs")

@pytest.fixture(scope="session", autouse=True)
def _nginx():
    match MODE:
        case "dev":
            subprocess.run(["pkill", "-x", "nginx"])
            NGINX_CONF.write_text("""
# A minimal nginx conf before hot reloads
events { worker_connections 1024; }
http {
    server {
        listen 8080;
        server_name localhost;
        location / {
            return 200 "ok";
        }
    }
}
""")

            process = subprocess.Popen(
                [
                    NGINX_PATH,
                    "-p", NGINX_PREFIX,
                    "-c", NGINX_CONF,
                    "-g", "daemon off; error_log logs/error.log debug;",
                ]
            )
            sleep(NGINX_START_WAIT_TIME)
            yield
            process.terminate()
            process.wait()
        case "container":
            return

@pytest.fixture(autouse=True)
def _nginx_reload(request: pytest.FixtureRequest, _nginx):
    match MODE:
        case "dev":
            TEST_CONF = TEST_ROOT / "tests" / (request.path.stem + ".conf")
            shutil.copy(TEST_CONF, NGINX_CONF)

            nginx_test = subprocess.run(
                [
                    NGINX_PATH,
                    "-t",
                    "-p", NGINX_PREFIX,
                    "-c", NGINX_CONF,
                    "-g", "error_log logs/error.log debug;",
                ],
                capture_output=True,
                text=True,
            )
            if nginx_test.returncode != 0:
                raise AssertionError(
                    f"Configuration file {TEST_CONF} test failed "
                    f"[return code {nginx_test.returncode}]:\n{nginx_test.stderr}"
                )

            subprocess.run(
                [NGINX_PATH, "-p", NGINX_PREFIX, "-c", NGINX_CONF, "-s", "reload"]
            )
            sleep(NGINX_START_WAIT_TIME)
            return
        case "container":
            return


# Proxy fixture

@dataclass
class EchoedRequest:
    headers: dict[str, str]

def _echoHandlerFactoryFactory(request: EchoedRequest):
    def EchoHandlerFactory(*args, **kwargs):
        class HeaderEchoHandler(BaseHTTPRequestHandler):
            def do_GET(self):
                request.headers.clear()
                request.headers.update({key: value for (key, value) in self.headers.items()})
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"ok")

            def log_message(self, format, *args):
                pass

        return HeaderEchoHandler(*args, **kwargs)

    return EchoHandlerFactory

class _ReusableHTTPServer(HTTPServer):
    allow_reuse_address = True

class _EchoServer(Thread):
    def __init__(self, request: EchoedRequest):
        super().__init__(daemon=True)
        self.server = _ReusableHTTPServer(
            ("localhost", 8081),
            _echoHandlerFactoryFactory(request),
        )

    def run(self):
        self.server.serve_forever(poll_interval=0.1)

    def stop(self):
        self.server.shutdown()
        self.server.server_close()

@pytest.fixture(scope="session")
def backend(_nginx):
    request = EchoedRequest({});
    server = _EchoServer(request)
    server.start()
    yield request
    server.stop()

# lib

def b64url_decode_json(value):
    padding = "=" * (-len(value) % 4)
    return json.loads(base64.urlsafe_b64decode(value + padding))
