from .lib import NginxTestCase, JSONServer
import time
from requests import Session
import jwt

REQUEST_TIMEOUT = 2


class TestSuccessJwksLoad(NginxTestCase):
    test_file = __file__
    def setUp(self):
        self.json_server = JSONServer(8082, "/.unknown/jwks", "{\"keys\": [{\"kty\": \"oct\", \"alg\": \"HS256\", \"k\": \"HS256_KEY_VALUE_3_VERY_LONG_VALUE_AT_LEAST_32_BYTES_LONG\", \"kid\": \"3\"}]}")
        self.json_server.start()
        try:
            time.sleep(1)
            super().setUp()
        except Exception:
            self.json_server.stop()
            raise

    def test_success_jwks_load(self):
        with Session() as session:
            response = session.get("http://localhost:8082/", timeout=REQUEST_TIMEOUT)
            assert response.status_code == 404

            jwt_token = jwt.encode(
                {
                    "exp": time.time(),
                    "nbf": time.time(),
                },
                "HS256_KEY_VALUE_1_VERY_LONG_VALUE_AT_LEAST_32_BYTES_LONG",
                "HS256",
                {"kid": "1"},
            )
            response = session.get(
                "http://localhost:8080/robots.txt",
                headers={"Authorization": f"Bearer {jwt_token}"},
                timeout=REQUEST_TIMEOUT,
            )
            assert response.status_code == 200

            jwt_token = jwt.encode(
                {
                    "exp": time.time(),
                    "nbf": time.time(),
                },
                "HS256_KEY_VALUE_2_VERY_LONG_VALUE_AT_LEAST_32_BYTES_LONG",
                "HS256",
                {"kid": "2"},
            )
            response = session.get(
                "http://localhost:8080/robots.txt",
                headers={"Authorization": f"Bearer {jwt_token}"},
                timeout=REQUEST_TIMEOUT,
            )
            assert response.status_code == 200

            jwt_token = jwt.encode(
                {
                    "exp": time.time(),
                    "nbf": time.time(),
                },
                "HS256_KEY_VALUE_3_VERY_LONG_VALUE_AT_LEAST_32_BYTES_LONG",
                "HS256",
                {"kid": "3"},
            )
            response = session.get(
                "http://localhost:8080/robots.txt",
                headers={"Authorization": f"Bearer {jwt_token}"},
                timeout=REQUEST_TIMEOUT,
            )
            assert response.status_code == 200

    def tearDown(self):
        try:
            super().tearDown()
        finally:
            self.json_server.stop()