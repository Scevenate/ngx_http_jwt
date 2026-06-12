from .lib import NginxProxyTestCase
from requests import Session
import jwt
import time


class TestSuccess1(NginxProxyTestCase):
    test_file = __file__

    def test_success_1(self):
        now = int(time.time())
        jwt_token = jwt.encode(
            {
                "exp": now + 3600,
                "nbf": now - 1,
                "banner_name": "承诺",
                "api_version": 0,
                "game_version": 1.41,
                "metadata": {"type": "pull request", "DSCP": {"enable": False}},
                "fragment": False,
                "last_fragment": True,
                "priority": None,
                "p": ["a", "b", "c", None],
                "pulls": 10,
            },
            "test_secret_key_32_bytes_long!!!",
            "HS256",
            {"kid": "lowkey_a_kid"},
        )

        with Session() as session:
            response = session.get(
                "http://localhost:8080/",
                headers={
                    "Authorization": f"Bearer {jwt_token}",
                    "admin": "true",
                },
            )

        assert response.status_code == 200

        headers = self.proxied_headers
        assert headers
        assert "authorization" not in headers
        assert "admin" not in headers
        assert self.b64url_decode_json(headers["banner_name"]) == "承诺"
        assert self.b64url_decode_json(headers["pulls"]) == 10
