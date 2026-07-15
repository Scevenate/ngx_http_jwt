from .lib import NginxTestCase
from requests import Session
import jwt
import time


class TestSuccessCookie(NginxTestCase):
    test_file = __file__

    def test_success_cookie(self):
        jwt_token = jwt.encode(
            {
                "exp": time.time(),
                "nbf": time.time(),
                "jwt_validate": "jwt_validate"
            },
            "test_secret_key_32_bytes_long!!!",
            "HS256",
            {"kid": "lowkey_a_kid"},
        )

        with Session() as session:
            session.cookies.set("SOME_SESSION", jwt_token)
            response = session.get(
                "http://localhost:8080/robots.txt"
            )

        assert response.status_code == 200
