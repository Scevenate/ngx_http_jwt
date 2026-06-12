from .lib import NginxTestCase
from requests import Session
import jwt
import time

class TestExpFail(NginxTestCase):
    test_file = __file__

    def test_exp_fail(self):
        with Session() as session:
            jwt_token = jwt.encode(
                {"exp": int(time.time()) - 10,
                "nbf": int(time.time()) - 5,
                "food": "bar"},
                "test_secret_key_32_bytes_long!!!",
                "HS256",
                {"kid": "lowkey_a_kid"},
            )
            response = session.get("http://localhost:8080/robots.txt", headers={
                "Authorization": f"Bearer {jwt_token}"
            })
            assert response.status_code == 429