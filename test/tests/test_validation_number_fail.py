from .lib import NginxTestCase
from requests import Session
import jwt
import time

class TestNbfFail(NginxTestCase):
    test_file = __file__

    def test_nbf_fail(self):
        with Session() as session:
            jwt_token = jwt.encode(
                {"exp": int(time.time()),
                "nbf": int(time.time()),
                "food": "bar",
                "price": 100.75,
                "amount": -3,
                "discount": -4.9,
                "organization_id": 0,
                "api_key": None},
                "test_secret_key_32_bytes_long!!!",
                "HS256",
                {"kid": "lowkey_a_kid"},
            )
            response = session.get("http://localhost:8080/robots.txt", headers={
                "Authorization": f"Bearer {jwt_token}"
            })
            assert response.status_code == 403