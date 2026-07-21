from requests import Session
import jwt
import time

def test_exp_fail():
    with Session() as session:
        jwt_token = jwt.encode(
            {
                "exp": time.time(),
                "nbf": time.time(),
                "food": "bar",
                "null": "",
                "continent": "SA",
                "time_signature": 67
            },
            "test_secret_key_32_bytes_long!!!",
            "HS256",
            {"kid": "lowkey_a_kid"},
        )
        response = session.get(f"http://localhost:8080/robots.txt?t={jwt_token}")
        assert response.status_code == 200
