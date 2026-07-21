from requests import Session
import jwt
import time

def test_exp_fail():
    with Session() as session:
        jwt_token = jwt.encode(
            {"exp": time.time() - 10,
            "nbf": time.time() - 5,
            "food": "bar"},
            "test_secret_key_32_bytes_long!!!",
            "HS256",
            {"kid": "lowkey_a_kid"},
        )
        response = session.get("http://localhost:8080/robots.txt", headers={
            "Authorization": f"Bearer {jwt_token}"
        })
        assert response.status_code == 429
