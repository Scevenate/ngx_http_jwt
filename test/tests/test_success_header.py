from requests import Session
import jwt
import time


def test_success_header():
    jwt_token = jwt.encode(
        {
            "exp": time.time() + 2,
            "nbf": time.time() - 3,
            "jwt_validate": "jwt_validate"
        },
        "test_secret_key_32_bytes_long!!!",
        "HS256",
        {"kid": "lowkey_a_kid"},
    )

    with Session() as session:
        response = session.get(
            "http://localhost:8080/robots.txt",
            headers={
                "x-app-jwt-token": jwt_token
            }
        )

    assert response.status_code == 200
