import time
from requests import Session
import jwt

def test_success_jwks_load():
    with Session() as session:
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
            headers={"Authorization": f"Bearer {jwt_token}"}
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
            headers={"Authorization": f"Bearer {jwt_token}"}
        )
        assert response.status_code == 200
