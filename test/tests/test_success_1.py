from conftest import EchoedRequest, b64url_decode_json
from requests import Session
import jwt
import time


def test_success_1(backend: EchoedRequest):
    jwt_token = jwt.encode(
        {
            "exp": time.time() + 3600,
            "nbf": time.time() - 1,
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

    assert backend.headers
    assert "admin" not in backend.headers
    assert b64url_decode_json(backend.headers["banner_name"]) == "承诺"
    assert b64url_decode_json(backend.headers["pulls"]) == 10
