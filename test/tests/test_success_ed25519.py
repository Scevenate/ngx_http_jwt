from requests import Session
import jwt
import time

def test_success_ed25519():
    with Session() as session:
        jwt_token = jwt.encode(
            {"exp": time.time() + 2,
            "nbf": time.time() + 2,
            "food": {"truth": "There is no food", "food": [None]}},
            "-----BEGIN PRIVATE KEY-----MC4CAQAwBQYDK2VwBCIEIP8AHcZCyoeAzEq68CFKLrgGI2UpsC5ce9INGStPnfo0-----END PRIVATE KEY-----",
            "EdDSA", # Ed25519
            {"kid": "ed25519_key"},
        )
        response = session.get("http://localhost:8080/robots.txt", headers={
            "Authorization": f"Bearer {jwt_token}"
        })
        assert response.content == b"Don't scrape, thanks!"
