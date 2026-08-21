from requests import Session
import jwt
import time

def test_success_rsa():
    with Session() as session:
        jwt_token = jwt.encode(
            {"exp": time.time() + 2,
            "nbf": time.time() - 2},
            """-----BEGIN PRIVATE KEY-----
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQDiGkGqC0lIqQ1E
Ipu48rRu1+W1BrMRhfzAOYkgJXtgYM83oDuVan8kdtNw/SkwHQzrc7XYA6D5W5z2
Ig95MYo2tLbNp16Ww+AYEpdSJq9iS3ODLhekGtOvdR1c8M8qmX3h/0KbYvUHoRBn
Se6594U0s7jfFckkrzLRbZfs1JwJ/87SBuCCXaJVxyFZGpHffvSR5+fI+6C0RYFM
NtWND495dhin8MgFMnKaGx7tO98DOJATDJrdWKFBX6/xMnJYBattBVmW/IA8OeHU
mLvjnP2sZgK5axjjeInahheufqwxxW6+XbSoCrnfS0/s1xXg0/MBWrpr9fjtaqZg
f8KXb2WPAgMBAAECggEAOfsNt7NpOY7QbhaJ5GWoy3vl1gQ/y1CWvhyDA5FZECAD
Q3p9jRVgQVOPaTwiYcoxU/e6PAjCMO/DUoLtgOCpVtoEvrwaz4KvZrztvQ1akFRU
7ODXAyg1/JqFyx2dooj19QxmYj6AI1K0SCh3ZY0JxbgIwnxttlCPMZFvEjZ7RTyu
u+6PfCmEux3w8NF7ApT6HewYublUzjy7oMs4qXehkX3r1ioMrWmLZGaV77+KRoKH
y/Axfx6s3ovAQe1K5hC1+uwRiQJ+Pp0Ww+D24tsb0Ec4B0gyEQibOS/qjMn+oqBM
/rStBRstTmacbE5rZEoH/YU5x9zvoSeVyKq1a6UR8QKBgQD1gKBYl9wEn65TvE8Q
xfvsaAp9/vVzHDUpItP1CabirdsaRnFM1+lqJCQA53gynJKOeTs5fcRMB4ndeduH
7SzXwdK9T7WHJATktFDoYxImxcC83qZSR3mrs3W8icwDIQa0BVmQ03pqu4Phccr0
W8/ErNj045HubbNZYgdCKyRbNQKBgQDrxUVVJlr48ftAPetncmjpl9dm1jWawf27
bMM3c2j+jBAFasLbi/+hPsMzAg44wP8NO0Dz89ItewWEwQq9ZkCusH93rFSKnEjF
LVLnZhFszLQyOi6+fKLzNQ+Bywe6c58FUSJtOX4GD1aLh9R5tLQNjmcn0+dDSOu/
avsLTxmSMwKBgEJn03eDRCkgBCh0NDLGStlsXwIrt7q2M47387tBLBn+ith1m2n8
sQ9bzT1NXw7ZmS7eje2EHleuZlU5A++lcM6/h8BbUi/Gx2gReh0RxzQjo3mzA+wX
l0qhVUR1RXDHOyfwloR9H4zFQev2Or6UIwQA+QJsl+mVVMDlqi70unXNAoGAWc/i
8mXS/8QGJtmvg8+UYW+DEVyGPPaq9iufTc877sNiEv4xTjrNXRowd4zP6BS009B/
lK6LoOGdH439zlpWR3VaiTbvWYHhQqNaUmWSO7Ta68s4JT4LQMQ0rQevYPpMWFUo
3RyqghpzqGFMsjQA5q0ZZJWXIg10KI3TJeKy5fsCgYBQ4saObGh8jFQFM39wyfXX
ytRYwwMKkBXy19dDX6gjJ8bFkAQISWQ+O72Ej/FuCO5CYee8Jk9BrF5kFWeh2kcx
eQBVvgQuXyaWH/YY58tLsWmMh3fqLjKp7zs6VEuHEa8VQ1QLCrT3v6ehkXdROJTY
vISbmkPxtYPaMfMpcpW8MQ==
-----END PRIVATE KEY-----""",
            "RS256",
            {"kid": "rsa_key"},
        )
        response = session.get("http://localhost:8080/robots.txt", headers={
            "Authorization": f"Bearer {jwt_token}"
        })
        assert response.status_code == 200
