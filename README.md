# ngx_http_jwt

*Nginx http module for JWT authorization*

## Usage

```nginx.conf

# events {}

http {
    server {
        listen 80;
        server_name localhost;

        root /app/public;

        jwt on;
        jwks_file /app/jwks;
        jwt_error_code 404; # Default is 403

        location /static/ {
            jwt off;
        }

        location /admin/ {
            jwt_iss v3; # Checks iss claim. "none" is reserved for explicitly turning it off.
        }
    }
}

```

```JSON

{
    "exp": 1778777777,
    "nbf": 1778700000,
    "iss": "v3",
    "ngx_http_jwt": {
        "servers": [
            {
                "server_name": "localhost",
                "locations": [
                    "/"
                ]
            }
        ]
    }
}

```

## Build

Dependencies:
1. `nginx (>= 1.31.0)` ([CVSS 9.2](https://nvd.nist.gov/vuln/detail/CVE-2026-42945) for 1.30.0)
2. `jansson (>= 2.15.0)`
3. `libjwt (>= 3.3.3)` ([CVSS 9.1](https://nvd.nist.gov/vuln/detail/CVE-2026-44699) for 3.3.2)

You might also need other libraries to build nginx. (`openssl`, `PCRE2`, etc.)