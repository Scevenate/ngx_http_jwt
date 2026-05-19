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
1. `nginx` (Last compatibility check 1.31.0)
2. `libjwt` (Last compatibility check 3.2.2)
