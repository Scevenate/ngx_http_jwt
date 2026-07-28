# ngx_http_jwt

> [!IMPORTANT]
> This module initially intends to progressively provide more powerful control over existing nginx jwt solutions. However after reviewing the features of the product, it does not seem to add much value. Therefore this project is no longer maintained.

## [Documentation](docs/index.md)

## Overview

This module extends nginx for custom JWT authorization. It allows nginx to fetch a token from request, validate its claims and extract values to proxy if you still need any.

> [!NOTE]
> The current release only supports local JWKS. Remote JWKS is being actively planned.

## Quick start

Pull the docker image:

```YAML
services:
  nginx:
    image: scevenate/nginx-jwt:v1.0.0
    container_name: nginx
    ports:
      - "80:80"
    volumes:
      - ./nginx.conf:/etc/nginx/nginx.conf:ro
      - ./conf.d:/etc/nginx/conf.d:ro
      - ./logs:/etc/nginx/logs
    restart: unless-stopped
```

Config example:

```nginx
events {
    worker_connections 1024;
}

http {
    include /etc/nginx/mime.types;

    # At http context level, this directive is applied to all locations.
    # This instructs nginx to return 404 on JWT validation failure.
    # Internal error of the module still returns 500.
    # Default value is 403.
    jwt_error_code 404;

    # This directive loads an jwks to all locations.
    jwt_load_jwks file jwks/gateway.json;

    server {
        listen 80;
        server_name localhost;

        # This claim enables the JWT module on all locations of the server.
        # It also instructs the JWT token to be fetched from http bearer
        # authorization.
        jwt bearer;

        # This directive loads an jwks to all locations of the server.
        # One location may load multiple key sets.
        # Local key sets are cached per cycle, and is read only once for
        # one path.
        jwt_load_jwks file jwks/bob.json;

        # This directive validates the claim iss by predicate ==, that
        # the claim must have JSON value "Bob".
        # The outer single quotes are for nginx.conf parsing. The inner
        # double quotes are JSON string literal quotes.
        # It is recommended to always quote JSON values with single quotes,
        # e.g. '"string"', 'true', '["Alice", 2, null]'.
        jwt_validate iss == '"Bob"';

        # This directive validates the claim exp by predicate exp, that
        # the claim must be a JSON number, interpreted as a timestamp,
        # being bigger than the runtime timestamp.
        # The exp validation has leeway time of 5 seconds. The value must
        # not be negative; Default value is 0.
        jwt_validate exp exp '5';

        location /static/ {
            root /static/;

            # This directive overwrites the server directive jwt bearer;
            # and turns the module off for this location.
            jwt off;
        }

        location /api/ {
            proxy_pass http://app/;
            proxy_set_header Host $host;
            proxy_set_header X-Real-IP $remote_addr;
            proxy_set_header X-Forwarded-For $proxy_add_x_forwarded_for;
            proxy_set_header X-Forwarded-Proto $scheme;

            # This directive fetches JWT from the custom http header
            # x-app-api-token.
            jwt header x-app-api-token;

            # This directive extracts the JWT claim id to http header id
            # for proxying.
            # The extracted header is base64url encoded JSON literal value.
            # Note that JSON literal string has double quotes.
            # The 'optional' option tells the module to skip if claim id
            # is not found, rather than failing validation.
            # Due to security concerns, the header is stripped
            # if the client attempts to forge a header named id.
            jwt_extract id id optional;

            # These two directives validate the claim version by
            # predicate in, that the claim value must equal to
            # one of the JSON values in the JSON array.
            # Then, the value is extarcted as base64url value into
            # header version for proxy.
            jwt_validate version in '[1, 2]';
            jwt_extract version version;
        }

        location /sample-2/ {
            root /sample-2/;

            # This directive fetches JWT from the cookie ACCESS_TOKEN.
            jwt cookie ACCESS_TOKEN;

            # These two directives validate claims exp & nbf
            # by predicates exp & nbf with default leeway 0.
            # The server exp validation directive is overwritten.
            jwt_validate exp exp;
            jwt_validate nbf nbf;
        }

        location /sample-3/ {
            root /sample-3/;

            # This directive fetches JWT from the query parameter token.
            jwt query token;

            jwt_validate issued nbf;
        }
    }
}
```
