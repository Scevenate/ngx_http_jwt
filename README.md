# ngx_http_jwt

*Nginx http module for JWT*

> [!IMPORTANT]
> As of the current `libjwt v3`, the underlying library does not support JWE yet. But it is said that the library will soon ship `libjwt v4` with [full JWE support](https://github.com/benmcollins/libjwt/issues/158). JWE support will be added to this project by then.

## [Documentation](docs/index.md)

## Overview

This module is an static add-on module compiled into nginx. It allows nginx to verify a JWT, validate custom claims and extract claims to proxied request if you still need any. Common use case would be verifying session tokens, bearer tokens or OAuth / OIDC [access tokens](https://datatracker.ietf.org/doc/html/rfc9068).

## Quick start
