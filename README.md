# ngx_http_jwt

*Nginx http module for JWT*

> [!IMPORTANT]
> As of the current `libjwt v3`, the underlying library does not support JWE yet. But it is said that the library will soon ship `libjwt v4` with [full JWE support](https://github.com/benmcollins/libjwt/issues/158). JWE support will be added to this project by then.

## Overview

This module is an static add-on module compiled into nginx. It enables nginx to verify a JWT, validate its claims and extract claims to proxied request if you still need any. Common use case would be like verifying session token or OAuth / OIDC [access token](https://datatracker.ietf.org/doc/html/rfc9068).

This module is still under construction. The main branch is maintained as a functional version, but no interface commitment is promised.

## Build from source

The project is intended to be built as a static module using [standard nginx build system](https://nginx.org/en/docs/configure.html).

Dependencies:
1. `nginx (>= 1.31.0)` ([CVSS 9.2](https://nvd.nist.gov/vuln/detail/CVE-2026-42945) for 1.30.0)
2. `jansson (>= 2.15.0)`
3. `libjwt (>= 3.3.3)` ([CVSS 9.1](https://nvd.nist.gov/vuln/detail/CVE-2026-44699) for 3.3.2)

You might also need other libraries to build nginx. (`openssl`, `PCRE2`, etc.)
