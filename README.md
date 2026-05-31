# ngx_http_jwt

*Nginx http module for JWT*

## Overview

## Quick start

## Build from source

The project is intended to be built as a static module using standard nginx build system.

Dependencies:
1. `nginx (>= 1.31.0)` ([CVSS 9.2](https://nvd.nist.gov/vuln/detail/CVE-2026-42945) for 1.30.0)
2. `jansson (>= 2.15.0)` (required by `libjwt`)
3. `libjwt (>= 3.3.3)` ([CVSS 9.1](https://nvd.nist.gov/vuln/detail/CVE-2026-44699) for 3.3.2)

You might also need other libraries to build nginx. (`openssl`, `PCRE2`, etc.)