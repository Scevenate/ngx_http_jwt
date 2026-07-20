# `ngx_http_jwt` module docs `v1.0.0`

# Builds

## Dependencies

This project has the following build dependencies:
- `nginx` (`>=1.31.2`)
- `libjwt` (`>=3.6.1`)
- `jansson` (`>=2.15.1`)
- `OpenSSL` (`>=3.5.6`)
- `PCRE2` (`>=10.46`)
- `zlib` (`>=1.3.1`)
- `libxslt` (`>=1.1.35`)
- `GD` (`>=2.3.3`)
- `perl` (`>=5.40.1`)
- `geoip` (`>=1.6.12`)

`v1.0.0` is tested and built on the version specified above.

## Prebuilts

`v1.0.0` build is available on dockerhub repository `scevenate/nginx-jwt`. 

An example docker compose configuration:

## Build from source

Please refer to [Nginx build system](https://nginx.org/en/docs/configure.html) to build `ngx_http_jwt` as a standard static add on module.

You will additionally need `jansson` and `libjwt` to build nginx.
