#!/bin/bash
NGINX="nginx-release-1.31.2"

ROOT=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/../.." &> /dev/null && pwd )

rm -rf "$ROOT/ngx_http_jwt/test/nginx" || true

cp -r "$ROOT/$NGINX" "$ROOT/ngx_http_jwt/test"

mv "$ROOT/ngx_http_jwt/test/$NGINX" "$ROOT/ngx_http_jwt/test/nginx"

cd "$ROOT/ngx_http_jwt/test/nginx"

./auto/configure \
--build="JWT test build" \
--add-module="$ROOT/ngx_http_jwt/src" \
--with-debug

make

rm -rf "$ROOT/ngx_http_jwt/test/prefix"

mkdir -p "$ROOT/ngx_http_jwt/test/prefix/logs"
