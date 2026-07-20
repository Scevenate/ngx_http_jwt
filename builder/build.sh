#!/bin/bash
NGINX="nginx-release-1.31.2"

ROOT=$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )/../.." &> /dev/null && pwd )

rm -rf "$ROOT/ngx_http_jwt/builder/nginx" || true

cp -r "$ROOT/$NGINX" "$ROOT/ngx_http_jwt/builder"

mv "$ROOT/ngx_http_jwt/builder/$NGINX" "$ROOT/ngx_http_jwt/builder/nginx"

mkdir -p "$ROOT/ngx_http_jwt/builder/nginx/addon/ngx_http_jwt"

cp -r "$ROOT/ngx_http_jwt/src" "$ROOT/ngx_http_jwt/builder/nginx/addon/ngx_http_jwt"

cd "$ROOT/ngx_http_jwt/builder/nginx"

auto/configure \
--prefix=/etc/nginx \
--sbin-path=/usr/sbin/nginx \
--modules-path=/usr/lib/nginx/modules \
--conf-path=/etc/nginx/nginx.conf \
--error-log-path=/var/log/nginx/error.log \
--http-log-path=/var/log/nginx/access.log \
--pid-path=/run/nginx.pid \
--lock-path=/run/nginx.lock \
--http-client-body-temp-path=/var/cache/nginx/client_temp \
--http-proxy-temp-path=/var/cache/nginx/proxy_temp \
--http-fastcgi-temp-path=/var/cache/nginx/fastcgi_temp \
--http-uwsgi-temp-path=/var/cache/nginx/uwsgi_temp \
--http-scgi-temp-path=/var/cache/nginx/scgi_temp \
--user=nginx \
--group=nginx \
--with-compat \
--with-file-aio \
--with-threads \
--with-http_addition_module \
--with-http_auth_request_module \
--with-http_dav_module \
--with-http_flv_module \
--with-http_gunzip_module \
--with-http_gzip_static_module \
--with-http_mp4_module \
--with-http_random_index_module \
--with-http_realip_module \
--with-http_secure_link_module \
--with-http_slice_module \
--with-http_ssl_module \
--with-http_stub_status_module \
--with-http_sub_module \
--with-http_v2_module \
--with-http_v3_module \
--with-mail \
--with-mail_ssl_module \
--with-stream \
--with-stream_realip_module \
--with-stream_ssl_module \
--with-stream_ssl_preread_module \
--with-cc-opt='-g -O2 -Werror=implicit-function-declaration -ffile-prefix-map=/home/build/docker/debian/amd64=. -fstack-protector-strong -fstack-clash-protection -Wformat -Werror=format-security -fcf-protection -Wp,-D_FORTIFY_SOURCE=2 -fPIC' \
--with-ld-opt='-Wl,-z,relro -Wl,-z,now -Wl,--as-needed -pie -Wl,-Bstatic -ljwt -Wl,-Bdynamic' \
--add-module=addon/ngx_http_jwt/src \
--build=nginx-jwt/1.0.0 || exit 1

make || exit 1

echo "Please delete the build dependency of install make target, then build the image."
