FROM debian:trixie-slim

ENV NGINX_VERSION      1.31.2
ENV NJS_VERSION        1.0.0
ENV NJS_RELEASE        1~trixie
ENV NGINX_JWT_VERSION  1.0.0
ENV ACME_VERSION       0.4.1
ENV PKG_RELEASE        1~trixie
ENV DYNPKG_RELEASE     1~trixie

COPY nginx /nginx

RUN set -x \
# os settings
    && groupadd --system --gid 101 nginx \
    && useradd --system --gid nginx --no-create-home --home /nonexistent --comment "nginx user" --shell /bin/false --uid 101 nginx \
# install build
    && apt-get update \
    && apt-get install --no-install-recommends --no-install-suggests -y \
        make \
        libjansson4 \
    && make -C /nginx install \
# clean up
    && apt-get remove --purge --auto-remove -y \
        make \
    && rm -rf /nginx \
# adding additional directories (created via postscript in regular image)
    && mkdir -p \
        /var/cache/nginx/client_temp \
        /var/cache/nginx/proxy_temp \
        /var/cache/nginx/fastcgi_temp \
        /var/cache/nginx/uwsgi_temp \
        /var/cache/nginx/scgi_temp \
# forward request and error logs to docker log collector
    && ln -sf /dev/stdout /var/log/nginx/access.log \
    && ln -sf /dev/stderr /var/log/nginx/error.log \
# create a docker-entrypoint.d directory
    && mkdir /docker-entrypoint.d

COPY docker-entrypoint.sh /
COPY 10-listen-on-ipv6-by-default.sh /docker-entrypoint.d
COPY 15-local-resolvers.envsh /docker-entrypoint.d
COPY 20-envsubst-on-templates.sh /docker-entrypoint.d
COPY 30-tune-worker-processes.sh /docker-entrypoint.d
ENTRYPOINT ["/docker-entrypoint.sh"]

COPY LICENSE /

EXPOSE 80

STOPSIGNAL SIGQUIT

CMD ["nginx", "-g", "daemon off;"]
