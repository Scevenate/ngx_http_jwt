#ifndef NGX_HTTP_JWT_HEADER_H
#define NGX_HTTP_JWT_HEADER_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jwt.h>

ngx_int_t ngx_http_jwt_header_check(ngx_str_t *key); 

ngx_int_t ngx_http_jwt_header_filter_authorization(ngx_http_request_t *r);

ngx_int_t ngx_http_jwt_header_filter(ngx_http_request_t *r, ngx_str_t *key, jwt_value_t *value); 

#endif /* NGX_HTTP_JWT_HEADER_H */