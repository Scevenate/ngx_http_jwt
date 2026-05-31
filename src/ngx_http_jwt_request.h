
/*
 * Copyright (C) Scevenate
 *
 * This file implements API for interaction with request object.
 */


#ifndef NGX_HTTP_JWT_REQUEST_H
#define NGX_HTTP_JWT_REQUEST_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

ngx_int_t ngx_http_jwt_request_filter_authorization(ngx_http_request_t *r);

ngx_int_t ngx_http_jwt_request_filter_header(ngx_http_request_t *r, ngx_str_t key, ngx_str_t value); 

#endif /* NGX_HTTP_JWT_REQUEST_H */