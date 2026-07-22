
/*
 * Copyright (C) Scevenate
 */


#ifndef NGX_HTTP_JWT_H
#define NGX_HTTP_JWT_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt_request_transaction.h>
#include <ngx_http_jwt_jwks_storage.h>
#include <ngx_http_jwt_memory.h>


#define NGX_HTTP_JWT_DEFAULT_ERROR_CODE NGX_HTTP_FORBIDDEN

#define NGX_HTTP_JWT_LEEWAY_MAX 2147483647

#define NGX_HTTP_JWT_CLAIM_NAME_LEN_MAX 2048 // Include null terminator
#define NGX_HTTP_JWT_CLAIM_VALUE_LEN_MAX 2048 // Include null terminator
#define NGX_HTTP_JWT_HEADER_NAME_LEN_MAX 2048 // Include null terminator

#endif /* NGX_HTTP_JWT_H */