
/*
 * Copyright (C) Scevenate
 */


#ifndef NGX_HTTP_JWT_H
#define NGX_HTTP_JWT_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt_request.h>
#include <ngx_http_jwt_jwk.h>
#include <ngx_http_jwt_memory.h>
#include <jansson.h>


#define NGX_HTTP_JWT_DEFAULT_ERROR_CODE NGX_HTTP_FORBIDDEN

#define NGX_HTTP_JWT_LEEWAY_MAX 2147483647

#define NGX_HTTP_JWT_CLAIM_NAME_LEN_MAX 2048 // Include null terminator
#define NGX_HTTP_JWT_CLAIM_VALUE_LEN_MAX 2048 // Include null terminator
#define NGX_HTTP_JWT_HEADER_NAME_LEN_MAX 2048 // Include null terminator


typedef struct {
    ngx_str_t name;
    json_t *value;
    ngx_queue_t queue;
} ngx_http_jwt_validate_claim_t;

typedef struct {
    double exp;
    double nbf;
    ngx_queue_t claims;
} ngx_http_jwt_validate_t;

typedef struct {
    ngx_str_t claim_name;
    ngx_str_t header_name;
    ngx_flag_t optional;
    ngx_queue_t queue;
} ngx_http_jwt_extract_claim_t;

typedef struct {
    ngx_queue_t claims;
} ngx_http_jwt_extract_t;


static const ngx_str_t null_string = ngx_null_string;


#endif /* NGX_HTTP_JWT_H */