
/*
 * Copyright (C) Scevenate
 *
 * This file implements transactional interaction with the request object.
 */


#ifndef NGX_HTTP_JWT_REQUEST_H
#define NGX_HTTP_JWT_REQUEST_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

typedef struct {
    ngx_str_t name;
    ngx_str_t value;
    ngx_queue_t queue;
} ngx_http_jwt_request_filter_header;

typedef struct {
    ngx_flag_t filter_authorization;
    ngx_queue_t filter; // of ngx_http_jwt_request_filter_header
} ngx_http_jwt_request_transaction_t;

// It is expected that each action is set exactly once in the transaction.
// It is the caller's responsibility to call transaction setters in a good manner.

ngx_int_t ngx_http_jwt_request_init(ngx_http_jwt_request_transaction_t *transaction);

// This function sets filter authorization.
ngx_int_t ngx_http_jwt_request_set_authorization(ngx_http_request_t *r, ngx_http_jwt_request_transaction_t *transaction);

// This function sets a custom header. Use value = ngx_null_string to set a header to be cleared.
ngx_int_t ngx_http_jwt_request_set_header(ngx_http_request_t *r, ngx_http_jwt_request_transaction_t *transaction, ngx_str_t key, ngx_str_t value); 

// Applying a transaction always frees & resets the transaction even if it failed.
// However, though called a "transaction", it does not revert the inconsistent changes. It expects the entire request process to just be destroyed.
ngx_int_t ngx_http_jwt_request_apply(ngx_http_request_t *r, ngx_http_jwt_request_transaction_t *transaction);

// Alternative route to free the transaction.
ngx_int_t ngx_http_jwt_request_free(ngx_http_jwt_request_transaction_t *transaction);

#endif /* NGX_HTTP_JWT_REQUEST_H */