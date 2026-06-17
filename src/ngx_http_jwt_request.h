
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
} ngx_http_jwt_request_header_t;

typedef struct {
    ngx_http_request_t *r;
    ngx_queue_t filter; // of ngx_http_jwt_request_header_t
} ngx_http_jwt_request_transaction_t;

// Initializes a new transaction.
// When using the transaction, it is expected that each action is set exactly once in the transaction. No canceling or multiple setting of the same action.
// Returns NULL on error.
ngx_http_jwt_request_transaction_t *ngx_http_jwt_request_init(ngx_http_request_t *r);

// Frees a transaction.
void ngx_http_jwt_request_free(ngx_http_jwt_request_transaction_t *transaction);

// Sets a custom header. It expects a header name / value with legal characters.
// Any header name, including reserved ones are allowed (though discouraged unless you know what you are doing).
// Use value = ngx_null_string to set a header to be cleared.
// Key and value are not borrowed, the caller can and should just free them.
ngx_int_t ngx_http_jwt_request_set_header(ngx_http_jwt_request_transaction_t *transaction, ngx_str_t name, ngx_str_t value); 

// Apply a transaction. The transaction is automatically freed after applying.
// Note that though called a "transaction", it does not rollback inconsistent changes nor properly frees itself if things got wrong.
// It expects the entire request to just be destroyed in that case.
ngx_int_t ngx_http_jwt_request_apply(ngx_http_jwt_request_transaction_t *transaction);

#endif /* NGX_HTTP_JWT_REQUEST_H */
