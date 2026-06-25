
/*
 * Copyright (C) Scevenate
 *
 * This file implements request transaction.
 * The transaction currectly only supports adding / removing headers.
 * There was an attempt to extend the functionalities of the transaction,
 * but modifying incoming request object is generally fragile and error prone.
 */


#ifndef NGX_HTTP_JWT_REQUEST_TRANSACTION_H
#define NGX_HTTP_JWT_REQUEST_TRANSACTION_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>


typedef struct ngx_http_jwt_request_transaction_s ngx_http_jwt_request_transaction_t;


// Initializes a new opaque transaction object bound to the given request.
// The transaction always allocate memory from the bounded request pool.
// When using the transaction, it is expected that each action is set exactly once in the transaction.
// Canceling or adding an action multiple times will cause undefined behavior.
// Returns NULL on error.
ngx_http_jwt_request_transaction_t *ngx_http_jwt_request_transaction_init(ngx_http_request_t *r);

// Frees a transaction.
void ngx_http_jwt_request_transaction_free(ngx_http_jwt_request_transaction_t *transaction);

// Adds an action to the transaction. It expects name / value to be legal (does not check).
// Even reserved header names are allowed (though discouraged unless you know what you are doing).
// Use value = ngx_null_string to set a key to be cleared.
// Name and value are not borrowed, the caller can and should just free them.
ngx_int_t ngx_http_jwt_request_transaction_add_action(ngx_http_jwt_request_transaction_t *transaction,ngx_str_t name, ngx_str_t value); 

// Apply a transaction. The transaction is automatically freed after applying.
// Note that though called a "transaction", it does not rollback inconsistent changes nor properly frees itself if things got wrong.
// It expects the entire request to just be destroyed in that case.
ngx_int_t ngx_http_jwt_request_transaction_apply(ngx_http_jwt_request_transaction_t *transaction);


#endif /* NGX_HTTP_JWT_REQUEST_TRANSACTION_H */
