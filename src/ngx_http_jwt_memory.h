
/*
 * Copyright (C) Scevenate
 * This file implements memory pool redirection for JWT (libjwt) / JSON (jansson) module.
 * This mechanism is NOT thread safe. It only works under standard nginx async event model.
 */


#ifndef NGX_HTTP_JWT_MEMORY_H
#define NGX_HTTP_JWT_MEMORY_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>

// The pool must be set before using any JSON / JWT / related memory operation.
// A standard approach shall be:
// 1. Set the pool to be cycle pool during preconfiguration.
// 2. Set the pool to be request pool for request handlers. (Thread unsafe)
// This is still fragile but it's the best we can do without rewriting the library.
ngx_int_t ngx_http_jwt_memory_set_pool(ngx_pool_t *pool);

void *ngx_http_jwt_memory_alloc(size_t size);
void ngx_http_jwt_memory_free(void *ptr);

#endif /* NGX_HTTP_JWT_MEMORY_H */
