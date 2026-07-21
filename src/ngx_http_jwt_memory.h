
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


typedef enum {
    NGX_HTTP_JWT_MEMORY_POOL_UNSET = -1,
    NGX_HTTP_JWT_MEMORY_POOL_REGULAR,
    NGX_HTTP_JWT_MEMORY_POOL_SLAB,
} ngx_http_jwt_memory_pool_type_t;

typedef struct {
    ngx_http_jwt_memory_pool_type_t pool_type;
    union {
        ngx_pool_t *pool;
        ngx_slab_pool_t *slab_pool;
    };
} ngx_http_jwt_memory_config_t;

// Memory redirection must be set before using any JSON / JWT / related memory operation.
// This is still fragile but it's the best we can do without rewriting the library.
// This configuration is global. Supporting library SHOULD restore the original memory allocator after use.
ngx_int_t ngx_http_jwt_memory_set(ngx_http_jwt_memory_config_t *config);

// Get the current memory redirection configuration.
ngx_int_t ngx_http_jwt_memory_get(ngx_http_jwt_memory_config_t *config);

// The current memory allocator.
void *ngx_http_jwt_memory_alloc(size_t size);

// The current memory free function.
void ngx_http_jwt_memory_free(void *ptr);


#endif /* NGX_HTTP_JWT_MEMORY_H */
