
/*
 * Copyright (C) Scevenate
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt.h>
#include <jwt.h>


static ngx_pool_t *pool = NULL;


ngx_int_t ngx_http_jwt_memory_set_pool(ngx_pool_t *new_pool) {
    pool = new_pool;

    // This function also sets the memory allocator for jansson. This behaviour is documented in jwt.h.
    if (jwt_set_alloc(ngx_http_jwt_memory_alloc, ngx_http_jwt_memory_free) != 0) {
        ngx_log_error(NGX_LOG_ERR, pool->log, 0, "JWT: failed to set memory allocator for JWT");
        return NGX_ERROR;
    }

    return NGX_OK;
}

void *ngx_http_jwt_memory_alloc(size_t size) {
    return ngx_palloc(pool, size);
}

void ngx_http_jwt_memory_free(void *ptr) {
    ngx_pfree(pool, ptr);
}
