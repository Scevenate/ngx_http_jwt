
/*
 * Copyright (C) Scevenate
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt.h>
#include <jwt.h>


static ngx_http_jwt_memory_config_t ngx_http_jwt_memory_config = {
    .pool_type = NGX_HTTP_JWT_MEMORY_POOL_UNSET
};

void *ngx_http_jwt_memory_alloc(size_t size) {
    switch (ngx_http_jwt_memory_config.pool_type) {
        case NGX_HTTP_JWT_MEMORY_POOL_REGULAR:
            return ngx_palloc(ngx_http_jwt_memory_config.pool, size);
        case NGX_HTTP_JWT_MEMORY_POOL_SLAB:
            return ngx_slab_alloc(ngx_http_jwt_memory_config.slab_pool, size);
        default:
            return NULL;
    }
}

void ngx_http_jwt_memory_free(void *ptr) {
    switch (ngx_http_jwt_memory_config.pool_type) {
        case NGX_HTTP_JWT_MEMORY_POOL_REGULAR:
            ngx_pfree(ngx_http_jwt_memory_config.pool, ptr);
            break;
        case NGX_HTTP_JWT_MEMORY_POOL_SLAB:
            ngx_slab_free(ngx_http_jwt_memory_config.slab_pool, ptr);
            break;
        default:
            break;
    }
}

ngx_int_t ngx_http_jwt_memory_set(ngx_http_jwt_memory_config_t *config) {
    ngx_http_jwt_memory_config = *config;

    // This function also sets the memory allocator for jansson. This behaviour is documented in jwt.h.
    if (jwt_set_alloc(ngx_http_jwt_memory_alloc, ngx_http_jwt_memory_free) != 0) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

ngx_int_t ngx_http_jwt_memory_get(ngx_http_jwt_memory_config_t *config) {
    *config = ngx_http_jwt_memory_config;
    return NGX_OK;
}
