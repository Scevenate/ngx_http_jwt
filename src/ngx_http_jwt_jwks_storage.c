
/*
 * Copyright (C) Scevenate
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt.h>
#include <jwt.h>


#define NGX_HTTP_JWT_JWKS_STORAGE_POOL_SIZE 65536 // 64KB. Hope it's enough.

#define NGX_HTTP_JWT_JWKS_STORAGE_CACHE_AGE_MIN 60000 // 60s
#define NGX_HTTP_JWT_JWKS_STORAGE_CACHE_AGE_MAX 1728000000 // 20d
#define NGX_HTTP_JWT_JWKS_STORAGE_CACHE_AGE_THRESHOLD 30000 // 30s
#define NGX_HTTP_JWT_JWKS_STORAGE_CACHE_AGE_BACKOFF 20000 // 20s


// This structure, and the pointed jwk_set_t, is allocated in shared memory zone.
// The structure is callocated in master process, when the shared memory zone is allocated.
// The actual jwks is updated in worker processes.
typedef struct {
    jwk_set_t *jwks;
    ngx_atomic_t lock;
    ngx_msec_t cache_until; // ngx_current_msec; 0 means never expire / not fetched yet.
} ngx_http_jwt_jwks_storage_jwks_shared_t;

// This structure is allocated in cycle pool, during configuration time,
// when there is only one master process and the shared memory pool is not yet allocated.
struct ngx_http_jwt_jwks_storage_jwks_s {
    ngx_queue_t queue;
    ngx_http_jwt_jwks_storage_type_t type;
    ngx_uint_t hash;
    ngx_str_t full_uri;
    ngx_http_jwt_jwks_storage_jwks_shared_t *shared;
};

struct ngx_http_jwt_jwks_storage_jwks_storage_s {
    ngx_cycle_t *cycle; // For configuration & allocating cycle structure.
    ngx_shm_zone_t *shm_zone; // For allocating shared memory storage.
    ngx_queue_t jwkss; // Of ngx_http_jwt_jwks_storage_jwks_t.
    ngx_event_t *refresh_event;
};

extern ngx_module_t ngx_http_jwt_module;

static ngx_str_t jwks_storage_zone_name = ngx_string("ngx_http_jwt_jwks_storage");

static ngx_int_t ngx_http_jwt_jwks_storage_shared_init(ngx_shm_zone_t *shm_zone, void *data); // Data is ngx_http_jwt_jwks_storage_jwks_storage_t.

// static void ngx_http_jwt_jwks_storage_refresh_event_handler(ngx_event_t *ev);

ngx_http_jwt_jwks_storage_jwks_storage_t *ngx_http_jwt_jwks_storage_init(ngx_conf_t *cf) {
    ngx_http_jwt_jwks_storage_jwks_storage_t *jwks_storage;
    ngx_shm_zone_t *shm_zone;

    jwks_storage = ngx_pcalloc(cf->cycle->pool, sizeof(ngx_http_jwt_jwks_storage_jwks_storage_t));
    if (jwks_storage == NULL) return NULL;
    jwks_storage->cycle = cf->cycle;
    ngx_queue_init(&jwks_storage->jwkss);
    
    shm_zone = ngx_shared_memory_add(cf, &jwks_storage_zone_name, NGX_HTTP_JWT_JWKS_STORAGE_POOL_SIZE, &ngx_http_jwt_module);
    if (shm_zone == NULL) return NULL;
    shm_zone->init = ngx_http_jwt_jwks_storage_shared_init;
    shm_zone->data = jwks_storage;
    shm_zone->noreuse = 1;
    return jwks_storage;
}

ngx_http_jwt_jwks_storage_jwks_t *ngx_http_jwt_jwks_storage_add_jwks(ngx_http_jwt_jwks_storage_jwks_storage_t *jwks_storage, ngx_http_jwt_jwks_storage_type_t type, ngx_str_t uri) {
    ngx_str_t full_uri;
    ngx_uint_t hash;
    ngx_queue_t *q;
    ngx_http_jwt_jwks_storage_jwks_t *storage_jwks;

    // First resolve the full URI.
    switch (type) {
        case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_STRING:
            full_uri.data = ngx_palloc(jwks_storage->cycle->pool, uri.len + 1);
            if (full_uri.data == NULL) return NULL;
            ngx_memcpy(full_uri.data, uri.data, uri.len);
            full_uri.len = uri.len;
            full_uri.data[uri.len] = '\0';
            break;
        case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_FILE:
            full_uri = uri;
            if (ngx_get_full_name(jwks_storage->cycle->pool, &jwks_storage->cycle->prefix, &full_uri) != NGX_OK) {
                return NULL;
            }
            break;
        case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_URL:
        case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_OAUTH:
        case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_OIDC:
        default:
            ngx_log_error(NGX_LOG_ERR, jwks_storage->cycle->log, 0, "JWKS: Invalid JWKS storage type");
            return NULL;
    }

    hash = ngx_hash_key(full_uri.data, full_uri.len);

    for (q = ngx_queue_head(&jwks_storage->jwkss);
         q != ngx_queue_sentinel(&jwks_storage->jwkss);
         q = ngx_queue_next(q)) {
        storage_jwks = ngx_queue_data(q, ngx_http_jwt_jwks_storage_jwks_t, queue);
        if (storage_jwks->hash == hash && ngx_strncmp(storage_jwks->full_uri.data, full_uri.data, full_uri.len) == 0) {
            return storage_jwks;
        }
    }

    storage_jwks = ngx_palloc(jwks_storage->cycle->pool, sizeof(ngx_http_jwt_jwks_storage_jwks_t));
    if (storage_jwks == NULL) return NULL;
    storage_jwks->full_uri = full_uri;
    storage_jwks->type = type;
    storage_jwks->hash = hash;
    storage_jwks->shared = NULL;
    ngx_queue_insert_tail(&jwks_storage->jwkss, &storage_jwks->queue);
    return storage_jwks;
}

static ngx_int_t ngx_http_jwt_jwks_storage_shared_init(ngx_shm_zone_t *shm_zone, void *data) {
    // Memory redirection
    ngx_http_jwt_memory_config_t config, old_config;
    if (ngx_http_jwt_memory_get(&old_config) != NGX_OK) return NGX_ERROR;
    config.pool_type = NGX_HTTP_JWT_MEMORY_POOL_SLAB;
    config.slab_pool = (ngx_slab_pool_t *) shm_zone->shm.addr;
    if (ngx_http_jwt_memory_set(&config) != NGX_OK) return NGX_ERROR;

    ngx_http_jwt_jwks_storage_jwks_storage_t *jwks_storage;
    ngx_slab_pool_t *shpool;
    ngx_http_jwt_jwks_storage_jwks_t *storage_jwks;
    ngx_queue_t *q;

    (void) data; // This value is NULL. It's the reused data from previous pool, and our pool is not reused.
    jwks_storage = shm_zone->data;
    if (jwks_storage == NULL) {
        ngx_http_jwt_memory_set(&old_config);
        return NGX_ERROR;
    }

    shpool = (ngx_slab_pool_t *) shm_zone->shm.addr;

    for (q = ngx_queue_head(&jwks_storage->jwkss);
         q != ngx_queue_sentinel(&jwks_storage->jwkss);
         q = ngx_queue_next(q)) {
        storage_jwks = ngx_queue_data(q, ngx_http_jwt_jwks_storage_jwks_t, queue);
        storage_jwks->shared = ngx_slab_calloc(shpool, sizeof(ngx_http_jwt_jwks_storage_jwks_shared_t));
        if (storage_jwks->shared == NULL) {
            ngx_http_jwt_memory_set(&old_config);
            return NGX_ERROR;
        }
        switch (storage_jwks->type) {
            case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_STRING:
                storage_jwks->shared->jwks = jwks_load_strn(NULL, (char *) storage_jwks->full_uri.data, storage_jwks->full_uri.len);
                if (storage_jwks->shared->jwks == NULL) {
                    ngx_http_jwt_memory_set(&old_config);
                    return NGX_ERROR;
                }
                break;
            case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_FILE:
                storage_jwks->shared->jwks = jwks_load_fromfile(NULL, (char *) storage_jwks->full_uri.data);
                if (storage_jwks->shared->jwks == NULL) {
                    ngx_http_jwt_memory_set(&old_config);
                    return NGX_ERROR;
                }
                break;
            case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_URL:
            case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_OAUTH:
            case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_OIDC:
            default:
                ngx_http_jwt_memory_set(&old_config);
                return NGX_ERROR;
                break;
        }
    }

    if (ngx_http_jwt_memory_set(&old_config) != NGX_OK) return NGX_ERROR;
    return NGX_OK;
}

// ngx_int_t ngx_http_jwt_jwks_storage_setup_timers(ngx_http_jwt_jwks_storage_jwks_storage_t *jwks_storage)

// static void ngx_http_jwt_jwks_storage_refresh_event_handler(ngx_event_t *ev)

jwk_set_t *ngx_http_jwt_jwks_storage_get_jwks(ngx_http_jwt_jwks_storage_jwks_t *jwks) {
    switch (jwks->type) {
        case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_STRING:
        case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_FILE:
            return jwks->shared->jwks;
        case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_URL:
        case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_OAUTH:
        case NGX_HTTP_JWT_JWKS_STORAGE_TYPE_OIDC:
        default:
            return NULL;
    }
}
