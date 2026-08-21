
/*
 * Copyright (C) Scevenate
 */


#ifndef NGX_HTTP_JWT_JWKS_STORAGE_H
#define NGX_HTTP_JWT_JWKS_STORAGE_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jwt.h>


typedef enum {
    NGX_HTTP_JWT_JWKS_STORAGE_TYPE_STRING,
    NGX_HTTP_JWT_JWKS_STORAGE_TYPE_FILE,
    // Not implemented:
    NGX_HTTP_JWT_JWKS_STORAGE_TYPE_URL,
    NGX_HTTP_JWT_JWKS_STORAGE_TYPE_OAUTH,
    NGX_HTTP_JWT_JWKS_STORAGE_TYPE_OIDC,
} ngx_http_jwt_jwks_storage_type_t;

typedef struct ngx_http_jwt_jwks_storage_jwks_storage_s ngx_http_jwt_jwks_storage_jwks_storage_t;

typedef struct ngx_http_jwt_jwks_storage_jwks_s ngx_http_jwt_jwks_storage_jwks_t;


// Initializes a new opaque JWKS storage object.
// The storage internally allocates itself in a shared memory zone.
// Should only be called once in main conf creation. (Shared memory zone has global unique name.)
// Returns NULL on error.
ngx_http_jwt_jwks_storage_jwks_storage_t *ngx_http_jwt_jwks_storage_init(ngx_conf_t *cf);

// Add JWKS to temporary cycle registeration structure at configuration time.
// The actual JWKS will be populated after configuration parsing, when the shared memory zone is allocated in master process. (before postconfiguration)
// The uri data is borrowed, the storage keeps an internal copy.
// Relative file path is expanded by cycle prefix, all URI are treated case sensitively.
// Returns NULL on error.
ngx_http_jwt_jwks_storage_jwks_t *ngx_http_jwt_jwks_storage_add_jwks(ngx_http_jwt_jwks_storage_jwks_storage_t *jwks_storage, ngx_http_jwt_jwks_storage_type_t type, ngx_str_t uri);

// Get JWKS from storage JWKS object.
// Returns NULL if jwks expired.
jwk_set_t *ngx_http_jwt_jwks_storage_get_jwks(ngx_http_jwt_jwks_storage_jwks_t *jwks);

// ngx_int_t ngx_http_jwt_jwks_storage_setup_timers(ngx_http_jwt_jwks_storage_jwks_storage_t *jwks_storage)

#endif /* NGX_HTTP_JWT_JWKS_STORAGE_H */
