
/*
 * Copyright (C) Scevenate
 *
 * JWK / JWKS is cached per cycle for configuration use.
 * It requires separate memory management with manual synchronization with cycles.
 * Note that each process has its own storage. Configuration time keys are copied from master process.
 */


#ifndef NGX_HTTP_JWT_JWK_H
#define NGX_HTTP_JWT_JWK_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <jwt.h>

#define NGX_HTTP_JWT_JWKS_TABLE_SIZE 512

ngx_int_t ngx_http_jwt_jwk_cycle_init(ngx_cycle_t *new_cycle);

// Load JWKS from file. Relative path is expanded by cycle prefix.
// Path is case sensitive. Being overly sensitive does not cause harm, so we're simplifying it.
jwk_set_t *ngx_http_jwt_jwk_load_jwks_from_file(ngx_str_t *path);

#endif /* NGX_HTTP_JWT_JWK_H */
