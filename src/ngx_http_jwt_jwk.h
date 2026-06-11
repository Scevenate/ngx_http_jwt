
/*
 * Copyright (C) Scevenate
 *
 * JWK / JWKS is cached per cycle for configuration use.
 * It requires separate memory management with manual synchronization with cycles.
 */


#ifndef NGX_HTTP_JWT_JWK_H
#define NGX_HTTP_JWT_JWK_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <jwt.h>

#define NGX_HTTP_JWT_JWKS_TABLE_SIZE 512

jwk_set_t *ngx_http_jwt_jwk_load_jwks_from_file(u_char* path);

ngx_int_t ngx_http_jwt_jwk_cycle_init(ngx_cycle_t *cycle);

#endif /* NGX_HTTP_JWT_JWK_H */