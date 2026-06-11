
/*
 * Copyright (C) Scevenate
 */


#include <ngx_http_jwt_jwk.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <jwt.h>
#include <string.h>


struct ngx_http_jwt_jwk_jwks_node_s {
    char *path;
    jwk_set_t *jwks;
    struct ngx_http_jwt_jwk_jwks_node_s *next;
};

typedef struct ngx_http_jwt_jwk_jwks_node_s ngx_http_jwt_jwk_jwks_node_t;

typedef struct {
    ngx_http_jwt_jwk_jwks_node_t *nodes[NGX_HTTP_JWT_JWKS_TABLE_SIZE];
} ngx_http_jwt_jwk_jwks_table_t;

static ngx_http_jwt_jwk_jwks_table_t jwks_table = { .nodes = { NULL } };
static ngx_cycle_t *cycle = NULL;

static inline ngx_int_t ngx_http_jwt_jwk_string_hash(u_char* str) {
    return ngx_hash_key( str, strlen((char *) str)) % NGX_HTTP_JWT_JWKS_TABLE_SIZE;
}

ngx_int_t ngx_http_jwt_jwk_cycle_init(ngx_cycle_t *cycle) {
    // Free previous cycle
    if (cycle != NULL) {
        ngx_http_jwt_jwk_jwks_node_t *node, *next;

        for (ngx_uint_t i = 0; i < NGX_HTTP_JWT_JWKS_TABLE_SIZE; i++) {
            node = jwks_table.nodes[i];
            while (node != NULL) {
                next = node->next;
                ngx_free(node->path);
                jwks_free(node->jwks);
                ngx_free(node);
                node = next;
            }
            jwks_table.nodes[i] = NULL;
        }
    }
    cycle = cycle;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "JWK: cycle initialized");

    return NGX_OK;
}

jwk_set_t *ngx_http_jwt_jwk_load_jwks_from_file(u_char* path) {
    if (cycle == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "JWK: attempting to load JWKS from file before cycle initialization");
        return NULL;
    }

    ngx_http_jwt_jwk_jwks_node_t *node;
    jwk_set_t *jwks;
    ngx_int_t index;
    
    index = ngx_http_jwt_jwk_string_hash(path);
    node = jwks_table.nodes[index];

    while (node != NULL) {
        if (ngx_strcmp(node->path, (char *) path) == 0) {
            return node->jwks;
        }
        node = node->next;
    }
    
    jwks = jwks_create_fromfile((char *) path);
    if (jwks == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "JWK: could not create JWKS from file");
        return NULL;
    }

    node = ngx_calloc(sizeof(ngx_http_jwt_jwk_jwks_node_t), NULL);
    if (node == NULL) {
        jwks_free(jwks);
        return NULL;
    }
    node->path = ngx_calloc(strlen((char *) path) + 1, NULL);
    if (node->path == NULL) {
        jwks_free(jwks);
        ngx_free(node);
        return NULL;
    }
    strcpy(node->path, (char *) path);
    node->jwks = jwks;

    node->next = jwks_table.nodes[index];
    jwks_table.nodes[index] = node;
    return node->jwks;
}
