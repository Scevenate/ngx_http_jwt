
/*
 * Copyright (C) Scevenate
 */


#include <ngx_http_jwt_jwk.h>
#include <ngx_config.h>
#include <ngx_core.h>
#include <jwt.h>
#include <string.h>


typedef struct {
    char *path;
    jwk_set_t *jwks;
    struct ngx_http_jwt_jwks_node_t *next;
} ngx_http_jwt_jwk_jwks_node_t;

typedef struct {
    ngx_http_jwt_jwk_jwks_node_t *nodes[NGX_HTTP_JWT_JWKS_TABLE_SIZE];
} ngx_http_jwt_jwk_jwks_table_t;

static ngx_http_jwt_jwk_jwks_table_t jwks_table = { .nodes = { NULL } };
static ngx_flag_t initialized = 0;

static inline ngx_int_t ngx_http_jwt_jwk_string_hash(u_char* str) {
    return ngx_hash_key( str, strlen((char *) str)) % NGX_HTTP_JWT_JWKS_TABLE_SIZE;
}

ngx_int_t ngx_http_jwt_jwk_cycle_init() {
    // Free previous cycle
    if (initialized) {
        ngx_http_jwt_jwk_jwks_node_t *node, *next;

        for (ngx_uint_t i = 0; i < NGX_HTTP_JWT_JWKS_TABLE_SIZE; i++) {
            node = (ngx_http_jwt_jwk_jwks_node_t *) jwks_table.nodes[i]->next;
            while (node != NULL) {
                next = (ngx_http_jwt_jwk_jwks_node_t *) node->next;
                ngx_free(node->path);
                jwks_free(node->jwks);
                ngx_free(node);
                node = next;
            }
            jwks_table.nodes[i] = NULL;
        }
    }
    initialized = 1;

    return NGX_OK;
}

jwk_set_t *ngx_http_jwt_jwk_load_jwks_from_file(u_char* path) {
    ngx_http_jwt_jwk_jwks_node_t *node;
    jwk_set_t *jwks;
    ngx_int_t index;
    
    index = ngx_http_jwt_jwk_string_hash(path);
    node = jwks_table.nodes[index];

    while (node != NULL) {
        if (ngx_strcmp(node->path, (char *) path) == 0) {
            return node->jwks;
        }
        node = (ngx_http_jwt_jwk_jwks_node_t *) node->next;
    }
    
    jwks = jwks_create_fromfile((char *) path);
    if (jwks == NULL) {
        return NULL;
    }

    node = ngx_alloc(sizeof(ngx_http_jwt_jwk_jwks_node_t), NULL);
    node->path = ngx_alloc(strlen((char *) path) + 1, NULL);
    strcpy(node->path, (char *) path);
    node->jwks = jwks;
    node->next = NULL;
    return node->jwks;
}