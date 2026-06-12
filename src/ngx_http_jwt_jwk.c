
/*
 * Copyright (C) Scevenate
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt_jwk.h>
#include <ngx_http_jwt_memory.h>
#include <jwt.h>


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


ngx_int_t ngx_http_jwt_jwk_cycle_init(ngx_cycle_t *new_cycle) {
    // Free previous cycle
    if (cycle != NULL) {
        ngx_http_jwt_jwk_jwks_node_t *node, *next;

        for (ngx_uint_t i = 0; i < NGX_HTTP_JWT_JWKS_TABLE_SIZE; i++) {
            node = jwks_table.nodes[i];
            while (node != NULL) {
                next = node->next;
                ngx_http_jwt_memory_free(node->path);
                jwks_free(node->jwks);
                ngx_http_jwt_memory_free(node);
                node = next;
            }
            jwks_table.nodes[i] = NULL;
        }
    }
    cycle = new_cycle;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "JWK: cycle initialized");

    return NGX_OK;
}

jwk_set_t *ngx_http_jwt_jwk_load_jwks_from_file(ngx_str_t *path) {
    if (cycle == NULL) {
        return NULL;
    }

    ngx_str_t *full_path;
    ngx_http_jwt_jwk_jwks_node_t *node;
    jwk_set_t *jwks;
    ngx_int_t index;

    full_path = path;

    if (ngx_get_full_name(cycle->pool, &cycle->prefix, full_path) != NGX_OK) {
        return NULL;
    }

    index = ngx_http_jwt_jwk_string_hash(full_path->data);
    node = jwks_table.nodes[index];

    while (node != NULL) {
        if (ngx_strcmp(node->path, full_path->data) == 0) {
            ngx_pfree(cycle->pool, full_path->data);
            return node->jwks;
        }
        node = node->next;
    }

    jwks = jwks_create_fromfile((char *) full_path->data);
    if (jwks == NULL) {
        // JWKS not found is a rejection. The handling relies on upper layer.
        ngx_pfree(cycle->pool, full_path->data);
        return NULL;
    }

    node = ngx_pcalloc(cycle->pool, sizeof(ngx_http_jwt_jwk_jwks_node_t));
    if (node == NULL) {
        ngx_pfree(cycle->pool, full_path->data);
        jwks_free(jwks);
        return NULL;
    }
    node->path = ngx_palloc(cycle->pool, full_path->len + 1);
    if (node->path == NULL) {
        ngx_pfree(cycle->pool, full_path->data);
        jwks_free(jwks);
        ngx_pfree(cycle->pool, node);
        return NULL;
    }
    ngx_memcpy(node->path, full_path->data, full_path->len);
    node->path[full_path->len] = '\0';
    node->jwks = jwks;

    node->next = jwks_table.nodes[index];
    jwks_table.nodes[index] = node;
    return node->jwks;
}
