
/*
 * Copyright (C) Scevenate
 */


#include "ngx_conf_file.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt.h>
#include <jansson.h>
#include <jwt.h>


typedef struct {
    ngx_http_jwt_jwks_storage_jwks_storage_t *jwks_storage;
} ngx_http_jwt_main_conf_t;

typedef enum {
    NGX_HTTP_JWT_LOCATION_UNSET = -1,
    NGX_HTTP_JWT_LOCATION_OFF,
    NGX_HTTP_JWT_LOCATION_BEARER,
    NGX_HTTP_JWT_LOCATION_HEADER,
    NGX_HTTP_JWT_LOCATION_COOKIE,
    NGX_HTTP_JWT_LOCATION_QUERY,
} ngx_http_jwt_location_type_t;

typedef struct {
    ngx_http_jwt_location_type_t type;
    ngx_str_t key;
} ngx_http_jwt_location_t;

typedef enum {
    NGX_HTTP_JWT_VALIDATE_EQUALS,
    NGX_HTTP_JWT_VALIDATE_EXP,
    NGX_HTTP_JWT_VALIDATE_NBF,
    NGX_HTTP_JWT_VALIDATE_IN
} ngx_http_jwt_validate_predicate_t;

typedef struct {
    ngx_str_t name;
    json_t *value;
    ngx_http_jwt_validate_predicate_t predicate;
    ngx_queue_t queue;
} ngx_http_jwt_validate_claim_t;

typedef struct {
    ngx_queue_t claims;
} ngx_http_jwt_validate_t;

typedef struct {
    ngx_str_t claim_name;
    ngx_str_t header_name;
    ngx_flag_t optional;
    ngx_queue_t queue;
} ngx_http_jwt_extract_claim_t;

typedef struct {
    ngx_queue_t claims;
} ngx_http_jwt_extract_t;

typedef struct {
    ngx_http_jwt_jwks_storage_jwks_t *jwks;
    ngx_queue_t queue;
} ngx_http_jwt_loaded_jwks_t;

typedef struct {
    ngx_http_jwt_location_t location;
    ngx_queue_t loaded_jwkss;
    ngx_http_jwt_validate_t validate;
    ngx_http_jwt_extract_t extract;
    ngx_int_t error_code;
} ngx_http_jwt_loc_conf_t;

typedef struct {
    ngx_http_request_t *r;
    ngx_http_jwt_request_transaction_t *transaction; // Used for postponed apply
    ngx_flag_t internal_server_error; // internal_server_error ? NGX_HTTP_INTERNAL_SERVER_ERROR : jcf_loc_conf->error_code
} ngx_http_jwt_request_handler_checker_callback_ctx_t;

static ngx_int_t ngx_http_jwt_preconfiguration(ngx_conf_t *cf);

static char *ngx_conf_set_location_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_set_load_jwks_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_set_validate_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_set_extract_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_check_error_code_slot(ngx_conf_t *cf, void *post, void *np);
static ngx_conf_post_t ngx_conf_check_error_code_slot_post = {
    ngx_conf_check_error_code_slot
};

static void *ngx_http_jwt_create_main_conf(ngx_conf_t *cf);
static char *ngx_http_jwt_init_main_conf(ngx_conf_t *cf, void *conf);

static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);

static ngx_int_t ngx_http_jwt_postconfiguration(ngx_conf_t *cf);

static ngx_int_t ngx_http_jwt_init_process(ngx_cycle_t *cycle);

static ngx_int_t ngx_http_jwt_request_handler(ngx_http_request_t *r);
static int ngx_http_jwt_request_handler_checker_callback(jwt_t *jwt, jwt_config_t *config);

static ngx_command_t  ngx_http_jwt_commands[] = {
    { ngx_string("jwt"),
    NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
    ngx_conf_set_location_slot,
    NGX_HTTP_LOC_CONF_OFFSET,
    offsetof(ngx_http_jwt_loc_conf_t, location),
    NULL },

  { ngx_string("jwt_load_jwks"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_load_jwks_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, loaded_jwkss),
      NULL },

  { ngx_string("jwt_validate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
      ngx_conf_set_validate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, validate),
      NULL },

  { ngx_string("jwt_extract"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE23,
      ngx_conf_set_extract_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, extract),
      NULL },

  { ngx_string("jwt_error_code"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_num_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, error_code),
      &ngx_conf_check_error_code_slot_post },

  ngx_null_command
};

static ngx_http_module_t  ngx_http_jwt_module_ctx = {
    ngx_http_jwt_preconfiguration,        /* preconfiguration */
    ngx_http_jwt_postconfiguration,       /* postconfiguration */

    ngx_http_jwt_create_main_conf,       /* create main configuration */
    ngx_http_jwt_init_main_conf,         /* init main configuration */

    NULL,                                 /* create server configuration */
    NULL,                                 /* merge server configuration */

    ngx_http_jwt_create_loc_conf,         /* create location configuration */
    ngx_http_jwt_merge_loc_conf           /* merge location configuration */
};

ngx_module_t  ngx_http_jwt_module = {
    NGX_MODULE_V1,
    &ngx_http_jwt_module_ctx,              /* module context */
    ngx_http_jwt_commands,                 /* module directives */
    NGX_HTTP_MODULE,                       /* module type */
    NULL,                                  /* init master */
    NULL,                                  /* init module */
    ngx_http_jwt_init_process,            /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_jwt_preconfiguration(ngx_conf_t *cf) {
    ngx_http_jwt_memory_config_t config;
    config.pool_type = NGX_HTTP_JWT_MEMORY_POOL_REGULAR;
    config.pool = (ngx_pool_t *) cf->cycle->pool;
    return ngx_http_jwt_memory_set(&config);
}

static char *ngx_conf_set_location_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char* p = conf;

    ngx_http_jwt_location_t *field;
    ngx_int_t nelts;
    ngx_str_t *value;
    ngx_conf_post_t *post;

    field = (ngx_http_jwt_location_t *) (p + cmd->offset);
    nelts = cf->args->nelts;
    value = cf->args->elts;

    if (field->type != NGX_HTTP_JWT_LOCATION_UNSET) return "is duplicate";

    switch (value[1].data[0]) {
        case 'o':
            if (ngx_strcasecmp(value[1].data, (u_char *) "off") != 0) return "got invalid type";
            if (nelts != 2) return "expected 1 argument for off type";
            field->type = NGX_HTTP_JWT_LOCATION_OFF;
            break;
        case 'b':
            if (ngx_strcasecmp(value[1].data, (u_char *) "bearer") != 0)
                return "got invalid type";
            if (nelts != 2) return "expected 1 argument for bearer type";
            field->type = NGX_HTTP_JWT_LOCATION_BEARER;
            break;
        case 'h':
            if (ngx_strcasecmp(value[1].data, (u_char *) "header") != 0) return "got invalid type";
            if (nelts != 3) return "expected 2 arguments for header type";
            field->type = NGX_HTTP_JWT_LOCATION_HEADER;
            field->key = value[2];
            break;
        case 'c':
            if (ngx_strcasecmp(value[1].data, (u_char *) "cookie") != 0) return "got invalid type";
            if (nelts != 3) return "expected 2 arguments for cookie type";
            field->type = NGX_HTTP_JWT_LOCATION_COOKIE;
            field->key = value[2];
            break;
        case 'q':
            if (ngx_strcasecmp(value[1].data, (u_char *) "query") != 0) return "got invalid type";
            if (nelts != 3) return "expected 2 arguments for query type";
            field->type = NGX_HTTP_JWT_LOCATION_QUERY;
            field->key = value[2];
            break;
        default:
            return "got invalid type";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}

static char *ngx_conf_set_load_jwks_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char *p = conf;

    ngx_http_jwt_main_conf_t *jwt_mc = ngx_http_conf_get_module_main_conf(cf, ngx_http_jwt_module);
    if (jwt_mc == NULL) {
        return "failed to get main configuration";
    }

    ngx_queue_t *field;
    ngx_http_jwt_jwks_storage_jwks_t *jwks;
    ngx_str_t *value;
    ngx_conf_post_t *post;
    
    field = (ngx_queue_t *) (p + cmd->offset);

    value = cf->args->elts;

    if (value[1].len < 3) return "got invalid JWKS source";

    switch (value[1].data[3]) {
        case 'i':
            if (ngx_strcmp(value[1].data, "string") != 0) return "got invalid JWKS source";
            jwks = ngx_http_jwt_jwks_storage_add_jwks(jwt_mc->jwks_storage, NGX_HTTP_JWT_JWKS_STORAGE_TYPE_STRING, value[2]);
            if (jwks == NULL) return "failed to load JWKS from string";
            break;
        case 'e':
            if (ngx_strcmp(value[1].data, "file") != 0) return "got invalid JWKS source";
            jwks = ngx_http_jwt_jwks_storage_add_jwks(jwt_mc->jwks_storage, NGX_HTTP_JWT_JWKS_STORAGE_TYPE_FILE, value[2]);
            if (jwks == NULL) return "failed to load JWKS from file";
            break;
        case 0:
            if (ngx_strcmp(value[1].data, "url") != 0) return "got invalid JWKS source";
            jwks = ngx_http_jwt_jwks_storage_add_jwks(jwt_mc->jwks_storage, NGX_HTTP_JWT_JWKS_STORAGE_TYPE_URL, value[2]);
            if (jwks == NULL) return "failed to load JWKS from URL";
            break;
        case 't':
            if (ngx_strcmp(value[1].data, "oauth") != 0) return "got invalid JWKS source";
            jwks = ngx_http_jwt_jwks_storage_add_jwks(jwt_mc->jwks_storage, NGX_HTTP_JWT_JWKS_STORAGE_TYPE_OAUTH, value[2]);
            if (jwks == NULL) return "failed to load JWKS from OAuth";
            break;
        case 'c':
            if (ngx_strcmp(value[1].data, "oidc") != 0) return "got invalid JWKS source";
            jwks = ngx_http_jwt_jwks_storage_add_jwks(jwt_mc->jwks_storage, NGX_HTTP_JWT_JWKS_STORAGE_TYPE_OIDC, value[2]);
            if (jwks == NULL) return "failed to load JWKS from OIDC";
            break;
        default:
            return "got invalid JWKS source";
    }

    ngx_queue_t *q;
    ngx_http_jwt_loaded_jwks_t *loaded_jwks;
    for (q = ngx_queue_head(field);
         q != ngx_queue_sentinel(field);
         q = ngx_queue_next(q)) {
        loaded_jwks = ngx_queue_data(q, ngx_http_jwt_loaded_jwks_t, queue);
        if (loaded_jwks->jwks == jwks) {
            return "is duplicate";
        }
    }

    loaded_jwks = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_loaded_jwks_t));
    if (loaded_jwks == NULL) return NGX_CONF_ERROR;

    loaded_jwks->jwks = jwks;
    ngx_queue_insert_tail(field, &loaded_jwks->queue);

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}

static char *ngx_conf_set_validate_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char* p = conf;

    ngx_http_jwt_validate_t *field;
    ngx_str_t *value;
    ngx_conf_post_t *post;

    field = (ngx_http_jwt_validate_t *) (p + cmd->offset);
    value = cf->args->elts;

    ngx_queue_t *q;
    ngx_http_jwt_validate_claim_t *claim;
    json_t *json;

    if (value[1].len == 0 || value[1].len >= NGX_HTTP_JWT_CLAIM_NAME_LEN_MAX) {
        return "got invalid claim name";
    }

    if (value[3].len == 0 || value[3].len >= NGX_HTTP_JWT_CLAIM_VALUE_LEN_MAX) {
        return "got invalid claim value";
    }

    for (q = ngx_queue_head(&field->claims);
         q != ngx_queue_sentinel(&field->claims);
         q = ngx_queue_next(q)) {
        if (ngx_strcmp((ngx_queue_data(q, ngx_http_jwt_validate_claim_t, queue))->name.data,
            value[1].data) == 0) {
            return "is duplicate";
        }
    }

    claim = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_validate_claim_t));
    if (claim == NULL) return NGX_CONF_ERROR;
    json = json_loads((const char *) value[3].data,
        JSON_DECODE_ANY | JSON_REJECT_DUPLICATES, NULL);
    if (json == NULL) return "got invalid claim value";

    claim->name = value[1];
    claim->value = json;

    switch (value[2].data[0]) {
        case '=':
            if (ngx_strcmp(value[2].data, "==") != 0) return "got invalid predicate";
            claim->predicate = NGX_HTTP_JWT_VALIDATE_EQUALS;
            break;
        case 'i':
            if (ngx_strcmp(value[2].data, "in") != 0) return "got invalid predicate";
            claim->predicate = NGX_HTTP_JWT_VALIDATE_IN;
            if (!json_is_array(claim->value)) return "got invalid claim value";
            break;
        case 'e':
            if (ngx_strcmp(value[2].data, "exp") != 0) return "got invalid predicate";
            claim->predicate = NGX_HTTP_JWT_VALIDATE_EXP;
            if (!json_is_number(json)) return "got invalid claim value";
            if (json_number_value(json) < 0 || json_number_value(json) > NGX_HTTP_JWT_LEEWAY_MAX) return "got invalid claim value";
            break;
        case 'n':
            if (ngx_strcmp(value[2].data, "nbf") != 0) return "got invalid predicate";
            claim->predicate = NGX_HTTP_JWT_VALIDATE_NBF;
            if (!json_is_number(json)) return "got invalid claim value";
            if (json_number_value(json) < 0 || json_number_value(json) > NGX_HTTP_JWT_LEEWAY_MAX) return "got invalid claim value";
            break;
        default:
            return "got invalid predicate";
    }

    ngx_queue_insert_tail(&field->claims, &claim->queue);

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}

static char *ngx_conf_set_extract_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char* p = conf;

    ngx_http_jwt_extract_t *field;
    ngx_int_t nelts;
    ngx_str_t *value;
    ngx_conf_post_t *post;

    field = (ngx_http_jwt_extract_t *) (p + cmd->offset);
    nelts = cf->args->nelts;
    value = cf->args->elts;

    if (value[1].len == 0 || value[1].len >= NGX_HTTP_JWT_CLAIM_NAME_LEN_MAX) {
        return "got invalid claim name";
    }

    if (value[2].len == 0 || value[2].len >= NGX_HTTP_JWT_HEADER_NAME_LEN_MAX) {
        return "got invalid header name";
    }

    if (nelts == 4 && ngx_strcmp(value[3].data, "optional") != 0) {
        return "expected third argument to be 'optional'";
    }

    ngx_queue_t *q;
    ngx_http_jwt_extract_claim_t *claim;

    for (q = ngx_queue_head(&field->claims);
         q != ngx_queue_sentinel(&field->claims);
         q = ngx_queue_next(q)) {
        claim = ngx_queue_data(q, ngx_http_jwt_extract_claim_t, queue);
        if (ngx_strcmp(claim->claim_name.data, value[1].data) == 0
         || ngx_strcasecmp(claim->header_name.data, value[2].data) == 0) {
            return "is duplicate";
        }
    }

    ngx_uint_t i;

    for (i = 0; i < value[2].len; i++) {
        if ((value[2].data[i] >= '0' && value[2].data[i] <= '9')
            || (value[2].data[i] >= 'A' && value[2].data[i] <= 'Z')
            || (value[2].data[i] >= 'a' && value[2].data[i] <= 'z')
            || value[2].data[i] == '-'
            || value[2].data[i] == '_')
        {
            continue;
        }
        return "got invalid header name";
    }

    claim = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_extract_claim_t));
    if (claim == NULL) {
        return NGX_CONF_ERROR;
    }

    claim->claim_name = value[1];
    claim->header_name = value[2];
    claim->optional = nelts == 4 ? 1 : 0;

    ngx_queue_insert_tail(&field->claims, &claim->queue);

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}

static char *ngx_conf_check_error_code_slot(ngx_conf_t *cf, void *post, void *np) {
    ngx_int_t *error_code = np;

    if (*error_code < 300 || *error_code > 599) {
        return "Invalid error code for jwt_error_code";
    }

    return NGX_CONF_OK;
}


static void *ngx_http_jwt_create_main_conf(ngx_conf_t *cf) {
    ngx_http_jwt_main_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_main_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->jwks_storage = ngx_http_jwt_jwks_storage_init(cf);
    if (conf->jwks_storage == NULL) {
        return NULL;
    }

    return conf;
}

static char *ngx_http_jwt_init_main_conf(ngx_conf_t *cf, void *conf) {
    return NGX_CONF_OK;
}

static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_jwt_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->location.type = NGX_HTTP_JWT_LOCATION_UNSET;
    ngx_queue_init(&conf->loaded_jwkss);
    ngx_queue_init(&conf->validate.claims);
    ngx_queue_init(&conf->extract.claims);
    conf->error_code = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_jwt_loc_conf_t *prev = parent;
    ngx_http_jwt_loc_conf_t *conf = child;

    if (conf->location.type == NGX_HTTP_JWT_LOCATION_UNSET) {
        conf->location.key = prev->location.key;
    }
    ngx_conf_merge_value(conf->location.type, prev->location.type, NGX_HTTP_JWT_LOCATION_UNSET);
    ngx_conf_merge_value(conf->error_code, prev->error_code, NGX_HTTP_JWT_DEFAULT_ERROR_CODE);

    // Merge queues. Note that prev is shared and not stolen.

    ngx_queue_t *q_prev, *q_conf;
    ngx_http_jwt_validate_claim_t *validate_claim_prev, *validate_claim_conf;
    ngx_http_jwt_extract_claim_t *extract_claim_prev, *extract_claim_conf;
    ngx_http_jwt_loaded_jwks_t *loaded_jwks_prev, *loaded_jwks_conf;
    ngx_flag_t found;

    for (q_prev = ngx_queue_head(&prev->validate.claims);
         q_prev != ngx_queue_sentinel(&prev->validate.claims);
         q_prev = ngx_queue_next(q_prev)) {
        validate_claim_prev = ngx_queue_data(q_prev, ngx_http_jwt_validate_claim_t, queue);
        found = 0;
        for (q_conf = ngx_queue_head(&conf->validate.claims);
             q_conf != ngx_queue_sentinel(&conf->validate.claims);
             q_conf = ngx_queue_next(q_conf)) {
            validate_claim_conf = ngx_queue_data(q_conf, ngx_http_jwt_validate_claim_t, queue);
            if (ngx_strcmp(validate_claim_prev->name.data, validate_claim_conf->name.data) == 0) {
                found = 1;
                break;
            }
        }
        if (found) continue;

        validate_claim_conf = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_validate_claim_t));
        if (validate_claim_conf == NULL) return NGX_CONF_ERROR;

        validate_claim_conf->name = validate_claim_prev->name;
        validate_claim_conf->predicate = validate_claim_prev->predicate;
        validate_claim_conf->value = validate_claim_prev->value;

        ngx_queue_insert_tail(&conf->validate.claims, &validate_claim_conf->queue);
    }

    for (q_prev = ngx_queue_head(&prev->extract.claims);
         q_prev != ngx_queue_sentinel(&prev->extract.claims);
         q_prev = ngx_queue_next(q_prev)) {
        extract_claim_prev = ngx_queue_data(q_prev, ngx_http_jwt_extract_claim_t, queue);
        found = 0;
        for (q_conf = ngx_queue_head(&conf->extract.claims);
             q_conf != ngx_queue_sentinel(&conf->extract.claims);
             q_conf = ngx_queue_next(q_conf)) {
            extract_claim_conf = ngx_queue_data(q_conf, ngx_http_jwt_extract_claim_t, queue);
            if (ngx_strcmp(extract_claim_prev->claim_name.data, extract_claim_conf->claim_name.data) == 0) {
                found = 1;
                break;
            }
        }
        if (found) continue;

        extract_claim_conf = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_extract_claim_t));

        if (extract_claim_conf == NULL) return NGX_CONF_ERROR;

        extract_claim_conf->claim_name = extract_claim_prev->claim_name;
        extract_claim_conf->header_name = extract_claim_prev->header_name;
        extract_claim_conf->optional = extract_claim_prev->optional;

        ngx_queue_insert_tail(&conf->extract.claims, &extract_claim_conf->queue);
    }

    // Header collision check

    for (q_prev = ngx_queue_head(&conf->extract.claims);
         q_prev != ngx_queue_sentinel(&conf->extract.claims);
         q_prev = ngx_queue_next(q_prev)) {
        extract_claim_prev = ngx_queue_data(q_prev, ngx_http_jwt_extract_claim_t, queue);
        for (q_conf = ngx_queue_head(&conf->extract.claims);
             q_conf != ngx_queue_sentinel(&conf->extract.claims);
             q_conf = ngx_queue_next(q_conf)) {
            extract_claim_conf = ngx_queue_data(q_conf, ngx_http_jwt_extract_claim_t, queue);
            if (extract_claim_prev != extract_claim_conf
             && ngx_strcasecmp(extract_claim_prev->header_name.data,
                extract_claim_conf->header_name.data) == 0) {
                return "got duplicate headers";
            }
        }
    }


    for (q_prev = ngx_queue_head(&prev->loaded_jwkss);
         q_prev != ngx_queue_sentinel(&prev->loaded_jwkss);
         q_prev = ngx_queue_next(q_prev)) {
        loaded_jwks_prev = ngx_queue_data(q_prev, ngx_http_jwt_loaded_jwks_t, queue);
        found = 0;
        for (q_conf = ngx_queue_head(&conf->loaded_jwkss);
             q_conf != ngx_queue_sentinel(&conf->loaded_jwkss);
             q_conf = ngx_queue_next(q_conf)) {
            loaded_jwks_conf = ngx_queue_data(q_conf, ngx_http_jwt_loaded_jwks_t, queue);
            if (loaded_jwks_prev->jwks == loaded_jwks_conf->jwks) {
                found = 1;
                break;
            }
        }
        if (found) continue;

        loaded_jwks_conf = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_loaded_jwks_t));
        if (loaded_jwks_conf == NULL) return NGX_CONF_ERROR;

        loaded_jwks_conf->jwks = loaded_jwks_prev->jwks;
        ngx_queue_insert_tail(&conf->loaded_jwkss, &loaded_jwks_conf->queue);
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_jwt_postconfiguration(ngx_conf_t *cf) {
    ngx_http_handler_pt *handler;
    ngx_http_core_main_conf_t *cmcf;
    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);

    handler = ngx_array_push(&cmcf->phases[NGX_HTTP_ACCESS_PHASE].handlers);
    if (handler == NULL) {
        return NGX_ERROR;
    }

    *handler = ngx_http_jwt_request_handler;

    return NGX_OK;
}

static ngx_int_t ngx_http_jwt_init_process(ngx_cycle_t *cycle) {
    return NGX_OK;
    /** Do not uncomment this, will make error log explode to gigabytes in seconds
    ngx_http_jwt_main_conf_t *jwtmcf;
    jwtmcf = (ngx_http_jwt_main_conf_t *) ngx_http_cycle_get_module_main_conf(cycle, ngx_http_jwt_module);
    if (jwtmcf == NULL) return NGX_ERROR;
    return ngx_http_jwt_jwks_storage_setup_timers(jwtmcf->jwks_storage);
    */
}

static ngx_int_t ngx_http_jwt_request_handler(ngx_http_request_t *r) {
    ngx_http_jwt_memory_config_t config;
    config.pool_type = NGX_HTTP_JWT_MEMORY_POOL_REGULAR;
    config.pool = (ngx_pool_t *) r->pool;
    if (ngx_http_jwt_memory_set(&config) != NGX_OK) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Cannot intiailize memory redirection");
        return NGX_ERROR;
    }

    ngx_http_jwt_loc_conf_t            *jwt_lcf;

    jwt_lcf = r->loc_conf[ngx_http_jwt_module.ctx_index];

    // Fetch & filter token

    ngx_uint_t i;
    ngx_list_part_t *part;
    ngx_table_elt_t *header;
    ngx_str_t value;
    ngx_str_t token;

    switch (jwt_lcf->location.type) {
        case NGX_HTTP_JWT_LOCATION_UNSET:
        case NGX_HTTP_JWT_LOCATION_OFF:
            return NGX_DECLINED;
        case NGX_HTTP_JWT_LOCATION_BEARER:
            header = r->headers_in.authorization;
            // 10 is sort of random, just not segv and not too big
            if (header == NULL || header->value.len <= 10) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: token not found");
                return NGX_HTTP_JWT_DEFAULT_ERROR_CODE;
            }
            token.len = header->value.len - (sizeof("Bearer ") - 1);
            token.data = ngx_palloc(r->pool, header->value.len - (sizeof("Bearer ") - 2));
            if (token.data == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: Cannot initialize token");
            }
            ngx_memcpy(token.data, header->value.data + (sizeof("Bearer ") - 1), header->value.len - (sizeof("Bearer") - 2));
            break;
        case NGX_HTTP_JWT_LOCATION_HEADER:
            token.data = NULL;
            part = &r->headers_in.headers.part;
            header = part->elts;
            for (i = 0;;) {
                if (i >= part->nelts) {
                    if (part->next == NULL) {
                        break;
                    }

                    part = part->next;
                    header = part->elts;
                    i = 0;
                    continue;
                }

                if (header[i].hash != 0
                && header[i].key.len == jwt_lcf->location.key.len
                && ngx_strncasecmp(header[i].key.data, jwt_lcf->location.key.data,
                    jwt_lcf->location.key.len) == 0)
                {
                    token.len = header[i].value.len;
                    token.data = ngx_palloc(r->pool, header[i].value.len + 1);
                    if (token.data == NULL) {
                        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: Cannot initialize token");
                    }
                    ngx_memcpy(token.data, header[i].value.data, header[i].value.len + 1);
                    break;
                }
                i++;
            }
            if (token.data == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: token not found");
                return NGX_HTTP_JWT_DEFAULT_ERROR_CODE;
            }
            break;
        case NGX_HTTP_JWT_LOCATION_COOKIE:
            value.data = NULL;
            ngx_http_parse_cookie_lines(r, r->headers_in.cookie,
                &jwt_lcf->location.key, &value);
            if (value.data == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: token not found");
                return NGX_HTTP_JWT_DEFAULT_ERROR_CODE;
            }
            token.len = value.len;
            token.data = ngx_palloc(r->pool, value.len + 1);
            if (token.data == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: Cannot initialize token");
            }
            ngx_memcpy(token.data, value.data, value.len);
            token.data[value.len] = '\0';
            break;
        case NGX_HTTP_JWT_LOCATION_QUERY:
            value.data = NULL;
            ngx_http_arg(r, jwt_lcf->location.key.data,
                jwt_lcf->location.key.len, &value);
            if (value.data == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: token not found");
                return NGX_HTTP_JWT_DEFAULT_ERROR_CODE;
            }
            token.len = value.len;
            token.data = ngx_palloc(r->pool, value.len + 1);
            if (token.data == NULL) {
                ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: Cannot initialize token");
            }
            ngx_memcpy(token.data, value.data, value.len);
            token.data[value.len] = '\0';
            break;
        default:
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "Invalid configuration location type (should not happen)");
            return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: Fetched token \"%V\"", &token);

    // Transaction

    ngx_http_jwt_request_transaction_t *transaction;

    transaction = ngx_http_jwt_request_transaction_init(r);
    if (transaction == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: Cannot initialize transaction");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // Checker & ctx / callback

    jwt_checker_t *checker;
    ngx_http_jwt_request_handler_checker_callback_ctx_t ctx;
    
    ctx.r = r;
    ctx.transaction = transaction;
    ctx.internal_server_error = 0;

    checker = jwt_checker_new();
    if (checker == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: Cannot initialize checker");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // By default, the checker checks exp / nbf claims. Disabling it here.
    // We'll use custom exp / nbf check in callback for clearer validation responsibility boundary and better performance (use nginx cached time).
    if (jwt_checker_time_leeway(checker, JWT_CLAIM_EXP, -1) != 0
     || jwt_checker_time_leeway(checker, JWT_CLAIM_NBF, -1) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: Cannot disable libjwt checks");
        jwt_checker_free(checker);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    jwt_checker_setcb(checker, ngx_http_jwt_request_handler_checker_callback,
                      &ctx);

    // Verify

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: All set, validating token");
    if (jwt_checker_verify(checker, (const char*) token.data) != 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: authorization failed");
        jwt_checker_free(checker);
        return ctx.internal_server_error ? NGX_HTTP_INTERNAL_SERVER_ERROR : jwt_lcf->error_code;
    }

    jwt_checker_free(checker);

    // Apply transaction

    if (ngx_http_jwt_request_transaction_apply(transaction) != NGX_OK) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: Cannot apply request transaction");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: authorization successful");
    return NGX_DECLINED;
}

static int ngx_http_jwt_request_handler_checker_callback(jwt_t *jwt, jwt_config_t *config) {
    ngx_http_jwt_request_handler_checker_callback_ctx_t *ctx;
    ngx_http_request_t *r;
    ngx_flag_t *internal_server_error;
    ngx_http_jwt_request_transaction_t *transaction;
    ngx_http_jwt_loc_conf_t *jwt_lcf;
    ngx_queue_t *q;
    static const ngx_str_t null_string = ngx_null_string;

    ctx = config->ctx;
    r = ctx->r;
    transaction = ctx->transaction;
    internal_server_error = &ctx->internal_server_error;
    jwt_lcf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);

    // Set key & alg

    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: Beginning validation process");

        jwt_value_t kid;
        ngx_http_jwt_loaded_jwks_t *loaded_jwks;
        ngx_http_jwt_jwks_storage_jwks_t *storage_jwks;
        jwk_set_t *jwks;
        jwk_item_t *key;

        jwt_set_GET_STR(&kid, "kid");

        if (jwt_header_get(jwt, &kid) != JWT_VALUE_ERR_NONE || kid.str_val == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: kid not found");
            return -1;
        }

        key = NULL;
        for (q = ngx_queue_head(&jwt_lcf->loaded_jwkss);
             q != ngx_queue_sentinel(&jwt_lcf->loaded_jwkss);
             q = ngx_queue_next(q)) {
            loaded_jwks = ngx_queue_data(q, ngx_http_jwt_loaded_jwks_t, queue);
            storage_jwks = loaded_jwks->jwks;
            jwks = ngx_http_jwt_jwks_storage_get_jwks(storage_jwks);
            if (jwks == NULL) continue;
            key = jwks_find_bykid(jwks, kid.str_val);
            if (key != NULL) break;
        }

        if (key == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: No key found for kid");
            return -1;
        }

        config->alg = jwt_get_alg(jwt);

        if (config->alg == JWT_ALG_NONE) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: alg not found");
            return -1;
        }

        // The JWK can omit alg
        if (jwks_item_alg(key) != JWT_ALG_NONE && jwks_item_alg(key) != config->alg) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: key alg mismatch");
            return -1;
        }

        config->key = key;
    }

    // Extract token body

    jwt_value_t token_body_value;
    json_t *token_body;

    token_body_value.type = JWT_VALUE_JSON;
    token_body_value.name = NULL;
    token_body_value.error = JWT_VALUE_ERR_NONE;
    token_body_value.pretty = 0;
    if (jwt_claim_get(jwt, &token_body_value) != JWT_VALUE_ERR_NONE || token_body_value.json_val == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: Cannot load token body");
        return -1;
    }

    token_body = json_loads(token_body_value.json_val, JSON_REJECT_DUPLICATES, NULL);
    ngx_http_jwt_memory_free(token_body_value.json_val);
    if (token_body == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT authorization: cannot load token body as JSON object (should not happen)");
        *internal_server_error = 1;
        return -1;
    }

    if (!json_is_object(token_body)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT authorization: token body is not a JSON object (should not happen)");
        json_decref(token_body);
        *internal_server_error = 1;
        return -1;
    }

    // Validate

    ngx_http_jwt_validate_claim_t *validate_claim;
    json_t *value;

    for (q = ngx_queue_head(&jwt_lcf->validate.claims);
         q != ngx_queue_sentinel(&jwt_lcf->validate.claims);
         q = ngx_queue_next(q)) {
        validate_claim = ngx_queue_data(q, ngx_http_jwt_validate_claim_t, queue);

        value = json_object_get(token_body, (const char *) validate_claim->name.data); // borrow

        if (value == NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: validated claim %V not found", &validate_claim->name);
            json_decref(token_body);
            return -1;
        }

        switch (validate_claim->predicate) {
            case NGX_HTTP_JWT_VALIDATE_EQUALS:
                if (json_equal(value, validate_claim->value) != 1) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: validated claim %V has invalid value", &validate_claim->name);
                    json_decref(token_body);
                    return -1;
                }
                break;
            case NGX_HTTP_JWT_VALIDATE_IN:
                {
                    size_t index;
                    json_t *index_value, *found_value;

                    found_value = NULL;
                    json_array_foreach(validate_claim->value, index, index_value) {
                        if (json_equal(value, validate_claim->value) == 0) {
                            found_value = index_value;
                            break;
                        }
                    }
                    if (found_value == NULL) {
                        ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: validated claim %V has invalid value", &validate_claim->name);
                        json_decref(token_body);
                        return -1;
                    }
                }
                break;
            case NGX_HTTP_JWT_VALIDATE_EXP:
                if (!json_is_number(value)
                 || json_number_value(value) < ngx_time() - json_number_value(validate_claim->value)) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: validated claim %V has invalid value", &validate_claim->name);
                    json_decref(token_body);
                    return -1;
                }
                break;
            case NGX_HTTP_JWT_VALIDATE_NBF:
                if (!json_is_number(value)
                 || json_number_value(value) > ngx_time() + json_number_value(validate_claim->value)) {
                    ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: validated claim %V has invalid value", &validate_claim->name);
                    json_decref(token_body);
                    return -1;
                }
                break;
            default:
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: validated claim %V has invalid runtime type (should not happen)", &validate_claim->name);
                json_decref(token_body);
                return -1;
        }
        
    }

    // Extract

    ngx_http_jwt_extract_claim_t *extract_claim;
    ngx_str_t raw, encoded;

    for (q = ngx_queue_head(&jwt_lcf->extract.claims);
         q != ngx_queue_sentinel(&jwt_lcf->extract.claims);
         q = ngx_queue_next(q)) {
        extract_claim = ngx_queue_data(q, ngx_http_jwt_extract_claim_t, queue);

        value = json_object_get(token_body, (const char *) extract_claim->claim_name.data); // borrow

        if (value == NULL) {
            if (!(extract_claim->optional)) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: extracted claim %V not found (not optional)", &extract_claim->claim_name);
                json_decref(token_body);
                return -1;
            } else if (ngx_http_jwt_request_transaction_add_action(transaction, extract_claim->header_name, null_string) != NGX_OK) {
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT authorization: Cannot add null action to transaction for not found extract claim");
                json_decref(token_body);
                *internal_server_error = 1;
                return -1;
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: extract claim %V not found (optional, skipping)", &extract_claim->claim_name);
            continue;
        }

        raw.data = (u_char *) json_dumps(value, JSON_ENCODE_ANY | JSON_COMPACT);

        if (raw.data == NULL) {
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: Cannot extract claim %V", &extract_claim->claim_name);
            json_decref(token_body);
            *internal_server_error = 1;
            return -1;
        }

        if (ngx_strlen(raw.data) >= NGX_HTTP_JWT_CLAIM_VALUE_LEN_MAX) {
            if (!(extract_claim->optional)) {
                ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: Extract claim value %V too long (not optional)", &extract_claim->claim_name);
                json_decref(token_body);
                ngx_http_jwt_memory_free(raw.data);
                return -1;
            }
            ngx_log_debug1(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: Extract claim %V value too long (optional, skipping)", &extract_claim->claim_name);
            ngx_http_jwt_memory_free(raw.data);
            continue;
        }

        raw.len = ngx_strlen(raw.data);

        encoded.data = ngx_palloc(r->pool, ngx_base64_encoded_length(raw.len));
        if (encoded.data == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: Failed initializing base64 string");
            json_decref(token_body);
            ngx_http_jwt_memory_free(raw.data);
            *internal_server_error = 1;
            return -1;
        }

        ngx_encode_base64url(&encoded, &raw);

        if (ngx_http_jwt_request_transaction_add_action(transaction, extract_claim->header_name, encoded) != NGX_OK) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: Cannot add transaction action");
            json_decref(token_body);
            ngx_http_jwt_memory_free(raw.data);
            *internal_server_error = 1;
            return -1;
        }

        ngx_pfree(r->pool, encoded.data);
        ngx_http_jwt_memory_free(raw.data);
        continue;
    }

    json_decref(token_body);

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: All checks passed");
    return 0;
}