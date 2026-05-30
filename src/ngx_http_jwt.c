
/*
 * Copyright (C) Scevenate
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt_jwk.h>
#include <ngx_http_jwt_header.h>
#include <jwt.h>

#define NGX_HTTP_JWT_DEFAULT_ERROR_CODE 403


typedef struct {
    ngx_str_t name;
    ngx_str_t value;
    ngx_queue_t queue;
} ngx_http_jwt_claim_t;

typedef struct {
    ngx_flag_t exp;
    ngx_flag_t nbf;
    // queue of ngx_http_jwt_claim_t
    // A queue is preferred over rbtree because iterating all locations to compile is quite messy, and the queue of value claims is expected to be quite short.
    // A rbtree, or even hash table implementation, might be used in the future. But not likely.
    ngx_queue_t value_claims;
    ngx_queue_t negative_value_claims; // A structure of negative ("") claims used in compile time for merging conf.
} ngx_http_jwt_validate_t;

typedef struct {
    // Similar to validate, but for claim name and header name (value).
    ngx_queue_t value_claims;
    ngx_queue_t negative_value_claims;
} ngx_http_jwt_extract_t;

typedef struct {
    ngx_flag_t enable;
    ngx_flag_t filter; // filter is on by default, because the module is considered responsible for JWT.
    jwk_set_t *jwks;
    ngx_http_jwt_validate_t validate;
    ngx_http_jwt_extract_t extract;
    ngx_int_t error_code;
} ngx_http_jwt_loc_conf_t;

static ngx_int_t ngx_http_jwt_preconfiguration(ngx_conf_t *cf);

static char *ngx_conf_set_jwks_slot_from_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_set_validate_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_set_extract_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
static char *ngx_conf_check_error_code_slot(ngx_conf_t *cf, void *post, void *np);
static ngx_conf_post_t ngx_conf_check_error_code_slot_post = {
    ngx_conf_check_error_code_slot
};

static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);

static ngx_int_t ngx_http_jwt_postconfiguration(ngx_conf_t *cf);

static ngx_int_t ngx_http_jwt_request_handler(ngx_http_request_t *r);
static int ngx_http_jwt_request_handler_checker_callback(jwt_t *jwt, jwt_config_t *config); // config->ctx is ngx_http_request_t *r

static ngx_command_t  ngx_http_jwt_commands[] = {
  { ngx_string("jwt"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, enable),
      NULL },
    
  { ngx_string("jwt_filter"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, filter),
      NULL },

  { ngx_string("jwt_jwks_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_jwks_slot_from_file,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, jwks),
      NULL },

  { ngx_string("jwt_validate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE12,
      ngx_conf_set_validate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, validate),
      NULL },

  { ngx_string("jwt_extract"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
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
    ngx_http_jwt_preconfiguration,       /* preconfiguration */
    ngx_http_jwt_postconfiguration,       /* postconfiguration */

    NULL,                                 /* create main configuration */
    NULL,                                 /* init main configuration */

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
    NULL,                                  /* init process */
    NULL,                                  /* init thread */
    NULL,                                  /* exit thread */
    NULL,                                  /* exit process */
    NULL,                                  /* exit master */
    NGX_MODULE_V1_PADDING
};

static ngx_int_t ngx_http_jwt_preconfiguration(ngx_conf_t *cf) {
    return ngx_http_jwt_jwk_cycle_init();
}

static char *ngx_conf_set_jwks_slot_from_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char *p = conf;

    jwk_set_t *field;
    ngx_str_t *value;
    ngx_conf_post_t *post;
    
    field = (jwk_set_t *) (p + cmd->offset);

    if (field != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    field = ngx_http_jwt_jwk_load_jwks_from_file(value[1].data);

    if (field == NULL) {
        return "failed to load JWKS from file";
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}

static char *ngx_conf_set_validate_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char* p = conf;

    ngx_http_jwt_validate_t *field;
    ngx_int_t nelts;
    ngx_str_t *value;
    ngx_conf_post_t *post;

    field = (ngx_http_jwt_validate_t *) (p + cmd->offset);

    nelts = cf->args->nelts;
    value = cf->args->elts;

    // First handle exp [""] / nbf [""]

    if (ngx_strcmp(value[1].data, "exp") == 0) {
        if (field->exp != NGX_CONF_UNSET_UINT) return "is duplicate";
        // TAKE12, nelts is 2 or 3
        if (nelts == 2) {
            field->exp = 1;
            return NGX_CONF_OK;
        }
        if (value[2].len == 0) {
            field->exp = 0;
            return NGX_CONF_OK;
        }
        return "must not have a value for registered claim exp";
    }
    
    if (ngx_strcmp(value[1].data, "nbf") == 0) {
        if (field->nbf != NGX_CONF_UNSET_UINT) return "is duplicate";
        // TAKE12, nelts is 2 or 3
        if (nelts == 2) {
            field->nbf = 1;
            return NGX_CONF_OK;
        }
        if (value[2].len == 0) {
            field->nbf = 0;
            return NGX_CONF_OK;
        }
        return "must not have a value for registered claim nbf";
    }

    // Regular value claims
    
    if (nelts == 2) {
        return "defined custom claim with no given value";
    }

    ngx_queue_t *q;
    ngx_http_jwt_claim_t *claim;

    for (q = ngx_queue_head(&field->value_claims);
         q != ngx_queue_sentinel(&field->value_claims);
         q = ngx_queue_next(q)) {
        claim = ngx_queue_data(q, ngx_http_jwt_claim_t, queue);
        if (ngx_strcmp(claim->name.data, value[1].data) == 0) {
            return "is duplicate";
        }
    }

    for (q = ngx_queue_head(&field->negative_value_claims);
         q != ngx_queue_sentinel(&field->negative_value_claims);
         q = ngx_queue_next(q)) {
        claim = ngx_queue_data(q, ngx_http_jwt_claim_t, queue);
        if (ngx_strcmp(claim->name.data, value[1].data) == 0) {
            return "is duplicate";
        }
    }

    if (value[2].len != 0) {
        claim = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_claim_t));
        if (claim == NULL) {
            return NGX_CONF_ERROR;
        }

        claim->name = value[1];
        claim->value = value[2];
        ngx_queue_insert_head(&field->value_claims, &claim->queue);
    }

    else {
        claim = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_claim_t));
        if (claim == NULL) {
            return NGX_CONF_ERROR;
        }

        claim->name = value[1];
        claim->value = value[2];
        ngx_queue_insert_head(&field->negative_value_claims, &claim->queue);
    }

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

    if (ngx_http_jwt_header_check(&value[2]) != NGX_OK) {
        return "contains invalid header name";
    }

    ngx_queue_t *q;
    ngx_http_jwt_claim_t *claim;

    for (q = ngx_queue_head(&field->value_claims);
         q != ngx_queue_sentinel(&field->value_claims);
         q = ngx_queue_next(q)) {
        claim = ngx_queue_data(q, ngx_http_jwt_claim_t, queue);
        if (ngx_strcmp(claim->name.data, value[1].data) == 0) {
            return "is duplicate";
        }
    }

    for (q = ngx_queue_head(&field->negative_value_claims);
         q != ngx_queue_sentinel(&field->negative_value_claims);
         q = ngx_queue_next(q)) {
        claim = ngx_queue_data(q, ngx_http_jwt_claim_t, queue);
        if (ngx_strcmp(claim->name.data, value[1].data) == 0) {
            return "is duplicate";
        }
    }

    if (value[2].len != 0) {
        claim = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_claim_t));
        if (claim == NULL) {
            return NGX_CONF_ERROR;
        }

        claim->name = value[1];
        claim->value = value[2];
        ngx_queue_insert_head(&field->value_claims, &claim->queue);
    }

    else {
        claim = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_claim_t));
        if (claim == NULL) {
            return NGX_CONF_ERROR;
        }

        claim->name = value[1];
        claim->value = value[2];
        ngx_queue_insert_head(&field->negative_value_claims, &claim->queue);
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}

static char *ngx_conf_check_error_code_slot(ngx_conf_t *cf, void *post, void *np) {
    ngx_int_t *error_code = np;

    if (*error_code < 300 || *error_code > 599) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "Invalid error code for jwt_error_code");
        return NGX_CONF_ERROR;
    }

    return NGX_CONF_OK;
}

static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_jwt_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->filter = NGX_CONF_UNSET;
    conf->jwks = NGX_CONF_UNSET_PTR;
    conf->validate.exp = NGX_CONF_UNSET;
    conf->validate.nbf = NGX_CONF_UNSET;
    ngx_queue_init(&conf->validate.value_claims);
    ngx_queue_init(&conf->validate.negative_value_claims);
    ngx_queue_init(&conf->extract.value_claims);
    ngx_queue_init(&conf->extract.negative_value_claims);
    conf->error_code = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_jwt_loc_conf_t *prev = parent;
    ngx_http_jwt_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->filter, prev->filter, 1);
    ngx_conf_merge_ptr_value(conf->jwks, prev->jwks, NGX_CONF_UNSET_PTR);
    ngx_conf_merge_value(conf->validate.exp, prev->validate.exp, NGX_CONF_UNSET);
    ngx_conf_merge_value(conf->validate.nbf, prev->validate.nbf, NGX_CONF_UNSET);
    ngx_conf_merge_value(conf->error_code, prev->error_code, NGX_HTTP_JWT_DEFAULT_ERROR_CODE);

    // Merge all four queues UwU
    // Maybe make it a structure in the future

    ngx_queue_t *q_prev, *q_conf;
    ngx_http_jwt_claim_t *claim_prev, *claim_conf;
    ngx_uint_t found;

    for (q_prev = ngx_queue_head(&prev->validate.value_claims);
         q_prev != ngx_queue_sentinel(&prev->validate.value_claims);
         q_prev = ngx_queue_head(&prev->validate.value_claims)) {
        claim_prev = ngx_queue_data(q_prev, ngx_http_jwt_claim_t, queue);
        found = 0;
        for (q_conf = ngx_queue_head(&conf->validate.value_claims);
             q_conf != ngx_queue_sentinel(&conf->validate.value_claims);
             q_conf = ngx_queue_next(q_conf)) {
            claim_conf = ngx_queue_data(q_conf, ngx_http_jwt_claim_t, queue);
            if (ngx_strcmp(claim_prev->name.data, claim_conf->name.data) == 0) {
                found = 1;
                ngx_queue_remove(q_prev);
                ngx_pfree(cf->pool, claim_prev);
                break;
            }
        }
        if (found == 1) continue;

        for (q_conf = ngx_queue_head(&conf->validate.negative_value_claims);
             q_conf != ngx_queue_sentinel(&conf->validate.negative_value_claims);
             q_conf = ngx_queue_next(q_conf)) {
            claim_conf = ngx_queue_data(q_conf, ngx_http_jwt_claim_t, queue);
            if (ngx_strcmp(claim_prev->name.data, claim_conf->name.data) == 0) {
                found = 1;
                ngx_queue_remove(q_prev);
                ngx_pfree(cf->pool, claim_prev);
                break;
            }
        }
        if (found == 1) continue;

        ngx_queue_remove(q_prev);
        ngx_queue_insert_head(&conf->validate.value_claims, q_prev);
    }

    for (q_prev = ngx_queue_head(&prev->validate.negative_value_claims);
         q_prev != ngx_queue_sentinel(&prev->validate.negative_value_claims);
         q_prev = ngx_queue_head(&prev->validate.negative_value_claims)) {
        claim_prev = ngx_queue_data(q_prev, ngx_http_jwt_claim_t, queue);
        found = 0;
        for (q_conf = ngx_queue_head(&conf->validate.value_claims);
             q_conf != ngx_queue_sentinel(&conf->validate.value_claims);
             q_conf = ngx_queue_next(q_conf)) {
            claim_conf = ngx_queue_data(q_conf, ngx_http_jwt_claim_t, queue);
            if (ngx_strcmp(claim_prev->name.data, claim_conf->name.data) == 0) {
                found = 1;
                ngx_queue_remove(q_prev);
                ngx_pfree(cf->pool, claim_prev);
                break;
            }
        }
        if (found == 1) continue;

        for (q_conf = ngx_queue_head(&conf->validate.negative_value_claims);
             q_conf != ngx_queue_sentinel(&conf->validate.negative_value_claims);
             q_conf = ngx_queue_next(q_conf)) {
            claim_conf = ngx_queue_data(q_conf, ngx_http_jwt_claim_t, queue);
            if (ngx_strcmp(claim_prev->name.data, claim_conf->name.data) == 0) {
                found = 1;
                ngx_queue_remove(q_prev);
                ngx_pfree(cf->pool, claim_prev);
                break;
            }
        }
        if (found == 1) continue;

        ngx_queue_remove(q_prev);
        ngx_queue_insert_head(&conf->validate.negative_value_claims, q_prev);
    }

    for (q_prev = ngx_queue_head(&prev->extract.value_claims);
         q_prev != ngx_queue_sentinel(&prev->extract.value_claims);
         q_prev = ngx_queue_head(&prev->extract.value_claims)) {
        claim_prev = ngx_queue_data(q_prev, ngx_http_jwt_claim_t, queue);
        found = 0;
        for (q_conf = ngx_queue_head(&conf->extract.value_claims);
             q_conf != ngx_queue_sentinel(&conf->extract.value_claims);
             q_conf = ngx_queue_next(q_conf)) {
            claim_conf = ngx_queue_data(q_conf, ngx_http_jwt_claim_t, queue);
            if (ngx_strcmp(claim_prev->name.data, claim_conf->name.data) == 0) {
                found = 1;
                ngx_queue_remove(q_prev);
                ngx_pfree(cf->pool, claim_prev);
                break;
            }
        }
        if (found == 1) continue;

        for (q_conf = ngx_queue_head(&conf->extract.negative_value_claims);
             q_conf != ngx_queue_sentinel(&conf->extract.negative_value_claims);
             q_conf = ngx_queue_next(q_conf)) {
            claim_conf = ngx_queue_data(q_conf, ngx_http_jwt_claim_t, queue);
            if (ngx_strcmp(claim_prev->name.data, claim_conf->name.data) == 0) {
                found = 1;
                ngx_queue_remove(q_prev);
                ngx_pfree(cf->pool, claim_prev);
                break;
            }
        }
        if (found == 1) continue;

        ngx_queue_remove(q_prev);
        ngx_queue_insert_head(&conf->extract.value_claims, q_prev);
    }

    for (q_prev = ngx_queue_head(&prev->extract.negative_value_claims);
         q_prev != ngx_queue_sentinel(&prev->extract.negative_value_claims);
         q_prev = ngx_queue_head(&prev->extract.negative_value_claims)) {
        claim_prev = ngx_queue_data(q_prev, ngx_http_jwt_claim_t, queue);
        found = 0;
        for (q_conf = ngx_queue_head(&conf->extract.value_claims);
                q_conf != ngx_queue_sentinel(&conf->extract.value_claims);
                q_conf = ngx_queue_next(q_conf)) {
            claim_conf = ngx_queue_data(q_conf, ngx_http_jwt_claim_t, queue);
            if (ngx_strcmp(claim_prev->name.data, claim_conf->name.data) == 0) {
                found = 1;
                ngx_queue_remove(q_prev);
                ngx_pfree(cf->pool, claim_prev);
                break;
            }
        }
        if (found == 1) continue;

        for (q_conf = ngx_queue_head(&conf->extract.negative_value_claims);
                q_conf != ngx_queue_sentinel(&conf->extract.negative_value_claims);
                q_conf = ngx_queue_next(q_conf)) {
            claim_conf = ngx_queue_data(q_conf, ngx_http_jwt_claim_t, queue);
            if (ngx_strcmp(claim_prev->name.data, claim_conf->name.data) == 0) {
                found = 1;
                ngx_queue_remove(q_prev);
                ngx_pfree(cf->pool, claim_prev);
                break;
            }
        }
        if (found == 1) continue;

        ngx_queue_remove(q_prev);
        ngx_queue_insert_head(&conf->extract.negative_value_claims, q_prev);
    }

    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_jwt_postconfiguration(ngx_conf_t *cf)
{
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

static ngx_int_t ngx_http_jwt_request_handler(ngx_http_request_t *r) {
    ngx_http_jwt_loc_conf_t *jwt_lcf = r->loc_conf[ngx_http_jwt_module.ctx_index];

    if (jwt_lcf->enable == 0) {
        return NGX_DECLINED;
    }

    ngx_int_t error_code = jwt_lcf->error_code;

    // Fetch & filter

    ngx_table_elt_t *authorization;
    ngx_int_t len;
    char *token;
    
    authorization = r->headers_in.authorization;
    if (authorization == NULL ||
        authorization->value.len < sizeof("Bearer ") - 1 ||
        ngx_strncasecmp(authorization->value.data, (u_char *) "Bearer ", sizeof("Bearer ") - 1) != 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: invalid authorization header");
        return error_code;
    }
    len = authorization->value.len - sizeof("Bearer ") + 1;

    token = ngx_palloc(r->pool, len + 1);
    ngx_memcpy(token, authorization->value.data + sizeof("Bearer ") - 1, len);
    token[len] = '\0';

    if (jwt_lcf->filter == 1) {
        if (ngx_http_jwt_header_filter_authorization(r) != NGX_OK) {
            ngx_pfree(r->pool, token);
            return error_code;
        }
    }

    // Checker, exp & nbf, callback

    jwt_checker_t *checker = jwt_checker_new();
    if (checker == NULL) {
        ngx_pfree(r->pool, token);
        return error_code;
    }

    if (jwt_checker_time_leeway(checker, JWT_CLAIM_EXP, jwt_lcf->validate.exp - 1) != 0) {
        ngx_pfree(r->pool, token);
        jwt_checker_free(checker);
        return error_code;
    }
    if (jwt_checker_time_leeway(checker, JWT_CLAIM_NBF, jwt_lcf->validate.nbf - 1) != 0) {
        ngx_pfree(r->pool, token);
        jwt_checker_free(checker);
        return error_code;
    }
    jwt_checker_setcb(checker, ngx_http_jwt_request_handler_checker_callback, r);

    if (jwt_checker_verify(checker, token) != 0) {
        ngx_pfree(r->pool, token);
        jwt_checker_free(checker);
        return error_code;
    }

    ngx_pfree(r->pool, token);
    jwt_checker_free(checker);
    return NGX_DECLINED;
}

static int ngx_http_jwt_request_handler_checker_callback(jwt_t *jwt, jwt_config_t *config) {
    ngx_http_request_t *r = (ngx_http_request_t *) config->ctx;
    ngx_http_jwt_loc_conf_t *jwt_lcf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);

    // Set key & alg

    jwt_value_t kid;
    jwt_set_GET_STR(&kid, "kid");

    if (jwt_header_get(jwt, &kid) != JWT_VALUE_ERR_NONE || kid.str_val == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: No kid found");
        return -1;
    }

    jwk_item_t *key = jwks_find_bykid(jwt_lcf->jwks, kid.str_val);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: No jwk for kid");
        return -1;
    }

    config->key = key;
    config->alg = jwt_get_alg(jwt);

    // Validate value claims

    ngx_queue_t *q;
    ngx_http_jwt_claim_t *claim;

    for (q = ngx_queue_head(&jwt_lcf->validate.value_claims);
         q != ngx_queue_sentinel(&jwt_lcf->validate.value_claims);
         q = ngx_queue_next(q)) {
        jwt_value_t value;

        claim = ngx_queue_data(q, ngx_http_jwt_claim_t, queue);
        jwt_set_GET_STR(&value, (char *) claim->name.data);
        if (jwt_claim_get(jwt, &value) != JWT_VALUE_ERR_NONE || ngx_strcmp(value.str_val, claim->value.data) != 0) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: validation failed", claim->name.data);
            return -1;
        }
    }

    // Extract value claims

    for (q = ngx_queue_head(&jwt_lcf->extract.value_claims);
         q != ngx_queue_sentinel(&jwt_lcf->extract.value_claims);
         q = ngx_queue_next(q)) {
        jwt_value_t value;
        jwt_value_error_t error;
        
        claim = ngx_queue_data(q, ngx_http_jwt_claim_t, queue);
        jwt_set_GET_STR(&value, (char *) claim->name.data);
        error = jwt_claim_get(jwt, &value);
        switch (error) {
            case JWT_VALUE_ERR_NONE:
                if (ngx_http_jwt_header_filter(r, &claim->value, &value) != NGX_OK) {
                    return -1;
                }
                break;
            case JWT_VALUE_ERR_NOEXIST:
                if (ngx_http_jwt_header_filter(r, &claim->value, NULL) != NGX_OK) {
                    return -1;
                }
                break;
            default:
                break;
        }
    }

    return 0;
}