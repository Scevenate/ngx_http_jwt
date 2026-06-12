
/*
 * Copyright (C) Scevenate
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt.h>
#include <jansson.h>
#include <jwt.h>

typedef struct {
    ngx_flag_t enable;
    ngx_flag_t filter;
    jwk_set_t *default_jwks;
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

static char *ngx_conf_set_default_jwks_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);
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
static int ngx_http_jwt_request_handler_checker_callback(jwt_t *jwt, jwt_config_t *config);

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

  { ngx_string("jwt_default_jwks"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_default_jwks_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, default_jwks),
      NULL },

  { ngx_string("jwt_validate"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
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
    if (ngx_http_jwt_memory_set_pool(cf->cycle->pool) != NGX_OK) return NGX_ERROR;
    if (ngx_http_jwt_jwk_cycle_init(cf->cycle) != NGX_OK) return NGX_ERROR;
    return NGX_OK;
}

static char *ngx_conf_set_default_jwks_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char *p = conf;

    jwk_set_t **field;
    ngx_str_t *value;
    ngx_conf_post_t *post;
    
    field = (jwk_set_t **) (p + cmd->offset);

    if (*field != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    switch (value[1].data[0]) {
        case 'f':
            if (ngx_strcmp(value[1].data, "file") != 0) return "got invalid JWKS source";
            *field = ngx_http_jwt_jwk_load_jwks_from_file(&value[2]);
            if (*field == NULL) return "failed to load JWKS from file";
            break;
        default:
            return "got invalid JWKS source";
            break;
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

    // First handle exp / nbf

    json_t *leeway;
    double leeway_value;

    if (ngx_strcmp(value[1].data, "exp") == 0) {
        if (nelts == 3) return "expected 1 or 3 arguments for exp validation directive";
        if (field->exp != NGX_CONF_UNSET) return "is duplicate";

        
        if (nelts == 2) {
            field->exp = 0;
            return NGX_CONF_OK;
        }

        if (ngx_strcmp(value[2].data, "leeway") != 0) return "expected leeway for exp validation directive";
        
        leeway = json_loads((const char *) value[3].data, JSON_DECODE_ANY, NULL);
        if (leeway == NULL) {
            json_decref(leeway);
            return "got invalid leeway";
        }
        if (!json_is_number(leeway)) {
            json_decref(leeway);
            return "got invalid leeway";
        }
        leeway_value = json_number_value(leeway);
        if (leeway_value < 0 || leeway_value > NGX_HTTP_JWT_LEEWAY_MAX) {
            json_decref(leeway);
            return "got invalid leeway";
        }

        field->exp = leeway_value;
        json_decref(leeway);
        return NGX_CONF_OK;
    }
    
    if (ngx_strcmp(value[1].data, "nbf") == 0) {
        if (nelts == 3) return "expected 1 or 3 arguments for nbf validation directive";
        if (field->nbf != NGX_CONF_UNSET) return "is duplicate";

        
        if (nelts == 2) {
            field->nbf = 0;
            return NGX_CONF_OK;
        }

        if (ngx_strcmp(value[2].data, "leeway") != 0) return "expected leeway for nbf validation directive";

        leeway = json_loads((const char *) value[3].data, JSON_DECODE_ANY, NULL);
        if (leeway == NULL) {
            json_decref(leeway);
            return "got invalid leeway";
        }
        if (!json_is_number(leeway)) {
            json_decref(leeway);
            return "got invalid leeway";
        }
        leeway_value = json_number_value(leeway);
        if (leeway_value < 0 || leeway_value > NGX_HTTP_JWT_LEEWAY_MAX) {
            json_decref(leeway);
            return "got invalid leeway";
        }

        field->nbf = leeway_value;
        json_decref(leeway);
        return NGX_CONF_OK;
    }

    // Regular value claims
    
    ngx_queue_t *q;
    ngx_http_jwt_validate_claim_t *claim;

    if (nelts != 3) {
        return "expected 2 arguments for custom claim validation directive";
    }

    if (value[1].len == 0 || value[1].len >= NGX_HTTP_JWT_CLAIM_NAME_LEN_MAX) {
        return "got invalid claim name";
    }

    if (value[2].len == 0 || value[2].len >= NGX_HTTP_JWT_CLAIM_VALUE_LEN_MAX) {
        return "got invalid claim value";
    }

    for (q = ngx_queue_head(&field->claims);
         q != ngx_queue_sentinel(&field->claims);
         q = ngx_queue_next(q)) {
        if (ngx_strcmp((ngx_queue_data(q, ngx_http_jwt_validate_claim_t, queue))->name.data, value[1].data) == 0) {
            return "is duplicate";
        }
    }

    claim = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_validate_claim_t));
    if (claim == NULL) return NGX_CONF_ERROR;

    claim->name = value[1];
    claim->value = json_loads((const char *) value[2].data, JSON_DECODE_ANY | JSON_REJECT_DUPLICATES, NULL);
    if (claim->value == NULL) {
        ngx_pfree(cf->pool, claim);
        return "got invalid claim value";
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
    ngx_http_header_t  *header;

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

    for (header = ngx_http_headers_in; header->name.len; header++) {
        if (value[2].len == header->name.len
            && ngx_strncasecmp(value[2].data, header->name.data, value[2].len) == 0)
        {
            return "got collision-prone header name";
        }
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

static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_jwt_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET;
    conf->filter = NGX_CONF_UNSET;
    conf->default_jwks = NGX_CONF_UNSET_PTR;
    conf->validate.exp = NGX_CONF_UNSET;
    conf->validate.nbf = NGX_CONF_UNSET;
    ngx_queue_init(&conf->validate.claims);
    ngx_queue_init(&conf->extract.claims);
    conf->error_code = NGX_CONF_UNSET;
    return conf;
}

static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_jwt_loc_conf_t *prev = parent;
    ngx_http_jwt_loc_conf_t *conf = child;

    ngx_conf_merge_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_value(conf->filter, prev->filter, 1);
    ngx_conf_merge_ptr_value(conf->default_jwks, prev->default_jwks, NGX_CONF_UNSET_PTR);
    ngx_conf_merge_value(conf->validate.exp, prev->validate.exp, NGX_CONF_UNSET);
    ngx_conf_merge_value(conf->validate.nbf, prev->validate.nbf, NGX_CONF_UNSET);
    ngx_conf_merge_value(conf->error_code, prev->error_code, NGX_HTTP_JWT_DEFAULT_ERROR_CODE);

    // Merge queues. Note that prev is shared and not stolen.

    ngx_queue_t *q_prev, *q_conf;
    ngx_http_jwt_validate_claim_t *validate_claim_prev, *validate_claim_conf;
    ngx_http_jwt_extract_claim_t *extract_claim_prev, *extract_claim_conf;
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
             && ngx_strcasecmp(extract_claim_prev->header_name.data, extract_claim_conf->header_name.data) == 0) {
                return "got duplicate headers";
            }
        }
    }
    return NGX_CONF_OK;
}

static ngx_int_t
ngx_http_jwt_postconfiguration(ngx_conf_t *cf) {
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

static ngx_int_t 
ngx_http_jwt_request_handler(ngx_http_request_t *r) {
    ngx_http_jwt_memory_set_pool(r->pool);

    ngx_http_jwt_loc_conf_t            *jwt_lcf;
    ngx_http_jwt_request_handler_checker_callback_ctx_t          ctx;
    ngx_http_jwt_request_transaction_t  transaction;
    ngx_table_elt_t                    *authorization;
    ngx_int_t                           len;
    char                               *token;
    jwt_checker_t                      *checker;

    jwt_lcf = r->loc_conf[ngx_http_jwt_module.ctx_index];

    if (jwt_lcf->enable == 0) {
        return NGX_DECLINED;
    }

    // Fetch token

    authorization = r->headers_in.authorization;
    if (authorization == NULL
     || authorization->value.len <= (sizeof("Bearer ") - 1)
     || ngx_strncasecmp(authorization->value.data, (u_char *) "Bearer ",
                        sizeof("Bearer ") - 1) != 0)
    {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: invalid authorization header");
        return jwt_lcf->error_code;
    }

    for (len = authorization->value.len - (sizeof("Bearer ") - 1);
         authorization->value.data[len - 1] == ' ';
         len--);

    token = ngx_palloc(r->pool, len + 1);
    if (token == NULL) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ngx_memcpy(token, authorization->value.data + (sizeof("Bearer ") - 1), len);
    token[len] = '\0';

    // Initialize callback ctx & ctx.transaction
    
    ctx.r = r;
    if (ngx_http_jwt_request_init(&transaction) != NGX_OK) {
        ngx_pfree(r->pool, token);
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }
    ctx.transaction = &transaction;
    ctx.internal_server_error = 0;

    // Checker

    checker = jwt_checker_new();
    if (checker == NULL) {
        ngx_http_jwt_request_free(r, &transaction);
        ngx_pfree(r->pool, token);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: could not create checker");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // Use custom exp / nbf check in callback for clearer responsibility boundary and better performance (use nginx cached time).

    if (jwt_checker_time_leeway(checker, JWT_CLAIM_EXP, -1) != 0
     || jwt_checker_time_leeway(checker, JWT_CLAIM_NBF, -1) != 0) {
        ngx_http_jwt_request_free(r, &transaction);
        ngx_pfree(r->pool, token);
        jwt_checker_free(checker);
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: could not disable JWT leeway");
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    // Callback

    jwt_checker_setcb(checker, ngx_http_jwt_request_handler_checker_callback,
                      &ctx);

    if (jwt_checker_verify(checker, token) != 0) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: authorization failed");
        ngx_http_jwt_request_free(r, &transaction);
        ngx_pfree(r->pool, token);
        jwt_checker_free(checker);
        return ctx.internal_server_error ? NGX_HTTP_INTERNAL_SERVER_ERROR : jwt_lcf->error_code;
    }

    ngx_pfree(r->pool, token);
    jwt_checker_free(checker);

    // Apply transaction

    if (ngx_http_jwt_request_apply(r, &transaction) != NGX_OK) {
        return NGX_HTTP_INTERNAL_SERVER_ERROR;
    }

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT: authorization successful");
    return NGX_DECLINED;
}

static int ngx_http_jwt_request_handler_checker_callback(jwt_t *jwt, jwt_config_t *config) {
    ngx_http_jwt_request_handler_checker_callback_ctx_t         *ctx;
    ngx_http_request_t                 *r;
    ngx_flag_t *internal_server_error;
    ngx_http_jwt_request_transaction_t *transaction;
    ngx_http_jwt_loc_conf_t            *jwt_lcf;
    ngx_queue_t *q;

    ctx = config->ctx;
    r = ctx->r;
    transaction = ctx->transaction;
    internal_server_error = &ctx->internal_server_error;
    jwt_lcf = ngx_http_get_module_loc_conf(r, ngx_http_jwt_module);

    // Set key & alg

    jwt_value_t kid;
    jwk_set_t *default_jwks;
    jwk_item_t *key;

    default_jwks = jwt_lcf->default_jwks;
    if (default_jwks == NGX_CONF_UNSET_PTR) {
        // This is done runtime because default key / dynamic fetch w/ cache will be implemented in future. JWKS is hash table for a reason.
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: lcf->jwks not found");
        return -1;
    }

    jwt_set_GET_STR(&kid, "kid");

    if (jwt_header_get(jwt, &kid) != JWT_VALUE_ERR_NONE || kid.str_val == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: kid not found");
        return -1;
    }

    key = jwks_find_bykid(default_jwks, kid.str_val);
    if (key == NULL) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: No jwk for kid");
        return -1;
    }

    config->alg = jwt_get_alg(jwt);

    if (config->alg == JWT_ALG_NONE || jwks_item_alg(key) != config->alg) {
        ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: key alg mismatch");
        return -1;
    }

    config->key = key;

    // Extract token body

    jwt_value_t token_body_value;
    json_t *token_body, *value;

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
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT authorization: cannot load token body as JSON object");
        *internal_server_error = 1;
        return -1;
    }

    // I don't think this is possible...
    if (!json_is_object(token_body)) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT authorization: token body is not a JSON object");
        json_decref(token_body);
        *internal_server_error = 1;
        return -1;
    }

    // Validate exp / nbf

    if (jwt_lcf->validate.exp != NGX_CONF_UNSET) {
        value = json_object_get(token_body, "exp"); // borrow
        if (value == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: exp not found");
            json_decref(token_body);
            return -1;
        }
        if (!json_is_number(value)) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: exp is not an integer");
            json_decref(token_body);
            return -1;
        }
        if (json_number_value(value) <= (ngx_time() - jwt_lcf->validate.exp)) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: exp expired");
            json_decref(token_body);
            return -1;
        }
    }

    if (jwt_lcf->validate.nbf != NGX_CONF_UNSET) {
        value = json_object_get(token_body, "nbf"); // borrow
        if (value == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: nbf not found");
            json_decref(token_body);
            return -1;
        }
        if (!json_is_number(value)) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: nbf is not an integer");
            json_decref(token_body);
            return -1;
        }
        if (json_number_value(value) > (ngx_time() + jwt_lcf->validate.nbf)) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: nbf expired");
            json_decref(token_body);
            return -1;
        }
    }

    // Set authorization

    if (jwt_lcf->filter == 1) {
        if (ngx_http_jwt_request_set_authorization(transaction) != NGX_OK) {
            json_decref(token_body);
            *internal_server_error = 1;
            return -1;
        }
    }

    // Validate value claims

    ngx_http_jwt_validate_claim_t *validate_claim;

    for (q = ngx_queue_head(&jwt_lcf->validate.claims);
         q != ngx_queue_sentinel(&jwt_lcf->validate.claims);
         q = ngx_queue_next(q)) {
        validate_claim = ngx_queue_data(q, ngx_http_jwt_validate_claim_t, queue);

        value = json_object_get(token_body, (const char *) validate_claim->name.data); // borrow

        if (value == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: validated claim not found");
            json_decref(token_body);
            return -1;
        }

        if (json_equal(value, validate_claim->value) != 1) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: validated claim value mismatch");
            json_decref(token_body);
            return -1;
        }
    }

    // Extract value claims

    ngx_http_jwt_extract_claim_t *extract_claim;
    ngx_str_t raw, encoded;

    for (q = ngx_queue_head(&jwt_lcf->extract.claims);
         q != ngx_queue_sentinel(&jwt_lcf->extract.claims);
         q = ngx_queue_next(q)) {
        extract_claim = ngx_queue_data(q, ngx_http_jwt_extract_claim_t, queue);

        value = json_object_get(token_body, (const char *) extract_claim->claim_name.data); // borrow

        if (value == NULL) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: extract claim not found");
            if (!(extract_claim->optional)) {
                json_decref(token_body);
                return -1;
            } else if (ngx_http_jwt_request_set_header(r, transaction, extract_claim->header_name, null_string) != NGX_OK) {
                json_decref(token_body);
                *internal_server_error = 1;
                return -1;
            }
            continue;
        }

        raw.data = (u_char *) json_dumps(value, JSON_ENCODE_ANY | JSON_COMPACT);

        if (raw.data == NULL) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT authorization: Extract claim value");
            ngx_http_jwt_request_set_header(r, transaction, extract_claim->header_name, null_string); // Double fail. Doesn't care, just pass to fast finalization.
            json_decref(token_body);
            *internal_server_error = 1;
            return -1;
        }

        if (ngx_strlen(raw.data) >= NGX_HTTP_JWT_CLAIM_VALUE_LEN_MAX) {
            ngx_log_debug0(NGX_LOG_DEBUG_HTTP, r->connection->log, 0, "JWT authorization: Claim value too long");
            if (ngx_http_jwt_request_set_header(r, transaction, extract_claim->header_name, null_string) != NGX_OK) {
                json_decref(token_body);
                ngx_http_jwt_memory_free(raw.data);
                *internal_server_error = 1;
                return -1;
            }
            ngx_http_jwt_memory_free(raw.data);
            continue;
        }

        raw.len = ngx_strlen(raw.data);

        encoded.data = ngx_palloc(r->pool, ngx_base64_encoded_length(raw.len));
        if (encoded.data == NULL) {
            json_decref(token_body);
            ngx_http_jwt_memory_free(raw.data);
            *internal_server_error = 1;
            return -1;
        }

        ngx_encode_base64url(&encoded, &raw);

        if (ngx_http_jwt_request_set_header(r, transaction, extract_claim->header_name, encoded) != NGX_OK) {
            ngx_pfree(r->pool, encoded.data);
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

    return 0;
}
