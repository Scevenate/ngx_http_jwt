
/*
 * Copyright (C) Scevenate
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt_jwk.h>
#include <ngx_http_jwt_json.h>
#include <ngx_http_jwt_request.h>
#include <jansson.h>
#include <jwt.h>

#define NGX_HTTP_JWT_DEFAULT_ERROR_CODE NGX_HTTP_FORBIDDEN

#define NGX_HTTP_JWT_CLAIM_NAME_LEN_MAX 2048 // Include null terminator
#define NGX_HTTP_JWT_CLAIM_VALUE_LEN_MAX 2048 // Include null terminator
#define NGX_HTTP_JWT_CLAIM_VALUE_INT_MAX 2147483647
#define NGX_HTTP_JWT_CLAIM_VALUE_INT_MIN -2147483648
#define NGX_HTTP_JWT_HEADER_NAME_LEN_MAX 2048 // Include null terminator

typedef struct {
    ngx_str_t name;
    jwt_value_type_t type;
    union {
        ngx_int_t int_val;
        ngx_str_t str_val;
        ngx_flag_t bool_val;
        json_t *json_val;
    };
    ngx_queue_t queue;
} ngx_http_jwt_validate_claim_t;

typedef struct {
    ngx_int_t exp;
    ngx_int_t nbf;
    ngx_queue_t claims;
} ngx_http_jwt_validate_t;

typedef struct {
    ngx_str_t claim_name;
    jwt_value_type_t type;
    ngx_str_t header_name;
    ngx_queue_t queue;
} ngx_http_jwt_extract_claim_t;

typedef struct {
    ngx_queue_t claims;
} ngx_http_jwt_extract_t;

typedef struct {
    ngx_flag_t enable;
    ngx_flag_t filter;
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
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE123,
      ngx_conf_set_validate_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, validate),
      NULL },

  { ngx_string("jwt_extract"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE3,
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
    if (ngx_http_jwt_jwk_cycle_init() != NGX_OK) {
        return NGX_ERROR;
    }
    if (ngx_http_jwt_json_cycle_init() != NGX_OK) {
        return NGX_ERROR;
    }
    return NGX_OK;
}

static char *ngx_conf_set_jwks_slot_from_file(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char *p = conf;

    jwk_set_t **field;
    ngx_str_t *value;
    ngx_conf_post_t *post;
    
    field = (jwk_set_t **) (p + cmd->offset);

    if (*field != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    *field = ngx_http_jwt_jwk_load_jwks_from_file(value[1].data);

    if (*field == NULL) {
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

    // First handle exp / nbf

    if (ngx_strcmp(value[1].data, "exp") == 0) {
        if (nelts == 4) return "expected at most 2 arguments for exp validation directive";
        if (field->exp != NGX_CONF_UNSET) return "is duplicate";

        
        if (nelts == 2) {
            field->exp = 0;
            return NGX_CONF_OK;
        }
        
        ngx_int_t leeway;
        leeway = ngx_atoi(value[2].data, value[2].len); // This function only accept non negative value (documented behaviour).
        if (leeway == NGX_ERROR || leeway > 2147483647) return "got invalid leeway";

        field->exp = leeway;
        return NGX_CONF_OK;
    }
    
    if (ngx_strcmp(value[1].data, "nbf") == 0) {
        if (nelts == 4) return "expected at most 2 arguments for nbf validation directive";
        if (field->nbf != NGX_CONF_UNSET) return "is duplicate";

        
        if (nelts == 2) {
            field->nbf = 0;
            return NGX_CONF_OK;
        }
        
        ngx_int_t leeway;
        leeway = ngx_atoi(value[2].data, value[2].len); // This function only accept non negative value (documented behaviour).
        if (leeway == NGX_ERROR || leeway > 2147483647) return "got invalid leeway";

        field->nbf = leeway;
        return NGX_CONF_OK;
    }

    // Regular value claims
    
    ngx_queue_t *q;
    ngx_int_t int_value;
    ngx_str_t str_value;
    json_t *json_value;
    ngx_http_jwt_validate_claim_t *claim_value;
    ngx_http_jwt_validate_claim_t *claim;

    if (nelts != 4) {
        return "expected 3 arguments for custom claim validation directive";
    }

    if (value[1].len == 0 || value[1].len >= NGX_HTTP_JWT_CLAIM_NAME_LEN_MAX) {
        return "got invalid claim name";
    }

    for (q = ngx_queue_head(&field->claims);
         q != ngx_queue_sentinel(&field->claims);
         q = ngx_queue_next(q)) {
        claim = ngx_queue_data(q, ngx_http_jwt_validate_claim_t, queue);
        if (ngx_strcmp(claim->name.data, value[1].data) == 0) {
            return "got duplicate claims";
        }
    }

    claim_value = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_validate_claim_t));
    if (claim_value == NULL) {
        return NGX_CONF_ERROR;
    }

    claim_value->name = value[1];

    switch (value[2].data[0]) {
        case 'i':
            if (ngx_strcmp(value[2].data, "int") != 0) return "got invalid claim type";
            claim_value->type = JWT_VALUE_INT;
            if (value[3].len == 0) return "got invalid claim value";
            if (value[3].data[0] == '-') {
                int_value = ngx_atoi(value[3].data + 1, value[3].len - 1);
                if (int_value == NGX_ERROR) return "got invalid claim value";
                int_value *= -1;
            } else {
                int_value = ngx_atoi(value[3].data, value[3].len);
                if (int_value == NGX_ERROR) return "got invalid claim value";
            }
            if (int_value > NGX_HTTP_JWT_CLAIM_VALUE_INT_MAX
             || int_value < NGX_HTTP_JWT_CLAIM_VALUE_INT_MIN)
                return "got invalid claim value";
            claim_value->int_val = int_value;
            break;
        case 's':
            if (ngx_strcmp(value[2].data, "str") != 0) return "got invalid claim type";
            claim_value->type = JWT_VALUE_STR;
            str_value = value[3];
            if (str_value.len >= NGX_HTTP_JWT_CLAIM_VALUE_LEN_MAX) return "got invalid claim value";
            claim_value->str_val = str_value;
            break;
        case 'b':
            if (ngx_strcmp(value[2].data, "bool") != 0) return "got invalid claim type";
            claim_value->type = JWT_VALUE_BOOL;
            if (ngx_strcmp(value[3].data, "true") == 0) {
                claim_value->bool_val = 1;
            }
            else if (ngx_strcmp(value[3].data, "false") == 0) {
                claim_value->bool_val = 0;
            }
            else {
                return "got invalid claim value";
            }
            break;
        case 'j':
            if (ngx_strcmp(value[2].data, "json") != 0) return "got invalid claim type";
            claim_value->type = JWT_VALUE_JSON;
            str_value = value[3];
            if (str_value.len >= NGX_HTTP_JWT_CLAIM_VALUE_LEN_MAX) return "got invalid claim value";
            json_value = ngx_http_jwt_json_loads((const char *) str_value.data);
            if (json_value == NULL) return "got invalid claim value";
            claim_value->json_val = json_value;
            break;
        default:
            return "got invalid claim type";
            break;
    }

    ngx_queue_insert_head(&field->claims, &claim_value->queue);

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

    if (value[3].len == 0 || value[3].len >= NGX_HTTP_JWT_HEADER_NAME_LEN_MAX) {
        return "got invalid header name";
    }

    ngx_queue_t *q;
    ngx_http_jwt_extract_claim_t *claim;

    for (q = ngx_queue_head(&field->claims);
         q != ngx_queue_sentinel(&field->claims);
         q = ngx_queue_next(q)) {
        claim = ngx_queue_data(q, ngx_http_jwt_extract_claim_t, queue);
        if (ngx_strcmp(claim->claim_name.data, value[1].data) == 0) {
            return "got duplicate claims";
        }
        if (ngx_strcasecmp(claim->header_name.data, value[3].data) == 0) {
            return "got duplicate headers";
        }
    }

    ngx_int_t i;
    ngx_http_header_t  *header;

    for (i = 0; i < value[3].len; i++) {
        if ((value[3].data[i] >= '0' && value[3].data[i] <= '9')
            || (value[3].data[i] >= 'A' && value[3].data[i] <= 'Z')
            || (value[3].data[i] >= 'a' && value[3].data[i] <= 'z')
            || value[3].data[i] == '-'
            || value[3].data[i] == '_')
        {
            continue;
        }
        return "got invalid header name";
    }

    for (header = ngx_http_headers_in; header->name.len; header++) {
        if (value[3].len == header->name.len
            && ngx_strncasecmp(value[3].data, header->name.data, value[3].len) == 0)
        {
            return "got invalid header name";
        }
    }

    claim = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_extract_claim_t));
    if (claim == NULL) {
        return NGX_CONF_ERROR;
    }
    claim->claim_name = value[1];
    claim->header_name = value[3];
    switch (value[2].data[0]) {
        case 'i':
            if (ngx_strcmp(value[2].data, "int") != 0) return "got invalid claim type";
                claim->type = JWT_VALUE_INT;
                break;
        case 's':
            if (ngx_strcmp(value[2].data, "str") != 0) return "got invalid claim type";
                claim->type = JWT_VALUE_STR;
                break;
        case 'b':
            if (ngx_strcmp(value[2].data, "bool") != 0) return "got invalid claim type";
                claim->type = JWT_VALUE_BOOL;
                break;
        case 'j':
            if (ngx_strcmp(value[2].data, "json") != 0) return "got invalid claim type";
                claim->type = JWT_VALUE_JSON;
                break;
        default:
            return "got invalid claim type";
            break;
    }
    ngx_queue_insert_head(&field->claims, &claim->queue);

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
    ngx_conf_merge_ptr_value(conf->jwks, prev->jwks, NGX_CONF_UNSET_PTR);
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
        if (found == 1) continue;

        validate_claim_conf = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_validate_claim_t));
        if (validate_claim_conf == NULL) {
            return NGX_CONF_ERROR;
        }
        validate_claim_conf->name = validate_claim_prev->name;
        validate_claim_conf->type = validate_claim_prev->type;
        switch (validate_claim_prev->type) {
            case JWT_VALUE_INT:
                validate_claim_conf->int_val = validate_claim_prev->int_val;
                break;
            case JWT_VALUE_STR:
                validate_claim_conf->str_val = validate_claim_prev->str_val;
                break;
            case JWT_VALUE_BOOL:
                validate_claim_conf->bool_val = validate_claim_prev->bool_val;
                break;
            case JWT_VALUE_JSON:
                validate_claim_conf->json_val = ngx_http_jwt_json_deep_copy(validate_claim_prev->json_val);
                if (validate_claim_conf->json_val == NULL) {
                    return NGX_CONF_ERROR;
                }
                break;
            default:
                return NGX_CONF_ERROR;
                break;
        }
        ngx_queue_insert_head(&conf->validate.claims, &validate_claim_conf->queue);
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
        if (found == 1) continue;

        extract_claim_conf = ngx_palloc(cf->pool, sizeof(ngx_http_jwt_extract_claim_t));
        if (extract_claim_conf == NULL) {
            return NGX_CONF_ERROR;
        }
        extract_claim_conf->claim_name = extract_claim_prev->claim_name;
        extract_claim_conf->type = extract_claim_prev->type;
        extract_claim_conf->header_name = extract_claim_prev->header_name;
        ngx_queue_insert_head(&conf->extract.claims, &extract_claim_conf->queue);
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

static ngx_int_t ngx_http_jwt_request_handler(ngx_http_request_t *r) {
    ngx_http_jwt_loc_conf_t *jwt_lcf = r->loc_conf[ngx_http_jwt_module.ctx_index];

    if (jwt_lcf->enable == 0) {
        return NGX_DECLINED;
    }

    // Fetch & filter

    ngx_table_elt_t *authorization;
    ngx_int_t len;
    char *token;
    
    authorization = r->headers_in.authorization;
    if (authorization == NULL
     || authorization->value.len <= (sizeof("Bearer ") - 1)
     || ngx_strncasecmp(authorization->value.data, (u_char *) "Bearer ", sizeof("Bearer ") - 1) != 0) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: invalid authorization header");
        return jwt_lcf->error_code;
    }

    len = authorization->value.len - (sizeof("Bearer ") - 1);

    token = ngx_palloc(r->pool, len + 1);
    ngx_memcpy(token, authorization->value.data + (sizeof("Bearer ") - 1), len);
    token[len] = '\0';

    if (jwt_lcf->filter == 1) {
        if (ngx_http_jwt_request_filter_authorization(r) != NGX_OK) {
            ngx_pfree(r->pool, token);
            return jwt_lcf->error_code;
        }
    }

    // Checker & callback

    jwt_checker_t *checker = jwt_checker_new();
    if (checker == NULL) {
        ngx_pfree(r->pool, token);
        return jwt_lcf->error_code;
    }

    // Use custom exp / nbf check in callback for clearer responsibility boundary and better performance (use nginx cached time).

    if (jwt_checker_time_leeway(checker, JWT_CLAIM_EXP, -1) != 0) {
        ngx_pfree(r->pool, token);
        jwt_checker_free(checker);
        return jwt_lcf->error_code;
    }
    if (jwt_checker_time_leeway(checker, JWT_CLAIM_NBF, -1) != 0) {
        ngx_pfree(r->pool, token);
        jwt_checker_free(checker);
        return jwt_lcf->error_code;
    }
    jwt_checker_setcb(checker, ngx_http_jwt_request_handler_checker_callback, r);

    if (jwt_checker_verify(checker, token) != 0) {
        ngx_pfree(r->pool, token);
        jwt_checker_free(checker);
        return jwt_lcf->error_code;
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
    jwk_set_t *jwks;
    jwk_item_t *key;

    jwks = jwt_lcf->jwks;
    if (jwks == NGX_CONF_UNSET_PTR) {
        // This is done runtime because a default key will be added in future.
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: No jwks found");
        return -1;
    }

    jwt_set_GET_STR(&kid, "kid");

    if (jwt_header_get(jwt, &kid) != JWT_VALUE_ERR_NONE || kid.str_val == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: No kid found");
        return -1;
    }

    key = jwks_find_bykid(jwks, kid.str_val);
    if (key == NULL) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: No jwk for kid");
        return -1;
    }

    config->alg = jwt_get_alg(jwt);

    if (config->alg == JWT_ALG_NONE || jwks_item_alg(key) != config->alg) {
        ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: algorithm does not match");
        return -1;
    }

    config->key = key;

    // Validate exp / nbf
    
    jwt_value_t value;

    if (jwt_lcf->validate.exp != NGX_CONF_UNSET) {
        jwt_set_GET_INT(&value, "exp");
        if (jwt_claim_get(jwt, &value) != JWT_VALUE_ERR_NONE) {
            return -1;
        }
        if (value.int_val <= (ngx_time() - jwt_lcf->validate.exp)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: exp validation failed");
            return -1;
        }
    }

    if (jwt_lcf->validate.nbf != NGX_CONF_UNSET) {
        jwt_set_GET_INT(&value, "nbf");
        if (jwt_claim_get(jwt, &value) != JWT_VALUE_ERR_NONE) {
            return -1;
        }
        if (value.int_val > (ngx_time() + jwt_lcf->validate.nbf)) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: nbf validation failed");
            return -1;
        }
    }

    // Validate value claims

    ngx_queue_t *q;
    ngx_http_jwt_validate_claim_t *validate_claim;
    ngx_http_jwt_extract_claim_t *extract_claim;
    json_t *json_val;

    for (q = ngx_queue_head(&jwt_lcf->validate.claims);
         q != ngx_queue_sentinel(&jwt_lcf->validate.claims);
         q = ngx_queue_next(q)) {

        validate_claim = ngx_queue_data(q, ngx_http_jwt_validate_claim_t, queue);
        value.name = (const char *) validate_claim->name.data;
        value.type = validate_claim->type;
        value.error = JWT_VALUE_ERR_NONE;
        value.pretty = 0;

        if (jwt_claim_get(jwt, &value) != JWT_VALUE_ERR_NONE) {
            ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: validation failed");
            return -1;
        }

        switch (value.type) {
            case JWT_VALUE_INT:
                if (validate_claim->int_val != value.int_val) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: validation failed");
                    return -1;
                }
                break;
            case JWT_VALUE_STR:
                if (ngx_strcmp(validate_claim->str_val.data, value.str_val) != 0) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: validation failed");
                    return -1;
                }
                break;
            case JWT_VALUE_BOOL:
                if (validate_claim->bool_val != value.bool_val) {
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: validation failed");
                    return -1;
                }
                break;
            case JWT_VALUE_JSON:
                json_val = json_loads((const char *) value.json_val, JSON_REJECT_DUPLICATES, NULL);
                if (json_val == NULL) {
                    free(value.json_val);
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: validation failed");
                    return -1;
                }
                if (!json_equal(validate_claim->json_val, json_val)) {
                    free(value.json_val);
                    json_decref(json_val);
                    ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: validation failed");
                    return -1;
                }
                free(value.json_val);
                json_decref(json_val);
                break;
            default:
                ngx_log_error(NGX_LOG_ERR, r->connection->log, 0, "JWT: validation failed");
                return -1;
                break;
        }
    }

    // Extract value claims

    ngx_str_t raw;
    ngx_int_t val, len, negative;
    ngx_str_t encoded;

    for (q = ngx_queue_head(&jwt_lcf->extract.claims);
         q != ngx_queue_sentinel(&jwt_lcf->extract.claims);
         q = ngx_queue_next(q)) {
        extract_claim = ngx_queue_data(q, ngx_http_jwt_extract_claim_t, queue);
        value.name = (const char *) extract_claim->claim_name.data;
        value.type = extract_claim->type;
        value.error = JWT_VALUE_ERR_NONE;
        value.pretty = 0;

        // Get claim

        const ngx_str_t null_string = ngx_null_string;

        if (jwt_claim_get(jwt, &value) != JWT_VALUE_ERR_NONE) {
            if (ngx_http_jwt_request_filter_header(r, extract_claim->header_name, null_string) == NGX_OK) {
                continue;
            }
            return -1;
        }

        // Extract by type

        switch (value.type) {
            case JWT_VALUE_STR:
                raw.data = (u_char *) value.str_val;
                raw.len = ngx_strlen(value.str_val);

                if (raw.len >= NGX_HTTP_JWT_CLAIM_VALUE_LEN_MAX) {
                    if (ngx_http_jwt_request_filter_header(r, extract_claim->header_name, null_string) != NGX_OK) {
                        return -1;
                    }
                    break;
                }

                encoded.data = ngx_palloc(r->pool, ngx_base64_encoded_length(raw.len));
                if (encoded.data == NULL) {
                    return -1;
                }
                ngx_encode_base64url(&encoded, &raw);
                if (ngx_http_jwt_request_filter_header(r, extract_claim->header_name, encoded) != NGX_OK) {
                    ngx_pfree(r->pool, encoded.data);
                    return -1;
                }
                ngx_pfree(r->pool, encoded.data);
                break;
            case JWT_VALUE_INT:
                if (value.int_val > NGX_HTTP_JWT_CLAIM_VALUE_INT_MAX || value.int_val < NGX_HTTP_JWT_CLAIM_VALUE_INT_MIN) {
                    if (ngx_http_jwt_request_filter_header(r, extract_claim->header_name, null_string) != NGX_OK) {
                        return -1;
                    }
                    break;
                }

                encoded.data = ngx_palloc(r->pool, NGX_ATOMIC_T_LEN);
                if (encoded.data == NULL) return -1;

                encoded.len = ngx_sprintf(encoded.data, "%d", value.int_val) - encoded.data;

                if (ngx_http_jwt_request_filter_header(r, extract_claim->header_name, encoded) != NGX_OK) {
                    ngx_pfree(r->pool, encoded.data);
                    return -1;
                }
                ngx_pfree(r->pool, encoded.data);
                break;
            case JWT_VALUE_BOOL:
                if (value.bool_val) {
                    encoded.data = (u_char *) "true";
                    encoded.len = 4;
                } else {
                    encoded.data = (u_char *) "false";
                    encoded.len = 5;
                }
                if (ngx_http_jwt_request_filter_header(r, extract_claim->header_name, encoded) != NGX_OK) {
                    return -1;
                }
                break;
            case JWT_VALUE_JSON:
                raw.data = (u_char *) value.json_val;
                raw.len = ngx_strlen(value.json_val);

                if (raw.len >= NGX_HTTP_JWT_CLAIM_VALUE_LEN_MAX) {
                    if (ngx_http_jwt_request_filter_header(r, extract_claim->header_name, null_string) != NGX_OK) {
                        return -1;
                    }
                    break;
                }

                encoded.data = ngx_palloc(r->pool, ngx_base64_encoded_length(raw.len));
                if (encoded.data == NULL) {
                    free(value.json_val);
                    return -1;
                }
                ngx_encode_base64url(&encoded, &raw);
                if (ngx_http_jwt_request_filter_header(r, extract_claim->header_name, encoded) != NGX_OK) {
                    free(value.json_val);
                    ngx_pfree(r->pool, encoded.data);
                    return -1;
                }
                free(value.json_val);
                ngx_pfree(r->pool, encoded.data);
                break;
            default:
                return -1;
                break;
        }
    }

    return 0;
}