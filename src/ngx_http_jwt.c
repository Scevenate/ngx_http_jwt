#include "ngx_conf_file.h"
#include "ngx_string.h"
#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jwt.h>

typedef struct {
    ngx_flag_t enable;
    jwk_set_t *jwks;
    ngx_int_t error_code;
    ngx_str_t iss;
} ngx_http_jwt_loc_conf_t;

static char *ngx_conf_set_jwks_file_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf);

static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf);
static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *prev, void *conf);

static ngx_int_t ngx_http_jwt_postconfiguration(ngx_conf_t *cf);

static ngx_command_t  ngx_http_jwt_commands[] = {
  { ngx_string("jwt"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_FLAG,
      ngx_conf_set_flag_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, enable),
      NULL },
    
  { ngx_string("jwks_file"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE2,
      ngx_conf_set_jwks_file_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, jwks),
      NULL },

  { ngx_string("jwt_iss"),
      NGX_HTTP_MAIN_CONF|NGX_HTTP_SRV_CONF|NGX_HTTP_LOC_CONF|NGX_CONF_TAKE1,
      ngx_conf_set_str_slot,
      NGX_HTTP_LOC_CONF_OFFSET,
      offsetof(ngx_http_jwt_loc_conf_t, iss),
      NULL },

  ngx_null_command
};

static ngx_http_module_t  ngx_http_jwt_module_ctx = {
    NULL,                                 /* preconfiguration */
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

static char *ngx_conf_set_jwks_file_slot(ngx_conf_t *cf, ngx_command_t *cmd, void *conf) {
    char *p = conf;

    jwk_set_t *field;
    ngx_str_t *value;
    ngx_conf_post_t *post;
    
    field = (jwk_set_t *) (p + cmd->offset);

    if (field != NGX_CONF_UNSET_PTR) {
        return "is duplicate";
    }

    value = cf->args->elts;

    field = jwks_create_fromfile((const char*) value[1].data);

    if (field == NULL) {
        ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "failed to create jwk set from file %s", value[1].data);
        return NGX_CONF_ERROR;
    }

    if (cmd->post) {
        post = cmd->post;
        return post->post_handler(cf, post, field);
    }

    return NGX_CONF_OK;
}

static void *ngx_http_jwt_create_loc_conf(ngx_conf_t *cf) {
    ngx_http_jwt_loc_conf_t *conf = ngx_pcalloc(cf->pool, sizeof(ngx_http_jwt_loc_conf_t));
    if (conf == NULL) {
        return NULL;
    }

    conf->enable = NGX_CONF_UNSET_UINT;
    conf->jwks = NGX_CONF_UNSET_PTR;
    conf->error_code = NGX_CONF_UNSET;
    ngx_str_null(&conf->iss);
    return conf;
}

static char *ngx_http_jwt_merge_loc_conf(ngx_conf_t *cf, void *parent, void *child) {
    ngx_http_jwt_loc_conf_t *prev = parent;
    ngx_http_jwt_loc_conf_t *conf = child;

    ngx_conf_merge_uint_value(conf->enable, prev->enable, 0);
    ngx_conf_merge_ptr_value(conf->jwks, prev->jwks, NGX_CONF_UNSET_PTR);
    ngx_conf_merge_str_value(conf->iss, prev->iss, "none");
    ngx_conf_merge_value(conf->error_code, prev->error_code, NGX_HTTP_FORBIDDEN);
    return NGX_CONF_OK;
}

static ngx_int_t ngx_http_jwt_postconfiguration(ngx_conf_t *cf)
{
    ngx_http_core_main_conf_t   *cmcf;
    ngx_uint_t                   s;
    ngx_http_core_srv_conf_t   **cscf;
    ngx_http_location_queue_t   *lq;
    ngx_queue_t                 *queue, *q;
    ngx_http_core_loc_conf_t    *clcf, *sclcf;
    ngx_http_jwt_loc_conf_t     *jwt_lcf;
    

    cmcf = ngx_http_conf_get_module_main_conf(cf, ngx_http_core_module);
    cscf = cmcf->servers.elts;

    for (s = 0; s < cmcf->servers.nelts; s++) {
        clcf = cscf[s]->ctx->loc_conf[ngx_http_jwt_module.ctx_index];
        queue = clcf->locations;

        if (queue == NULL) {
            continue;
        }

        for (q = ngx_queue_head(queue);
             q != ngx_queue_sentinel(queue);
             q = ngx_queue_next(q)) {
            lq = ngx_queue_data(q, ngx_http_location_queue_t, queue);

            sclcf = lq->exact ? lq->exact : lq->inclusive;

            if (sclcf == NULL) {
                continue;
            }

            jwt_lcf = sclcf->loc_conf[ngx_http_jwt_module.ctx_index];

            if (ngx_strcmp(jwt_lcf->iss.data, "none") == 0) {
                ngx_str_null(&jwt_lcf->iss);
            }

            if (jwt_lcf->enable == 1) {
                if (jwt_lcf->jwks == NULL) {
                    ngx_conf_log_error(NGX_LOG_EMERG, cf, 0, "jwks is required");
                    return NGX_ERROR;
                }
            }
        }
  }

  return NGX_OK;
}
