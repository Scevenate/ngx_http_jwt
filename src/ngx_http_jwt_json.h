
/*
 * Copyright (C) Scevenate
 *
 * This file manages configuration JSON object per cycle memory.
 */


#ifndef NGX_HTTP_JWT_JSON_H
#define NGX_HTTP_JWT_JSON_H

#include <ngx_config.h>
#include <ngx_core.h>
#include <jansson.h>

// This function only decodes object or array.
json_t *ngx_http_jwt_json_loads(const char *str);

json_t *ngx_http_jwt_json_deep_copy(json_t *json);

ngx_int_t ngx_http_jwt_json_cycle_init(ngx_cycle_t *cycle);

#endif /* NGX_HTTP_JWT_JSON_H */