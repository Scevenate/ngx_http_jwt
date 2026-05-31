
/*
 * Copyright (C) Scevenate
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt_request.h>


ngx_int_t ngx_http_jwt_request_filter_authorization(ngx_http_request_t *r)
{
    r->headers_in.authorization = NULL;

    static ngx_str_t authorization = ngx_string("Authorization");
    static ngx_str_t null_string = ngx_null_string;

    // This header is filtered by the following function that is capable of erasing all appearances of the header. Just erasing lookup pointer may miss duplicates.
    return ngx_http_jwt_request_filter_header(r, authorization, null_string);
}

ngx_int_t ngx_http_jwt_request_filter_header(ngx_http_request_t *r, ngx_str_t key, ngx_str_t value)
{
    ngx_uint_t i;
    ngx_list_part_t *part;
    ngx_table_elt_t *hi, *h;
    u_char *p;
    size_t len;
    ngx_uint_t hash;

    part = &r->headers_in.headers.part;
    hi = part->elts;
    h = NULL;

    for (i = 0;; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            hi = part->elts;
            i = 0;
        }

        if (hi[i].hash != 0
         && hi[i].key.len == key.len
         && ngx_strncasecmp(hi[i].key.data, key.data, key.len) == 0)
        {
            hi[i].hash = 0;
            h = &hi[i];
        }
    }

    if (value.data == NULL) return NGX_OK;

    if (h == NULL) {
        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }
    }

    // Safeguards error return
    h->next = NULL;
    h->hash = 0;

    h->key.len = key.len;
    h->key.data = ngx_pnalloc(r->pool, key.len + 1);
    if (h->key.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(h->key.data, key.data, key.len);
    h->key.data[key.len] = '\0';

    h->lowcase_key = ngx_pnalloc(r->pool, key.len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_hash_strlow(h->lowcase_key, key.data, key.len);

    h->value.len = value.len;
    h->value.data = ngx_pnalloc(r->pool, h->value.len + 1);
    if (h->value.data == NULL) {
        return NGX_ERROR;
    }

    ngx_memcpy(h->value.data, value.data, value.len);
    h->value.data[value.len] = '\0';

    h->hash = hash;

    return NGX_OK;
}
