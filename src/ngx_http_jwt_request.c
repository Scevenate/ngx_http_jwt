
/*
 * Copyright (C) Scevenate
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt_request.h>


static ngx_int_t ngx_http_jwt_request_apply_filter_header(ngx_http_request_t *r, ngx_str_t key, ngx_str_t value);


ngx_int_t ngx_http_jwt_request_init(ngx_http_jwt_request_transaction_t *transaction) {
    transaction->filter_authorization = 0;
    ngx_queue_init(&transaction->filter);
    return NGX_OK;
}

ngx_int_t ngx_http_jwt_request_free(ngx_http_request_t *r, ngx_http_jwt_request_transaction_t *transaction) {
    ngx_queue_t *q, *next;
    ngx_http_jwt_request_filter_header *entry;

    for (q = ngx_queue_head(&transaction->filter);
         q != ngx_queue_sentinel(&transaction->filter);
         q = next) {
        next = ngx_queue_next(q);
        entry = ngx_queue_data(q, ngx_http_jwt_request_filter_header, queue);
        ngx_pfree(r->pool, entry);
    }

    return NGX_OK;
}

ngx_int_t ngx_http_jwt_request_set_authorization(ngx_http_jwt_request_transaction_t *transaction) {
    transaction->filter_authorization = 1;
    return NGX_OK;
}

ngx_int_t ngx_http_jwt_request_set_header(ngx_http_request_t *r,
    ngx_http_jwt_request_transaction_t *transaction, ngx_str_t key, ngx_str_t value) {
    ngx_http_jwt_request_filter_header *entry;

    entry = ngx_palloc(r->pool, sizeof(ngx_http_jwt_request_filter_header));
    if (entry == NULL) {
        return NGX_ERROR;
    }

    entry->name.data = ngx_pnalloc(r->pool, key.len);
    if (entry->name.data == NULL) {
        ngx_pfree(r->pool, entry);
        return NGX_ERROR;
    }
    entry->name.len = key.len;
    ngx_memcpy(entry->name.data, key.data, key.len);

    if (value.data == NULL) {
        entry->value.len = 0;
        entry->value.data = NULL;
    } else {
        entry->value.len = value.len;
        entry->value.data = ngx_pnalloc(r->pool, value.len);
        if (entry->value.data == NULL) {
            ngx_pfree(r->pool, entry->name.data);
            ngx_pfree(r->pool, entry);
            return NGX_ERROR;
        }
        ngx_memcpy(entry->value.data, value.data, value.len);
        entry->value.data[value.len] = '\0';
    }

    ngx_queue_insert_tail(&transaction->filter, &entry->queue);

    return NGX_OK;
}

ngx_int_t ngx_http_jwt_request_apply(ngx_http_request_t *r, ngx_http_jwt_request_transaction_t *transaction) {
    ngx_queue_t *q;
    ngx_http_jwt_request_filter_header *entry;
    static const ngx_str_t null_string = ngx_null_string;
    static const ngx_str_t authorization = ngx_string("Authorization");

    if (transaction->filter_authorization) {
        r->headers_in.authorization = NULL;

        if (ngx_http_jwt_request_apply_filter_header(r, authorization, null_string) != NGX_OK) {
            ngx_http_jwt_request_free(r, transaction);
            return NGX_ERROR;
        }
    }

    for (q = ngx_queue_head(&transaction->filter);
         q != ngx_queue_sentinel(&transaction->filter);
         q = ngx_queue_next(q))
    {
        entry = ngx_queue_data(q, ngx_http_jwt_request_filter_header, queue);

        if (ngx_http_jwt_request_apply_filter_header(r, entry->name, entry->value) != NGX_OK) {
            ngx_http_jwt_request_free(r, transaction);
            return NGX_ERROR;
        }
    }

    ngx_http_jwt_request_free(r, transaction);

    return NGX_OK;
}

static ngx_int_t ngx_http_jwt_request_apply_filter_header(ngx_http_request_t *r, ngx_str_t key, ngx_str_t value) {
    ngx_uint_t i;
    ngx_list_part_t *part;
    ngx_table_elt_t *hi, *h;
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

    if (value.data == NULL) {
        return NGX_OK;
    }

    if (h == NULL) {
        h = ngx_list_push(&r->headers_in.headers);
        if (h == NULL) {
            return NGX_ERROR;
        }
    }

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
