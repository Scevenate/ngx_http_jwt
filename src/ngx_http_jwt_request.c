
/*
 * Copyright (C) Scevenate
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt.h>


ngx_http_jwt_request_transaction_t *ngx_http_jwt_request_init(ngx_http_request_t *r) {
    ngx_http_jwt_request_transaction_t *transaction = ngx_palloc(r->pool, sizeof(ngx_http_jwt_request_transaction_t));
    if (transaction == NULL) {
        return NULL;
    }
    transaction->r = r;
    ngx_queue_init(&transaction->filter);
    return transaction;
}

void ngx_http_jwt_request_free(ngx_http_jwt_request_transaction_t *transaction) {
    ngx_queue_t *q, *next;
    ngx_http_jwt_request_header_t *entry;

    for (q = ngx_queue_head(&transaction->filter);
         q != ngx_queue_sentinel(&transaction->filter);
         q = next) {
        next = ngx_queue_next(q);
        entry = ngx_queue_data(q, ngx_http_jwt_request_header_t, queue);
        ngx_pfree(transaction->r->pool, entry->name.data);
        ngx_pfree(transaction->r->pool, entry->value.data);
        ngx_pfree(transaction->r->pool, entry);
    }

    ngx_pfree(transaction->r->pool, transaction);
}

ngx_int_t ngx_http_jwt_request_set_header(ngx_http_jwt_request_transaction_t *transaction, ngx_str_t name, ngx_str_t value) {
    ngx_http_jwt_request_header_t *entry;

    entry = ngx_palloc(transaction->r->pool, sizeof(ngx_http_jwt_request_header_t));
    if (entry == NULL) {
        return NGX_ERROR;
    }

    entry->name.data = ngx_pnalloc(transaction->r->pool, name.len + 1);
    if (entry->name.data == NULL) {
        ngx_pfree(transaction->r->pool, entry);
        return NGX_ERROR;
    }
    entry->name.len = name.len;
    ngx_memcpy(entry->name.data, name.data, name.len);
    entry->name.data[name.len] = '\0';

    if (value.data == NULL) {
        entry->value.len = 0;
        entry->value.data = NULL;
    } else {
        entry->value.data = ngx_pnalloc(transaction->r->pool, value.len + 1);
        if (entry->value.data == NULL) {
            ngx_pfree(transaction->r->pool, entry->name.data);
            ngx_pfree(transaction->r->pool, entry);
            return NGX_ERROR;
        }
        entry->value.len = value.len;
        ngx_memcpy(entry->value.data, value.data, value.len);
        entry->value.data[value.len] = '\0';
    }

    ngx_queue_insert_tail(&transaction->filter, &entry->queue);

    return NGX_OK;
}

ngx_int_t ngx_http_jwt_request_apply(ngx_http_jwt_request_transaction_t *transaction) {
    ngx_queue_t *q, *next;
    ngx_http_jwt_request_header_t *entry;
    ngx_uint_t i;
    ngx_list_part_t *part;
    ngx_table_elt_t *h, **hr;
    ngx_http_header_t *hh;
    ngx_uint_t hash;

    for (q = ngx_queue_head(&transaction->filter);
         q != ngx_queue_sentinel(&transaction->filter);
         q = ngx_queue_next(q)) {
        entry = ngx_queue_data(q, ngx_http_jwt_request_header_t, queue);
        part = &transaction->r->headers_in.headers.part;
        h = part->elts;

        // Find hr: reserved header pointer
        hr = NULL;
        for (hh = ngx_http_headers_in; hh->name.len; hh++) {
            if (hh->name.len == entry->name.len
            && ngx_strncasecmp(hh->name.data, entry->name.data, entry->name.len) == 0)
            {
                hr = (ngx_table_elt_t **) (((char *) &transaction->r->headers_in) + hh->offset);
                break;
            }
        }

        // Remove existing headers
        for (i = 0;;) {
            if (i >= part->nelts) {
                if (part->next == NULL) {
                    break;
                }

                part = part->next;
                h = part->elts;
                i = 0;
                continue;
            }

            if (h[i].hash != 0
            && h[i].key.len == entry->name.len
            && ngx_strncasecmp(h[i].key.data, entry->name.data, entry->name.len) == 0)
            {
                /*
                * As of nginx v1.31.0, the proxy module does not respect hash = 0 header invalidation.
                * It still proxies the header value, so we have to actually remove the header (even it is discouraged for dealing with lists).
                * Null string / empty string makes it an empty line with only a colon, I've tried.
                */
                transaction->r->headers_in.count--;
                part->nelts--;
                h[i] = h[part->nelts];
                continue;
            }

            i++;
        }

        // Case 1: Just remove header
        if (entry->value.data == NULL) {
            if (hr != NULL) {
                *hr = NULL;
            }
            continue;
        }

        h = ngx_list_push(&transaction->r->headers_in.headers);
        if (h == NULL) return NGX_ERROR;
        transaction->r->headers_in.count++;
        h->next = NULL;
        h->hash = 0;

        // We move the ownership of entry data from transaction to the new header.
        // (This is why the transaction does not borrow data when setting action in the first place.)
        // A custom transaction free is performed at the bottom of this function.
        h->key.len = entry->name.len;
        h->key.data = entry->name.data;

        h->lowcase_key = ngx_pnalloc(transaction->r->pool, entry->name.len);
        if (h->lowcase_key == NULL) {
            // Doing free here just free the current header. Just be lazy, don't larp.
            return NGX_ERROR;
        }
        hash = ngx_hash_strlow(h->lowcase_key, entry->name.data, entry->name.len);

        h->value.len = entry->value.len;
        h->value.data = entry->value.data;
        h->hash = hash;
    }

    // Free transaction
    for (q = ngx_queue_head(&transaction->filter);
         q != ngx_queue_sentinel(&transaction->filter);
         q = next) {
        next = ngx_queue_next(q);
        entry = ngx_queue_data(q, ngx_http_jwt_request_header_t, queue);
        ngx_pfree(transaction->r->pool, entry);
    }
    ngx_http_jwt_request_free(transaction);

    return NGX_OK;
}
