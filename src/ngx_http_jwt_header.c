/*
 * Copyright (C) Scevenate
 */


#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <ngx_http_jwt_header.h>
#include <jwt.h>
#include <string.h>


#define NGX_HTTP_JWT_HEADER_MAX_LEN 2048
#define NGX_HTTP_JWT_VALUE_MAX_LEN 2048


static ngx_int_t ngx_http_jwt_header_remove(ngx_http_request_t *r,
    ngx_str_t *key);
static ngx_int_t ngx_http_jwt_header_value_check(jwt_value_t *value);


ngx_int_t
ngx_http_jwt_header_check(ngx_str_t *key)
{
    ngx_uint_t          i;
    ngx_http_header_t  *header;

    if (key->len > NGX_HTTP_JWT_HEADER_MAX_LEN) {
        return NGX_ERROR;
    }

    for (i = 0; i < key->len; i++) {
        if ((key->data[i] >= '0' && key->data[i] <= '9')
            || (key->data[i] >= 'A' && key->data[i] <= 'Z')
            || (key->data[i] >= 'a' && key->data[i] <= 'z')
            || key->data[i] == '-'
            || key->data[i] == '_')
        {
            continue;
        }

        return NGX_ERROR;
    }

    for (header = ngx_http_headers_in; header->name.len; header++) {
        if (key->len == header->name.len
            && ngx_strncasecmp(key->data, header->name.data, key->len) == 0)
        {
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}


ngx_int_t
ngx_http_jwt_header_filter_authorization(ngx_http_request_t *r)
{
    static ngx_str_t authorization = ngx_string("Authorization");

    r->headers_in.authorization = NULL;

    return ngx_http_jwt_header_remove(r, &authorization);
}


ngx_int_t
ngx_http_jwt_header_filter(ngx_http_request_t *r, ngx_str_t *key,
    jwt_value_t *value)
{
    ngx_table_elt_t  *h;
    u_char           *p;
    size_t            len;
    ngx_uint_t        hash;

    if (ngx_http_jwt_header_value_check(value) != NGX_OK) {
        return ngx_http_jwt_header_remove(r, key);
    }

    if (ngx_http_jwt_header_remove(r, key) != NGX_OK) {
        return NGX_ERROR;
    }

    h = ngx_list_push(&r->headers_in.headers);
    if (h == NULL) {
        return NGX_ERROR;
    }

    ngx_memzero(h, sizeof(ngx_table_elt_t));

    h->key.len = key->len;
    h->key.data = ngx_pnalloc(r->pool, key->len + 1);
    if (h->key.data == NULL) {
        return NGX_ERROR;
    }
    ngx_memcpy(h->key.data, key->data, key->len);
    h->key.data[key->len] = '\0';

    h->lowcase_key = ngx_pnalloc(r->pool, key->len);
    if (h->lowcase_key == NULL) {
        return NGX_ERROR;
    }
    hash = ngx_hash_strlow(h->lowcase_key, key->data, key->len);

    len = strlen(value->str_val);
    h->value.len = len + 2;
    h->value.data = ngx_pnalloc(r->pool, h->value.len + 1);
    if (h->value.data == NULL) {
        return NGX_ERROR;
    }

    p = h->value.data;
    *p++ = '"';
    p = ngx_cpymem(p, value->str_val, len);
    *p++ = '"';
    *p = '\0';
    h->hash = hash;

    return NGX_OK;
}


static ngx_int_t
ngx_http_jwt_header_remove(ngx_http_request_t *r, ngx_str_t *key)
{
    ngx_uint_t        i;
    ngx_list_part_t  *part;
    ngx_table_elt_t  *h;

    part = &r->headers_in.headers.part;
    h = part->elts;

    for (i = 0; /* void */; i++) {
        if (i >= part->nelts) {
            if (part->next == NULL) {
                break;
            }

            part = part->next;
            h = part->elts;
            i = 0;
        }

        if (h[i].hash != 0
            && h[i].key.len == key->len
            && ngx_strncasecmp(h[i].key.data, key->data, key->len) == 0)
        {
            h[i].hash = 0;
        }
    }

    return NGX_OK;
}


static ngx_int_t
ngx_http_jwt_header_value_check(jwt_value_t *value)
{
    const u_char  *p;
    size_t         len, i;

    if (value == NULL || value->str_val == NULL) {
        return NGX_ERROR;
    }

    len = strlen(value->str_val);
    if (len > NGX_HTTP_JWT_VALUE_MAX_LEN) {
        return NGX_ERROR;
    }

    p = (const u_char *) value->str_val;
    for (i = 0; i < len; i++) {
        if ((p[i] >= '0' && p[i] <= '9')
            || (p[i] >= 'A' && p[i] <= 'Z')
            || (p[i] >= 'a' && p[i] <= 'z'))
        {
            continue;
        }

        switch (p[i]) {
        case '_':
        case '-':
        case ' ':
        case ':':
        case ';':
        case '.':
        case ',':
        case '/':
        case '\'':
        case '?':
        case '!':
        case '(':
        case ')':
        case '{':
        case '}':
        case '[':
        case ']':
        case '@':
        case '<':
        case '>':
        case '=':
        case '+':
        case '*':
        case '#':
        case '$':
        case '&':
        case '`':
        case '|':
        case '~':
        case '^':
        case '%':
            continue;
        default:
            return NGX_ERROR;
        }
    }

    return NGX_OK;
}
