#include <ngx_config.h>
#include <ngx_core.h>
#include <ngx_http.h>
#include <jansson.h>
#include <ngx_http_jwt_json.h>
#include <stdlib.h>
#include <stddef.h>


typedef struct {
    json_t *json;
    ngx_queue_t queue;
} ngx_http_jwt_json_t;

static ngx_queue_t json_queue = { .prev = NULL, .next = NULL };
static ngx_cycle_t *cycle = NULL;

json_t *ngx_http_jwt_json_loads(const char *s) {
    if (cycle == NULL) {
        return NULL;
    }

    ngx_http_jwt_json_t *json_item;
    
    json_item = (ngx_http_jwt_json_t *) ngx_alloc(sizeof(ngx_http_jwt_json_t), cycle->log);
    if (json_item == NULL) {
        return NULL;
    }
    ngx_queue_init(&json_item->queue);

    json_item->json = json_loads(s, JSON_REJECT_DUPLICATES, NULL);
    if (json_item->json == NULL) {
        // This is reject not error
        free(json_item);
        return NULL;
    }
    ngx_queue_insert_head(&json_queue, &json_item->queue);
    return json_item->json;
}

json_t *ngx_http_jwt_json_deep_copy(json_t *json) {
    if (cycle == NULL) {
        return NULL;
    }

    ngx_http_jwt_json_t *json_item;
    
    json_item = (ngx_http_jwt_json_t *) ngx_alloc(sizeof(ngx_http_jwt_json_t), cycle->log);
    if (json_item == NULL) {
        return NULL;
    }

    json_item->json = json_deep_copy(json);
    if (json_item->json == NULL) {
        ngx_log_error(NGX_LOG_ERR, cycle->log, 0, "JSON: could not deep copy JSON");
        free(json_item);
        return NULL;
    }

    ngx_queue_insert_head(&json_queue, &json_item->queue);
    return json_item->json;
}

ngx_int_t ngx_http_jwt_json_cycle_init(ngx_cycle_t *new_cycle) {
    if (cycle != NULL) {
        ngx_queue_t *q;
        ngx_http_jwt_json_t *json_item;

        for (q = ngx_queue_head(&json_queue);
            q != ngx_queue_sentinel(&json_queue);
            q = ngx_queue_head(&json_queue)) {
            json_item = (ngx_http_jwt_json_t *) ngx_queue_data(q, ngx_http_jwt_json_t, queue);
            ngx_queue_remove(q);
            json_decref(json_item->json);
            free(json_item);
        }
    } else {
        ngx_queue_init(&json_queue);
    }

    cycle = new_cycle;

    ngx_log_debug0(NGX_LOG_DEBUG_HTTP, cycle->log, 0, "JSON: cycle initialized");

    return NGX_OK;
}