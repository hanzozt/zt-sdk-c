// Copyright (c) 2021-2023.  NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#include <zt/zt.h>
#include <string.h>
#include "zt/zt_log.h"

struct app_ctx {
    uv_loop_t *loop;
    zt_context ztx;

    model_map bindings;
};

typedef struct {
    char *service_id;
    char *service_name;
    zt_server_cfg_v1 *host_cfg;
    zt_connection server;
    struct app_ctx *app;
} host_binding;

typedef struct {
    zt_connection zt_conn;
    uv_tcp_t tcp;
} host_connection;

static const char *config_types[] = {
        "zt-tunneler-server.v1"
};

static void on_zt_event(zt_context ztx, const zt_event_t *event);

static void bind_service(struct app_ctx *app, zt_context ztx, zt_service *s, zt_server_cfg_v1 *host_cfg);

int main(int argc, char *argv[]) {
    uv_loop_t *loop = uv_default_loop();
    zt_log_init(loop, ZITI_LOG_DEFAULT_LEVEL, NULL);

    struct app_ctx ctx = {
            .loop = loop,
    };

    zt_config cfg;
    zt_context ztx = NULL;

#define check(op) do{ \
int err = (op); if (err != ZITI_OK) { \
fprintf(stderr, "ERROR: %s", zt_errorstr(err)); \
exit(err);\
}}while(0)

    check(zt_load_config(&cfg, argv[1]));
    check(zt_context_init(&ztx, &cfg));
    check(zt_context_set_options(ztx, &(zt_options){
            .app_ctx = &ctx,
            .refresh_interval = 60,
            .config_types = config_types,
            .event_cb = on_zt_event,
            .events = ZitiContextEvent | ZitiServiceEvent,
    }));

    zt_context_run(ztx, loop);

    uv_run(loop, UV_RUN_DEFAULT);
}

void on_zt_event(zt_context ztx, const zt_event_t *event) {
    struct app_ctx *ctx = zt_app_ctx(ztx);

    if (event->type == ZitiServiceEvent) {
        const struct zt_service_event *se = &event->service;
        for (int i = 0; se->added[i] != NULL; i++) {
            zt_service *s = se->added[i];
            if ((s->perm_flags & ZITI_CAN_BIND) == 0) {
                continue;
            }

            zt_server_cfg_v1 *host_cfg = calloc(1, sizeof(zt_server_cfg_v1));
            int rc = zt_service_get_config(s, config_types[0], host_cfg,
                                             (int (*)(void *, const char *, size_t)) parse_zt_server_cfg_v1);
            if (rc != ZITI_OK) {
                fprintf(stderr, "skipping service[%s] hosting config: %s\n", s->name, zt_errorstr(rc));
                free_zt_server_cfg_v1(host_cfg);
                free(host_cfg);
                continue;
            }

            bind_service(ctx, ztx, s, host_cfg);
        }
    }
}

/*************** Proxy functions ************/

static void on_tcp_write(uv_write_t *wr, int status) {
    free(wr->data);
    free(wr);
    if (status != 0) {
        fprintf(stderr, "failed to write to client: %s\n", uv_strerror(status));
    }
}

static void on_tcp_shutdown(uv_shutdown_t *sr, int status) {
    free(sr);
}

static void on_tcp_close(uv_handle_t *s) {
    host_connection *hc = s->data;
    free(hc);
}

static void zt_proxy_close_cb(zt_connection c) {
    host_connection *hc = zt_conn_data(c);
    uv_close((uv_handle_t *) &hc->tcp, on_tcp_close);
}

static ssize_t on_zt_data(zt_connection c, const uint8_t *b, ssize_t len) {
    host_connection *hc = zt_conn_data(c);

    if (len > 0) {
        uv_write_t *wr = calloc(1, sizeof(uv_write_t));

        char *copy = malloc(len);
        memcpy(copy, b, len);
        uv_buf_t buf = uv_buf_init(copy, len);

        wr->data = copy;
        uv_write(wr, (uv_stream_t *) &hc->tcp, &buf, 1, on_tcp_write);
    } else if (len == ZITI_EOF) {
        uv_shutdown_t *sr = calloc(1, sizeof(uv_shutdown_t));
        uv_shutdown(sr, (uv_stream_t *) &hc->tcp, on_tcp_shutdown);
    } else {
        uv_read_stop((uv_stream_t *) &hc->tcp);
        zt_close(hc->zt_conn, zt_proxy_close_cb);
    }
    return len;
}

static void alloc_cb(uv_handle_t *h, size_t len, uv_buf_t *b) {
    b->base = malloc(len);
    if (b->base) {
        b->len = len;
    } else {
        b->len = 0;
    }
}

static void on_zt_write(zt_connection c, ssize_t status, void *ctx) {
    free(ctx);

    if (status < ZITI_OK) {
        host_connection *hc = zt_conn_data(c);
        uv_read_stop((uv_stream_t *) &hc->tcp);
        zt_close(c, zt_proxy_close_cb);
    }
}

static void on_tcp_data(uv_stream_t *s, ssize_t len, const uv_buf_t *buf) {
    host_connection *hc = s->data;
    if (len > 0) {
        zt_write(hc->zt_conn, (uint8_t *) buf->base, len, on_zt_write, buf->base);
    } else {
        if (len == UV_EOF) {
            zt_close_write(hc->zt_conn);
        } else {
            printf("tcp peer closed: %s\n", uv_strerror((int)len));
            zt_close(hc->zt_conn, zt_proxy_close_cb);
        }

        if (buf->base) {
            free(buf->base);
        }
    }
}

static void on_accept(zt_connection c, int status) {
    printf("zt connection established\n");
}

static void on_tcp_connect(uv_connect_t *cr, int status) {
    uv_tcp_t *tcp = (uv_tcp_t *) cr->handle;
    host_connection *hc = tcp->data;
    if (status == 0) {
        zt_accept(hc->zt_conn, on_accept, on_zt_data);
        uv_read_start(cr->handle, alloc_cb, on_tcp_data);
    }

    free(cr);
}

/************* Binding functions *************/
static void listen_cb(zt_connection server, int status) {
    host_binding *b = zt_conn_data(server);
    if (status == ZITI_OK) {
        printf("successfully bound to service[%s]\n", b->service_name);
    } else {
        fprintf(stderr, "failed to bind to service[%s]\n", b->service_name);
        // TODO close/retry?
    }
}

static void on_client(zt_connection server, zt_connection conn, int status, const zt_client_ctx *clt_ctx) {
    if (status == ZITI_OK) {
        host_binding *binding = zt_conn_data(server);
        struct app_ctx *app = binding->app;

        printf("accepting connection from <<<%s>>>\n", clt_ctx->caller_id);
        printf("client supplied data: '%.*s'", (int) clt_ctx->app_data_sz, clt_ctx->app_data);

        uv_getaddrinfo_t resolve;
        char port[6];
        snprintf(port, sizeof(port), "%hu", (short) binding->host_cfg->port);
        if (uv_getaddrinfo(app->loop, &resolve, NULL, binding->host_cfg->hostname, port, NULL) != 0) {
            fprintf(stderr, "failed to resolve %s:%d\n", binding->host_cfg->hostname, (int)binding->host_cfg->port);
            return;
        }

        host_connection *hc = calloc(1, sizeof(host_connection));
        hc->zt_conn = conn;
        uv_tcp_init(app->loop, &hc->tcp);
        uv_handle_set_data((uv_handle_t *) &hc->tcp, hc);

        uv_connect_t *cr = calloc(1, sizeof(uv_connect_t));
        if (uv_tcp_connect(cr, &hc->tcp, resolve.addrinfo->ai_addr, on_tcp_connect) != 0) {
            uv_freeaddrinfo(resolve.addrinfo);
            fprintf(stderr, "failed to connect to tcp:%s:%" PRIu64 "\n",
                    binding->host_cfg->hostname, binding->host_cfg->port);
            zt_close(hc->zt_conn, NULL);
            free(hc);
            free(cr);
            return;
        }

        uv_freeaddrinfo(resolve.addrinfo);
        zt_conn_set_data(hc->zt_conn, hc);
    } else {
        fprintf(stderr, "hosting error: %d(%s)\n", status, zt_errorstr(status));
    }
}

void bind_service(struct app_ctx *app, zt_context ztx, zt_service *s, zt_server_cfg_v1 *host_cfg) {
    host_binding *b = calloc(1, sizeof(host_binding));
    b->app = app;
    b->service_id = strdup(s->id);
    b->service_name = strdup(s->name);
    b->host_cfg = host_cfg;
    zt_conn_init(ztx, &b->server, b);
    zt_listen(b->server, b->service_name, listen_cb, on_client);

    model_map_set(&app->bindings, s->id, b);
}
