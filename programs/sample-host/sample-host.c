/*
Copyright 2019-2020 NetFoundry, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

https://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

#include <zt/errors.h>
#include <zt/zt.h>
#include <string.h>

#define DIE(v) do { \
int code = (v);\
if (code != ZITI_OK) {\
fprintf(stderr, "ERROR: " #v " => %s\n", zt_errorstr(code));\
exit(code);\
}} while(0)


static zt_context zt;
static int server = 0;
static const char *service;

static void on_client_write(zt_connection clt, ssize_t status, void *ctx) {
    free(ctx);
}

static ssize_t on_client_data(zt_connection clt, const uint8_t *data, ssize_t len) {
    if (len > 0) {
        printf("client sent:%.*s\n", (int) len, data);
        char *reply = malloc(128);
        size_t l = sprintf(reply, "%zd", len);
        zt_write(clt, (uint8_t *) reply, l, on_client_write, reply);
    }
    else if (len == ZITI_EOF) {
        printf("client disconnected\n");
        zt_close_write(clt);
    }
    else {
        fprintf(stderr, "error: %zd(%s)", len, zt_errorstr(len));
        zt_close(clt, NULL);
    }
    return len;
}

static void on_client_connect(zt_connection clt, int status) {
    if (status == ZITI_OK) {
        const char *msg = "Hello from byte counter!";
        zt_write(clt, (uint8_t *) msg, strlen(msg), on_client_write, NULL);
    }
}

static void on_client(zt_connection serv, zt_connection client, int status, const zt_client_ctx *clt_ctx) {
    if (status == ZITI_OK) {
        const char *source_identity = clt_ctx->caller_id;
        if (source_identity != NULL) {
            fprintf(stderr, "incoming connection from '%s'\n", source_identity);
        }
        else {
            fprintf(stderr, "incoming connection from unidentified client\n");
        }
        if (clt_ctx->app_data != NULL) {
            fprintf(stderr, "got app data '%.*s'!\n", (int) clt_ctx->app_data_sz, clt_ctx->app_data);
        }
        zt_accept(client, on_client_connect, on_client_data);
    } else {
        fprintf(stderr, "failed to accept client: %s(%d)\n", zt_errorstr(status), status);
    }
}

static void listen_cb(zt_connection serv, int status) {
    if (status == ZITI_OK) {
        printf("Byte Counter is ready! %d(%s)\n", status, zt_errorstr(status));
    }
    else {
        printf("ERROR The Byte Counter could not be started: %d(%s)\n", status, zt_errorstr(status));
        zt_close(serv, NULL);
    }
}

static void on_write(zt_connection conn, ssize_t status, void *ctx) {
    if (status < 0) {
        fprintf(stderr, "request failed to submit status[%zd]: %s\n", status, zt_errorstr((int) status));
    }
    else {
        printf("request success: %zd bytes sent\n", status);
    }

    if (ctx) {
        free(ctx);
    }
}

static void input_alloc(uv_handle_t *s, size_t len, uv_buf_t *b) {
    b->base = malloc(len);
    if (b->base) {
        b->len = len;
    }
}

static void input_read(uv_stream_t *s, ssize_t len, const uv_buf_t *b) {
    zt_connection conn = s->data;

    if (len > 0) {
        DIE(zt_write(conn, (uint8_t *) b->base, len, on_write, b->base));
    }
    else {
        exit(0);
    }
}

void on_connect(zt_connection conn, int status) {
    DIE(status);
    uv_loop_t *l = zt_app_ctx(zt_conn_context(conn));
    uv_pipe_t *input = calloc(1, sizeof(uv_pipe_t));
    uv_pipe_init(l, input, 0);
    input->data = conn;
    DIE(uv_pipe_open(input, 0));
    DIE(uv_read_start((uv_stream_t *) input, input_alloc, input_read));
}

static size_t total;

ssize_t on_data(zt_connection c, const uint8_t *buf, ssize_t len) {
    if (len == ZITI_EOF) {

        printf("request completed: %s\n", zt_errorstr(len));
        zt_close(c, NULL);
        zt_shutdown(zt);

    }
    else if (len < 0) {
        fprintf(stderr, "unexpected error: %s\n", zt_errorstr(len));
        zt_close(c, NULL);
        zt_shutdown(zt);
    }
    else {
        total += len;
        printf("%.*s", (int)len, buf);
    }
    return len;
}
static uv_signal_t sig;
static void on_signal(uv_signal_t *h, int signal) {
    zt_context ztx = h->data;
    zt_dump(ztx, (int (*)(void *, const char *, ...)) fprintf, stdout);
}

static void on_zt_init(zt_context ztx, const zt_event_t *ev) {
    if (ev->type != ZitiContextEvent) return;

    if (ev->ctx.ctrl_status == ZITI_PARTIALLY_AUTHENTICATED) return;

    if (ev->ctx.ctrl_status != ZITI_OK) {
        DIE(ev->ctx.ctrl_status);
        return;
    }

#ifndef _WIN32
    sig.data = ztx;
    uv_signal_start(&sig, on_signal, SIGUSR1);
#endif

    zt = ztx;
    zt_connection conn;
    zt_conn_init(zt, &conn, NULL);
    if (server) {
        zt_listen_opts listen_opts = {
//                .identity = "itsamee",
                .bind_using_edge_identity = false,
//                .terminator_precedence = PRECEDENCE_REQUIRED,
//                .terminator_cost = 10,
        };
        zt_listen_with_options(conn, service, &listen_opts, listen_cb, on_client);
    }
    else {
        char *app_data = "here is some data from the client to get you started";
        zt_dial_opts dial_opts = {
//                .identity = "itsamee",
                .app_data = app_data,
                .app_data_sz = strlen(app_data) + 1,
        };
        DIE(zt_dial_with_options(conn, service, &dial_opts, on_connect, on_data));
    }
}

int main(int argc, char **argv) {
#if _WIN32
    //changes the output to UTF-8 so that the windows output looks correct and not all jumbly
    SetConsoleOutputCP(65001);

#endif
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <client|server> <config-file> <service-name>", argv[0]);
        exit(1);
    }
    uv_loop_t *loop = uv_default_loop();

    if (strcmp("server", argv[1]) != 0) {
        printf("Running as client\n");
    }
    else {
        printf("Running as server\n");
        server = 1;
    }

    service = argv[3];

    zt_config cfg;
    zt_context ztx;
    DIE(zt_load_config(&cfg, argv[2]));
    DIE(zt_context_init(&ztx, &cfg));
    DIE(zt_context_set_options(ztx, &(zt_options){
        .event_cb = on_zt_init,
        .events = ZitiContextEvent,
    }));

    DIE(zt_context_run(ztx, loop));

    uv_signal_init(loop, &sig);
    // loop will finish after the request is complete and zt_shutdown is called
    uv_run(loop, UV_RUN_DEFAULT);

    printf("========================\n"
           "uv loop is done\n");

    zt_shutdown(zt);
}

