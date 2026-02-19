// Copyright (c) 2022-2023.  NetFoundry Inc.
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
#include <stdio.h>
#include "zt/zt_log.h"

#ifdef _WIN32
#define STDIN GetStdHandle(STD_INPUT_HANDLE)
#define STDOUT GetStdHandle(STD_OUTPUT_HANDLE)
#else
#define STDIN 0
#define STDOUT 1
#endif

typedef struct {
    uv_loop_t *loop;
    const char *service;
} zcat_opts;

// on successful connect bridge Ziti connection to standard input and output
void on_connect(zt_connection conn, int status) {
    if (status == ZITI_OK) {
        zt_conn_bridge_fds(conn, STDIN, STDOUT, (void (*)(void *)) zt_shutdown, zt_conn_context(conn));
    } else {
        fprintf(stderr, "zt connection failed: %s", zt_errorstr(status));
        zt_shutdown(zt_conn_context(conn));
    }
}

void on_zt_event(zt_context ztx, const zt_event_t *ev) {
    if (ev->type == ZitiContextEvent && ev->ctx.ctrl_status == ZITI_OK) {
        zcat_opts *opts = zt_app_ctx(ztx);
        zt_connection zconn;
        zt_conn_init(ztx, &zconn, NULL);
        zt_dial(zconn, opts->service, on_connect, NULL);
    }
}

int main(int argc, char *argv[]) {
    uv_loop_t *l = uv_loop_new();
    zcat_opts opts = {
            .loop = l,
            .service = argv[2]
    };
    zt_options zopts = {
            .event_cb = on_zt_event,
            .events = ZitiContextEvent,
            .app_ctx = &opts
    };

    zt_config cfg;
    zt_context ztx = NULL;

    zt_log_init(l, ZITI_LOG_DEFAULT_LEVEL, NULL);

#define check(op) do{ \
int err = (op); if (err != ZITI_OK) { \
fprintf(stderr, "ERROR: %s", zt_errorstr(err)); \
exit(err);\
}}while(0)

    check(zt_load_config(&cfg, argv[1]));
    check(zt_context_init(&ztx, &cfg));
    check(zt_context_set_options(ztx, &zopts));

    zt_context_run(ztx, l);

    uv_run(l, UV_RUN_DEFAULT);
}

