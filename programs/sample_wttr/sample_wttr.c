// Copyright (c) 2023.  NetFoundry Inc.
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
#include <stdlib.h>
#include <stdio.h>
#include <uv.h>

#define DIE(v) do { \
int code = (v);\
if (code != ZITI_OK) {\
fprintf(stderr, "ERROR: " #v " => %s\n", zt_errorstr(code));\
exit(code);\
}} while(0)

static size_t total;
static zt_context zt;

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
        printf("%.*s",  (int)len, buf);
    }
    return len;
}

static void on_write(zt_connection conn, ssize_t status, void *ctx) {
    if (status < 0) {
        fprintf(stderr, "request failed to submit status[%zd]: %s\n", status, zt_errorstr((int) status));
    }
    else {
        printf("request success: %zd bytes sent\n", status);
    }
}

void on_connect(zt_connection conn, int status) {
    DIE(status);

    printf("sending HTTP request\n");

    const char *req = "GET /Rochester HTTP/1.0\r\n"
                   "Accept: */*\r\n"
                   "Connection: close\r\n"
                   "Host: wttr.in\r\n"
                   "User-Agent: curl/7.59.0\r\n"
                   "\r\n";

    DIE(zt_write(conn, (uint8_t *) req, strlen(req), on_write, NULL));
}

void on_zt_init(zt_context ztx, const zt_event_t *ev) {
    DIE(ev->ctx.ctrl_status);
    zt = ztx;

    zt_connection conn;
    DIE(zt_conn_init(zt, &conn, NULL));
    DIE(zt_dial(conn, "demo-weather", on_connect, on_data));
}

int main(int argc, char** argv) {
#if _WIN32
    //changes the output to UTF-8 so that the windows output looks correct and not all jumbly
    SetConsoleOutputCP(65001);
#endif
    uv_loop_t *loop = uv_default_loop();
    zt_config cfg;
    zt_context ztx;
    zt_options options = (zt_options) {
            .event_cb = on_zt_init,
            .events = ZitiContextEvent,
    };

    DIE(zt_load_config(&cfg, argv[1]));
    DIE(zt_context_init(&ztx, &cfg));
    DIE(zt_context_set_options(ztx, &options));
    DIE(zt_context_run(ztx, loop));

    // loop will finish after the request is complete and zt_shutdown is called
    uv_run(loop, UV_RUN_DEFAULT);

    printf("========================\n");

    zt_shutdown(zt);
}