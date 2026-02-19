/*
Copyright (c) 2020 Netfoundry, Inc.

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

#ifndef ZITI_SDK_AUTH_QUERIES_H
#define ZITI_SDK_AUTH_QUERIES_H

#include <uv.h>
#include "zt_internal.h"

#ifdef __cplusplus
extern "C" {
#endif

#include "zt_internal.h"
#include <utils.h>

typedef struct zt_mfa_auth_ctx_s zt_mfa_auth_ctx;

struct auth_queries {
    zt_mfa_auth_ctx *outstanding_auth_query_ctx;
};

extern void zt_auth_query_init(struct zt_ctx *ztx);
extern void zt_auth_query_free(struct auth_queries* aq);
extern void zt_send_event(zt_context ztx, const zt_event_t *e);

#ifdef __cplusplus
}
#endif


#endif //ZITI_SDK_AUTH_QUERIES_H
