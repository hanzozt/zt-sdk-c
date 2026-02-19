// Copyright (c) 2023-2024. NetFoundry Inc.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
//
// You may obtain a copy of the License at
// https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

#ifndef ZITI_SDK_AUTH_METHOD_H
#define ZITI_SDK_AUTH_METHOD_H

#include "zt_ctrl.h"

#ifdef __cplusplus
extern "C" {
#endif

enum AuthenticationMethod {
    LEGACY,
    OIDC
};

static const zt_auth_query_mfa ZITI_MFA = {
        .type_id = zt_auth_query_type_MFA,
        .provider = "zt",
};

typedef enum {
    ZitiAuthStateUnauthenticated,
    ZitiAuthStateAuthStarted,

    ZitiAuthStatePartiallyAuthenticated,
    ZitiAuthStateFullyAuthenticated,

    ZitiAuthImpossibleToAuthenticate,
} zt_auth_state;

typedef struct zt_ctx *zt_context;
typedef struct zt_auth_method_s zt_auth_method_t;
typedef void (*auth_state_cb)(void *ctx, zt_auth_state, const void *data);
typedef void (*auth_mfa_cb)(void *ctx, int status);

struct zt_auth_method_s {
    enum AuthenticationMethod kind;
    int (*set_ext_jwt)(zt_auth_method_t *self, const char *token);
    int (*set_endpoint)(zt_auth_method_t *self, const api_path *api);
    int (*start)(zt_auth_method_t *self, auth_state_cb cb, void *ctx);
    int (*force_refresh)(zt_auth_method_t *self);
    const struct timeval* (*expiration)(zt_auth_method_t *self);
    int (*submit_mfa)(zt_auth_method_t *self, const char *code, auth_mfa_cb);
    int (*stop)(zt_auth_method_t *self);
    void (*free)(zt_auth_method_t *self);
};

zt_auth_method_t *new_legacy_auth(zt_controller *ctrl);
zt_auth_method_t *new_oidc_auth(uv_loop_t *l, const api_path *api, tls_context *tls);

#ifdef __cplusplus
}
#endif

#endif // ZITI_SDK_AUTH_METHOD_H
