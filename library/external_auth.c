//
// 	Copyright NetFoundry Inc.
//
// 	Licensed under the Apache License, Version 2.0 (the "License");
// 	you may not use this file except in compliance with the License.
// 	You may obtain a copy of the License at
//
// 	https://www.apache.org/licenses/LICENSE-2.0
//
// 	Unless required by applicable law or agreed to in writing, software
// 	distributed under the License is distributed on an "AS IS" BASIS,
// 	WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// 	See the License for the specific language governing permissions and
// 	limitations under the License.
//

#include "ext_oidc.h"
#include "zt_internal.h"
#include <assert.h>
#include <zt/zt_events.h>

static void ext_token_cb(ext_oidc_client_t *oidc, enum ext_oidc_status status, const void *data);

static void ext_oath_cfg_cb(ext_oidc_client_t *oidc, int status, const char *err) {
    zt_context ztx = oidc->data;
    zt_event_t ev = {
            .type = ZitiAuthEvent,
    };
    if (status == 0) {
        ev.auth = (struct zt_auth_event){
                .action = zt_auth_login_external,
                .type = "oidc",
                .detail = oidc->http.host,
        };
    } else {
        ZTX_LOG(ERROR, "OIDC provider configuration failed: %s", err);
        ev.auth = (struct zt_auth_event){
                .action = zt_auth_cannot_continue,
                .type = "oidc",
                .detail = err,
        };
    }

    zt_send_event(ztx, &ev);
}

static void ext_signers_cb(zt_context ztx, int status, zt_jwt_signer_array signers, void *ctx) {

    if (status != ZITI_OK) {
        ZTX_LOG(WARN, "failed to get external signers: %s", zt_errorstr(status));
        return;
    }

    zt_event_t ev = {
            .type = ZitiAuthEvent,
            .auth = (struct zt_auth_event){
                    .action = zt_auth_select_external,
                    .type = "oidc",
                    .providers = signers,
            },
    };
    zt_send_event(ztx, &ev);
}

int ztx_init_external_auth(zt_context ztx, const zt_jwt_signer *oidc_cfg) {
    if (oidc_cfg != NULL) {
        NEWP(oidc, ext_oidc_client_t);
        int rc = ext_oidc_client_init(ztx->loop, oidc, oidc_cfg);
        if (rc != ZITI_OK) {
            free(oidc);
            ZTX_LOG(ERROR, "failed to initialize OIDC client: %s", zt_errorstr(rc));
            return rc;
        }
        oidc->data = ztx;
        ztx->ext_auth = oidc;
        ext_oath_cfg_cb(oidc, 0, NULL);
        return 0;
    }

    return zt_get_ext_jwt_signers(ztx, ext_signers_cb, ztx);
}

static void internal_link_cb(ext_oidc_client_t *oidc, const char *url, void *ctx) {
    zt_context ztx = oidc->data;
    ZITI_LOG(INFO, "received link request: %s", url);
    if (ztx->ext_launch_cb) {
        ztx->ext_launch_cb(ztx, url, ztx->ext_launch_ctx);
    }
    ztx->ext_launch_cb = NULL;
    ztx->ext_launch_ctx = NULL;
}

static void ext_token_cb(ext_oidc_client_t *oidc, enum ext_oidc_status status, const void *data) {
    zt_context ztx = oidc->data;
    enum zt_auth_action action = zt_auth_login_external;
    const char *err = NULL;
    switch (status) {
        case EXT_OIDC_TOKEN_OK: {
            zt_ext_auth_token(ztx, (const char*)data);
            return;
        }
        case EXT_OIDC_CONFIG_FAILED: {
            err = (const char*)data;
            action = zt_auth_cannot_continue;
            ZTX_LOG(WARN, "failed to configure external signer: %s", err);
            break;
        }
        case EXT_OIDC_RESTART: {
            action = zt_auth_login_external;
            break;
        }
        case EXT_OIDC_TOKEN_FAILED: {
            action = zt_auth_cannot_continue;
            err = data;
            ZTX_LOG(WARN, "failed to get external authentication token: %d/%s", status, err);
        }
    }

    if (ztx->auth_state != ZitiAuthStateFullyAuthenticated) {
        zt_event_t ev = {
            .type = ZitiAuthEvent,
            .auth = {
                .type = zt_auth_query_types.name(zt_auth_query_type_EXT_JWT),
                .action = action,
                .error = err,
                .detail = ztx->ext_auth->signer_cfg.name,
            }};
        zt_send_event(ztx, &ev);
    }
}

extern int zt_ext_auth(zt_context ztx,
                         void (*zt_ext_launch)(zt_context, const char*, void *), void *ctx) {
    if (ztx->ext_auth == NULL) {
        return ZITI_INVALID_STATE;
    }

    ztx->ext_launch_cb = zt_ext_launch;
    ztx->ext_launch_ctx = ctx;
    ext_oidc_client_set_link_cb(ztx->ext_auth, internal_link_cb, NULL);
    ext_oidc_client_start(ztx->ext_auth, ext_token_cb);
    return ZITI_OK;
}

static void ztx_on_token_enroll(zt_create_api_cert_resp *cert_resp, const zt_error *error, void *ctx) {
    zt_context ztx = ctx;
    assert(ztx->auth_method);

    if (cert_resp && cert_resp->client_cert_pem != NULL) {
        ZTX_LOG(ERROR, "not handling client cert for now");
    }
    assert(cert_resp == NULL || cert_resp->client_cert_pem == NULL);

    if (error) {
        if (error->err == ZITI_ALREADY_ENROLLED) {
            ZTX_LOG(DEBUG, "already enrolled");
        } else {
            ZTX_LOG(WARN, "failed to enroll: %s", error->message);
        }
    }
    ztx->auth_method->start(ztx->auth_method, ztx_auth_state_cb, ztx);
    free_zt_create_api_cert_resp_ptr(cert_resp);
}

extern int zt_ext_auth_token(zt_context ztx, const char *token) {
    ZTX_LOG(DEBUG, "received access token: %s", jwt_payload(token));
    assert(ztx->auth_method);
    ztx->auth_method->set_ext_jwt(ztx->auth_method, token);

    ZTX_LOG(DEBUG, "received access token: %s", jwt_payload(token));
    // create identity if needed and allowed
    if (ztx->identity_data == NULL && ztx->id_creds.cert == NULL) {
        ZTX_LOG(INFO, "no credentials present trying just-in-time enrollment");
        zt_ctrl_enroll_token(ztx_get_controller(ztx), token, NULL, ztx_on_token_enroll, ztx);
        return ZITI_OK;
    }

    if (ztx->auth_state == ZitiAuthStateUnauthenticated) {
        ZTX_LOG(DEBUG, "initiating authentication flow");
        ztx->auth_method->start(ztx->auth_method, ztx_auth_state_cb, ztx);
    }
    return ZITI_OK;
}