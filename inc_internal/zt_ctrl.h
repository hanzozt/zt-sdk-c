// Copyright (c) 2019-2024. NetFoundry Inc.
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


#ifndef ZITI_SDK_CONTROLLER_H
#define ZITI_SDK_CONTROLLER_H

#include <tlsuv/http.h>
#include "internal_model.h"
#include "zt/zt_model.h"

#ifdef __cplusplus
extern "C" {
#endif
    
typedef void (*zt_ctrl_redirect_cb)(const char *new_address, void *ctx);

typedef void (*zt_ctrl_change_cb)(void *ctx, const model_map *endpoints);

typedef void (*ctrl_version_cb)(const zt_version *, const zt_error *, void *);

typedef void(*routers_cb)(zt_service_routers *srv_routers, const zt_error *, void *);

typedef struct zt_controller_s {
    uv_loop_t *loop;
    tlsuv_http_t *client;

    char *url;
    model_map endpoints;

    unsigned int active_reqs;

    // tuning options
    unsigned int page_size;

    bool legacy;
    bool is_ha;
    zt_version version;
    ctrl_version_cb version_cb;
    void *version_cb_ctx;
    void *version_req;

    bool has_token;
    char *instance_id;

    zt_ctrl_change_cb change_cb;
    zt_ctrl_redirect_cb redirect_cb;
    void *cb_ctx;
} zt_controller;

int zt_ctrl_init(uv_loop_t *loop, zt_controller *ctrl, model_list *urls, tls_context *tls);

int zt_ctrl_set_token(zt_controller *ctrl, const char *access_token);

void zt_ctrl_set_legacy(zt_controller *ctrl, bool legacy);

int zt_ctrl_cancel(zt_controller *ctrl);

void zt_ctrl_set_page_size(zt_controller *ctrl, unsigned int size);

void zt_ctrl_set_callbacks(zt_controller *ctrl, void *ctx,
                             zt_ctrl_redirect_cb redirect_cb,
                             zt_ctrl_change_cb change_cb);

int zt_ctrl_close(zt_controller *ctrl);

void zt_ctrl_clear_auth(zt_controller *ctrl);

void zt_ctrl_get_version(zt_controller *ctrl, ctrl_version_cb cb, void *ctx);

void zt_ctrl_login(zt_controller *ctrl, model_list *cfg_types,
                     void (*cb)(zt_api_session *, const zt_error *, void *),
                     void *ctx);

void zt_ctrl_login_ext_jwt(zt_controller *ctrl, const char *jwt,
                             void (*cb)(zt_api_session *, const zt_error *, void *), void *ctx);

void zt_ctrl_list_ext_jwt_signers(zt_controller *ctrl,
                                    void (*cb)(zt_jwt_signer_array, const zt_error*, void*),
                                    void *ctx);

void zt_ctrl_get_network_jwt(zt_controller *ctrl,
                               void(*cb)(zt_network_jwt_array, const zt_error*, void *ctx),
                               void *ctx);

void zt_ctrl_list_controllers(zt_controller *ctrl,
                                void (*cb)(zt_controller_detail_array, const zt_error*, void *ctx), void *ctx);

void zt_ctrl_current_api_session(zt_controller *ctrl, void(*cb)(zt_api_session *, const zt_error *, void *), void *ctx);

void zt_ctrl_mfa_jwt(zt_controller *ctrl, const char *token, void(*cb)(zt_api_session *, const zt_error *, void *), void *ctx);

void zt_ctrl_create_api_certificate(zt_controller *ctrl, const char *csr_pem, void(*cb)(zt_create_api_cert_resp *, const zt_error *, void *), void *ctx);

void zt_ctrl_current_identity(zt_controller *ctrl, void(*cb)(zt_identity_data *, const zt_error *, void *), void *ctx);

void zt_ctrl_current_edge_routers(zt_controller *ctrl, void(*cb)(zt_edge_router_array, const zt_error *, void *),
                                    void *ctx);

void zt_ctrl_logout(zt_controller *ctrl, void(*cb)(void *, const zt_error *, void *), void *ctx);

void zt_ctrl_get_services_update(zt_controller *ctrl, void (*cb)(zt_service_update *, const zt_error *, void *),
                                   void *ctx);

void zt_ctrl_get_services(zt_controller *ctrl, void (*srv_cb)(zt_service_array, const zt_error *, void *),
                            void *ctx);

void zt_ctrl_get_service(zt_controller *ctrl, const char *service_name,
                           void (*srv_cb)(zt_service *, const zt_error *, void *), void *ctx);

void zt_ctrl_list_terminators(zt_controller *ctrl, const char *service_id,
                                void (*cb)(const zt_terminator_array, const zt_error*, void *ctx), void *ctx);

void zt_ctrl_list_service_routers(zt_controller *ctrl, const zt_service *srv, routers_cb, void *ctx);

void zt_ctrl_create_session(
        zt_controller *ctrl, const char *service_id, zt_session_type type,
        void (*cb)(zt_session *, const zt_error *, void *), void *ctx);

void zt_ctrl_get_session(
        zt_controller *ctrl, const char *session_id,
        void (*cb)(zt_session *, const zt_error *, void *), void *ctx);

void zt_ctrl_get_sessions(
        zt_controller *ctrl, void (*cb)(zt_session **, const zt_error *, void *), void *ctx);

void zt_ctrl_get_well_known_certs(zt_controller *ctrl, void (*cb)(char *, const zt_error *, void *), void *ctx);

void zt_ctrl_enroll(zt_controller *ctrl, zt_enrollment_method method, const char *token, const char *csr,
                      const char *name,
                      void (*cb)(zt_enrollment_resp *, const zt_error *, void *), void *ctx);

void zt_ctrl_enroll_token(zt_controller *ctrl, const char *token, const char *csr,
                            void (*cb)(zt_create_api_cert_resp *, const zt_error *, void *), void *ctx);

//Posture
void zt_pr_post_bulk(zt_controller *ctrl, char *body, size_t body_len, void(*cb)(zt_pr_response *, const zt_error *, void *), void *ctx);

void zt_pr_post(zt_controller *ctrl, char *body, size_t body_len, void(*cb)(zt_pr_response *, const zt_error *, void *), void *ctx);


//MFA
void zt_ctrl_login_mfa(zt_controller *ctrl, char *body, size_t body_len, void(*cb)(void *, const zt_error *, void *), void *ctx);

void zt_ctrl_post_mfa(zt_controller *ctrl, void(*cb)(void *, const zt_error *, void *), void *ctx);

void zt_ctrl_get_mfa(zt_controller *ctrl, void(*cb)(zt_mfa_enrollment *, const zt_error *, void *), void *ctx);

void zt_ctrl_delete_mfa(zt_controller *ctrl, char *code, void(*cb)(void *, const zt_error *, void *), void *ctx);

void zt_ctrl_post_mfa_verify(zt_controller *ctrl, char *body, size_t body_len, void(*cb)(void *, const zt_error *, void *), void *ctx);

void zt_ctrl_get_mfa_recovery_codes(zt_controller *ctrl, char *code, void(*cb)(zt_mfa_recovery_codes *, const zt_error *, void *), void *ctx);

void zt_ctrl_post_mfa_recovery_codes(zt_controller *ctrl, char *body, size_t body_len, void(*cb)(void *, const zt_error *, void *), void *ctx);

//Authenticators

void zt_ctrl_extend_cert_authenticator(zt_controller *ctrl, const char *authenticatorId, const char *csr, void(*cb)(zt_extend_cert_authenticator_resp*, const zt_error *, void *), void *ctx);

void zt_ctrl_verify_extend_cert_authenticator(zt_controller *ctrl, const char *authenticatorId, const char *client_cert, void(*cb)(void *, const zt_error *, void *), void *ctx);

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_CONTROLLER_H
