// Copyright (c) 2020-2023.  NetFoundry Inc.
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


#ifndef ZITI_SDK_ZITI_EVENTS_H
#define ZITI_SDK_ZITI_EVENTS_H

#include "zt_model.h"

#ifdef __cplusplus
extern "C" {
#endif


/**
 * \brief Ziti Event Types.
 *
 * \see zt_event_t
 * \see zt_options.events
 */
typedef enum {
    ZitiContextEvent = 1,
    ZitiRouterEvent = 1 << 1,
    ZitiServiceEvent = 1 << 2,
    ZitiAuthEvent = 1 << 3,
    ZitiConfigEvent = 1 << 4,
} zt_event_type;

/**
 * \brief Ziti Edge Router status.
 *
 * \see zt_router_event
 */
typedef enum {
    EdgeRouterAdded,
    EdgeRouterConnected,
    EdgeRouterDisconnected,
    EdgeRouterRemoved,
    EdgeRouterUnavailable,
} zt_router_status;

/**
 * \brief Context event.
 *
 * Informational event to notify app about issues communicating with Ziti controller.
 */
struct zt_context_event {
    int ctrl_status;
    const char *err;
    size_t ctrl_count;
    struct ctrl_detail_s *ctrl_details;
};

struct ctrl_detail_s {
    const char *id;
    const char *url;
    bool online;
    bool active;
};

struct zt_config_event {
    const char *identity_name;
    const zt_config *config;
};
/**
 * \brief Edge Router Event.
 *
 * Informational event to notify app about status of edge router connections.
 */
struct zt_router_event {
    zt_router_status status;
    const char *name;
    const char *address;
    const char *version;
};

/**
 * \brief Ziti Service Status event.
 *
 * Event notifying app about service access changes.
 * Each field is a NULL-terminated array of `zt_service*`.
 *
 * \see zt_service
 */
struct zt_service_event {

    /** Services no longer available in the Ziti Context */
    zt_service_array removed;

    /** Modified services -- name, permissions, configs, etc */
    zt_service_array changed;

    /** Newly available services in the Ziti Context */
    zt_service_array added;
};

enum zt_auth_action {
    zt_auth_cannot_continue,
    zt_auth_prompt_totp,
    zt_auth_prompt_pin,
    zt_auth_select_external,
    zt_auth_login_external
};
/**
 * \brief Event notifying the app that additional action is required to continue authentication or normal operation.
 *
 * The app may request that information from the user and then submit it
 * to zt_context.
 *
 * the following authentication actions are supported:
 *
 * [zt_auth_prompt_totp] - request for MFA code, application must call [zt_mfa_auth()] when it acquires TOTP code
 *
 * [zt_auth_login_external] - request for that app to launch external program (web browser)
 *                 that can authenticate with provided url ([detail] field)
 *
 * TODO: future
 * [zt_auth_prompt_pin] - request for HSM/TPM key pin, application must call [TBD method] when it acquires PIN
 */
struct zt_auth_event {
    enum zt_auth_action action;
    /** error message, if any action == zt_auth_cannot_continue */
    const char *error;
    const char *type;
    const char *detail;
    zt_jwt_signer_array providers;
};

/**
 * \brief Object passed to `zt_options.event_cb`.
 *
 * \note event data becomes invalid as soon as callback returns.
 * App must copy data if it's needed for further processing.
 */
typedef struct zt_event_s {
    zt_event_type type;
    union {
        struct zt_context_event ctx;
        struct zt_router_event router;
        struct zt_service_event service;
        struct zt_auth_event auth;
        struct zt_config_event cfg;
    };
} zt_event_t;

#ifdef __cplusplus
}
#endif

#endif //ZITI_SDK_ZITI_EVENTS_H
