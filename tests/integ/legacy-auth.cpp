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

#include "../catch2_includes.hpp"

#include <iostream>
#include <zt_internal.h>
#include <zt_ctrl.h>
#include <utils.h>

#include "test-data.h"
#include "fixtures.h"

static const char *const SERVICE_NAME = TEST_SERVICE;

using namespace std;
using namespace Catch::Matchers;


TEST_CASE("invalid_controller", "[controller][GH-44]") {
    zt_controller ctrl;
    uv_loop_t *loop = uv_default_loop();
    resp_capture<zt_version> version;

    PREP(zt);
    model_list endpoints = {nullptr};
    model_list_append(&endpoints, (void*)"https://not.a.zt.controll.er");
    TRY(zt, zt_ctrl_init(loop, &ctrl, &endpoints, nullptr));
    model_list_clear(&endpoints, nullptr);

    WHEN("get version") {
        zt_ctrl_get_version(&ctrl, resp_cb, &version);
        uv_run(loop, UV_RUN_DEFAULT);

        THEN("callback with proper error") {
            REQUIRE(version.error.err != 0);
            REQUIRE_THAT(version.error.code, Equals("CONTROLLER_UNAVAILABLE"));
        }
    }

    CATCH(zt) {
        FAIL("unexpected error");
    }

    zt_ctrl_close(&ctrl);
    uv_run(loop, UV_RUN_DEFAULT);
}

TEST_CASE("controller_test","[integ]") {
    const char *conf = TEST_CLIENT;

    zt_config config{};
    tls_credentials creds{};
    tls_context *tls = nullptr;
    zt_controller ctrl{};
    uv_loop_t *loop = uv_default_loop();

    REQUIRE(zt_load_config(&config, conf) == ZITI_OK);
    REQUIRE(load_tls(&config, &tls, &creds) == ZITI_OK);
    REQUIRE(zt_ctrl_init(loop, &ctrl, &config.controllers, tls) == ZITI_OK);

    resp_capture<zt_version> version;
    resp_capture<zt_api_session> session;
    resp_capture<zt_service> service;

    WHEN("get version and login") {
        auto v = ctrl_get(ctrl, zt_ctrl_get_version);
        REQUIRE(v != nullptr);

        auto v1 = (const char*)model_map_get(&v->api_versions->edge, "v1");
        CHECK(v1 != nullptr);

        auto s = ctrl_login(ctrl);
        free_zt_api_session_ptr(s);
    }

    WHEN("try to get services before login") {
        REQUIRE_THROWS(ctrl_get1(ctrl, zt_ctrl_get_service, SERVICE_NAME));
    }

    WHEN("try to login and get non-existing service") {
        auto api_sesh = ctrl_login(ctrl);

        auto s = ctrl_get1(ctrl, zt_ctrl_get_service, "this-service-should-not-exist");
        THEN("should NOT get non-existent service") {
            REQUIRE(s == nullptr);
        }
        free_zt_api_session_ptr(api_sesh);
    }

    WHEN("try to login, get service, and session") {
        auto api_session = ctrl_login(ctrl);

        auto services = ctrl_get(ctrl, zt_ctrl_get_services);
        zt_service *s = services[0];

        THEN("should get service") {
            REQUIRE(s != nullptr);
        }AND_THEN("should get api_session") {
            auto ns = ctrl_get2(ctrl, zt_ctrl_create_session, (const char *) s->id, *s->permissions[0]);
            REQUIRE(ns != nullptr);
            REQUIRE(ns->token != nullptr);
            free_zt_session_ptr(ns);
            free_zt_service_array(&services);
        }
        AND_THEN("logout should succeed") {
            ctrl_get(ctrl, zt_ctrl_logout);
        }

        free_zt_api_session_ptr(api_session);
    }

    free_zt_version(version.resp);
    free_zt_api_session(session.resp);

    zt_ctrl_close(&ctrl);
    uv_run(loop, UV_RUN_DEFAULT);
    tls->free_ctx(tls);
    free_zt_config(&config);
}

TEST_CASE("ztx-legacy-auth", "[integ]") {
    const char *zid = TEST_CLIENT;

    zt_config cfg;
    REQUIRE(zt_load_config(&cfg, zid) == ZITI_OK);

    zt_context ztx;
    REQUIRE(zt_context_init(&ztx, &cfg) == ZITI_OK);

    struct test_context_s {
        int event;
        std::string data;
    } test_context = {
        .event = 0,
    };


    zt_options opts = {};
    opts.app_ctx = &test_context;
    opts.events = ZitiContextEvent;
    opts.event_cb = [](zt_context ztx, const zt_event_t *event){
            printf("got event: %d => %s \n", event->type, event->ctx.err);
            auto test_ctx = (test_context_s*)zt_app_ctx(ztx);
            test_ctx->event = event->type;
        };

    zt_context_set_options(ztx, &opts);

    auto l = uv_loop_new();
    zt_context_run(ztx, l);

    while (test_context.event == 0) {
        uv_run(l, UV_RUN_ONCE);
    }

    zt_shutdown(ztx);
    uv_run(l, UV_RUN_DEFAULT);

    free_zt_config(&cfg);
}