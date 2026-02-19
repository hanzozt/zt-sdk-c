

#include <catch2/catch_all.hpp>
#include <zt/zt.h>
#include "oidc.h"
#include "zt/zt_log.h"
#include "zt_ctrl.h"
#include <tlsuv/tlsuv.h>

#include "fixtures.h"
#include <test-data.h>
#include <iostream>
#include <zt_internal.h>

TEST_CASE("cltr-network-jwt", "[integ]") {
    auto l = uv_default_loop();

    zt_config cfg{};
    zt_controller ctrl{};
    REQUIRE(zt_load_config(&cfg, TEST_CLIENT) == ZITI_OK);

    auto tls = default_tls_context(cfg.id.ca, strlen(cfg.id.ca));
    zt_ctrl_init(l, &ctrl, &cfg.controllers, tls);

    struct res {
        std::string err;
        zt_network_jwt_array arr;
    } result;

    zt_ctrl_get_network_jwt(&ctrl, [](zt_network_jwt_array arr, const zt_error *err, void *ctx) {
        auto r = static_cast<res *>(ctx);
        if (err) {
            r->err += err->message;
        } else {
            r->arr = arr;
        }

    }, &result);

    uv_run(l, UV_RUN_DEFAULT);

    CHECK(result.err.empty());
    CHECK(result.arr != nullptr);
    CHECK(result.arr[0] != nullptr);
    CHECK_THAT(result.arr[0]->name, Catch::Matchers::Equals("default"));

    zt_enrollment_jwt_header header{};
    zt_enrollment_jwt jwt{};

    char * sig;
    size_t siglen;
    parse_enrollment_jwt((char*)result.arr[0]->token, &header, &jwt, &sig, &siglen);

    CHECK(header.alg == jwt_sig_method_RS256);
    CHECK(jwt.method == zt_enrollment_method_network);

    free_zt_enrollment_jwt_header(&header);
    free_zt_enrollment_jwt(&jwt);

    zt_ctrl_close(&ctrl);
    tls->free_ctx(tls);
    free_zt_network_jwt_array(&result.arr);
    free_zt_config(&cfg);
    free(sig);
}

TEST_CASE("ctrl-list-terminators", "[integ]") {
    auto conf = TEST_CLIENT;
    zt_config config{};
    tls_credentials creds{};
    tls_context *tls = nullptr;
    zt_controller ctrl{};
    uv_loop_t *loop = uv_default_loop();

    REQUIRE(zt_load_config(&config, conf) == ZITI_OK);
    REQUIRE(load_tls(&config, &tls, &creds) == ZITI_OK);
    REQUIRE(zt_ctrl_init(loop, &ctrl, &config.controllers, tls) == ZITI_OK);

    auto session = ctrl_login(ctrl);
    CHECK(session != nullptr);

    auto service = ctrl_get1(ctrl, zt_ctrl_get_service, TEST_SERVICE);
    auto list = ctrl_get1(ctrl, zt_ctrl_list_terminators, service->id);
    CHECK(list != nullptr);
    free_zt_terminator_array(&list);
    free_zt_service_ptr(service);
    free_zt_api_session_ptr(session);
    zt_ctrl_close(&ctrl);
}

TEST_CASE("ctrl-token-auth", "[integ]") {
    // auto l = uv_default_loop();
    //
    // zt_config cfg;
    // REQUIRE(zt_load_config(&cfg, TEST_CLIENT) == ZITI_OK);
    //
    // auto ctrlTLS = default_tls_context(cfg.id.ca, strlen(cfg.id.ca));
    //
    // zt_controller ctrl = {};
    // REQUIRE(zt_ctrl_init(l, &ctrl, cfg.controller_url, ctrlTLS) == ZITI_OK);
    //
    // zt_version v = {0};
    // std::string err;
    // zt_ctrl_get_version(&ctrl, [](const zt_version *v, const zt_error *err, void *ctx){
    //     std::cout << "in version cb" << std::endl;
    //     auto out = (zt_version*)ctx;
    //     REQUIRE(v != NULL);
    //     *out = *v;
    //     free(v);
    //     }, &v);
    //
    // uv_run(l, UV_RUN_DEFAULT);
    //
    // bool HA = zt_has_capability(&v, zt_ctrl_caps.HA_CONTROLLER);
    // bool OIDC = zt_has_capability(&v, zt_ctrl_caps.OIDC_AUTH);
    // if (!(HA && OIDC)) {
    //     SKIP("can not test without HA and OIDC");
    // }
    //
    // oidc_client_t oidc;
    // auto oidcTLS = default_tls_context(cfg.id.ca, strlen(cfg.id.ca));
    // tlsuv_private_key_t key;
    // tls_cert cert = nullptr;
    // oidcTLS->load_key(&key, cfg.id.key, strlen(cfg.id.key));
    // oidcTLS->load_cert(&cert, cfg.id.cert, strlen(cfg.id.cert));
    // oidcTLS->set_own_cert(oidcTLS, key, cert);
    // oidc_client_init(l, &oidc, cfg.controller_url, oidcTLS);
    //
    // oidc_client_configure(&oidc, nullptr);
    // uv_run(l, UV_RUN_DEFAULT);
    //
    // std::string token;
    // oidc.data = &token;
    // oidc_client_start(&oidc, [](oidc_client_t *clt, int status, const char *token){
    //     CAPTURE(status);
    //     auto out = (std::string*)clt->data;
    //     *out = token;
    // });
    // uv_run(l, UV_RUN_DEFAULT);
    //
    // REQUIRE(!token.empty());
    //
    // zt_service service = {nullptr};
    // zt_ctrl_set_token(&ctrl, token.c_str());
    // zt_ctrl_get_service(&ctrl, TEST_SERVICE,
    //                       [](zt_service *s, const zt_error *err, void *ctx){
    //                           auto msg = err ? err->message : "";
    //                           INFO(msg);
    //                           REQUIRE(s != nullptr);
    //                           *(zt_service*)ctx = *s;
    //                           free(s);
    //                       },
    //                       &service);
    // uv_run(l, UV_RUN_DEFAULT);
    //
    // REQUIRE_THAT(service.name, Catch::Matchers::Equals(TEST_SERVICE));
    // oidc_client_close(&oidc, nullptr);
    // zt_ctrl_close(&ctrl);
    //
    // uv_run(l, UV_RUN_DEFAULT);
    //
    // oidcTLS->free_cert(&cert);
    //
    // oidcTLS->free_ctx(oidcTLS);
    // ctrlTLS->free_ctx(ctrlTLS);
    //
    // free_zt_version(&v);
    // free_zt_service(&service);
    // free_zt_config(&cfg);
}