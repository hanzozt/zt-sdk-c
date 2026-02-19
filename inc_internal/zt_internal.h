// Copyright (c) 2022-2024. NetFoundry Inc.
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

#ifndef ZT_SDK_ZT_INTERNAL_H
#define ZT_SDK_ZT_INTERNAL_H


#include <stdbool.h>
#include <tlsuv/tlsuv.h>
#include <tlsuv/queue.h>

#include <zt/zt.h>

#include "auth_method.h"
#include "buffer.h"
#include "deadline.h"
#include "metrics.h"
#include "pool.h"
#include "posture.h"
#include "stickiness.h"
#include "utils.h"
#include "zt_ctrl.h"

#include <sodium.h>

#if !defined(UUID_STR_LEN)
#define UUID_STR_LEN 37
#endif

#define MARKER_BIN_LEN 6
#define MARKER_CHAR_LEN sodium_base64_ENCODED_LEN(MARKER_BIN_LEN, sodium_base64_VARIANT_URLSAFE_NO_PADDING)

#define ZTX_LOG(lvl, fmt, ...) ZITI_LOG(lvl, "ztx[%u] " fmt, ztx->id, ##__VA_ARGS__)

#define DST_PROTOCOL "dst_protocol"
#define DST_HOSTNAME "dst_hostname"
#define DST_PORT "dst_port"

#define ZITI_LOG_ERROR(level, e, fmt, ...) do{\
const char *reason = model_map_get(&e->cause, "reason");\
ZITI_LOG(level, fmt " %s[%s] reason[%s]", ##__VA_ARGS__, e->code, e->message, reason ? reason : ""); \
} while(0)


extern const char *APP_ID;
extern const char *APP_VERSION;

typedef struct message_s message;
typedef struct hdr_s hdr_t;

typedef struct zt_channel zt_channel_t;

typedef void (*reply_cb)(void *ctx, message *m, int err);

typedef void (*ch_notify_state)(
        zt_channel_t *ch, zt_router_status status, int err, void *ctx);

typedef int ch_state;
typedef int conn_state;

struct zt_channel {
    uv_loop_t *loop;
    struct zt_ctx *ztx;
    char *name;
    char *url;
    char *version;
    char *host;
    int port;

    uint32_t id;
    char token[UUID_STR_LEN];
    tlsuv_stream_t *connection;
    bool reconnect;

    // multipurpose timer:
    // - reconnect timeout if not connected
    // - connect timeout when connecting
    // - latency interval/timeout if connected
    deadline_t deadline;

    uint64_t latency;
    struct waiter_s *latency_waiter;
    uint64_t last_read;
    uint64_t last_write;
    uint64_t last_write_delay;
    size_t out_q;
    size_t out_q_bytes;

    ch_state state;
    uint32_t reconnect_count;

    uint32_t msg_seq;

    buffer *incoming;

    pool_t *in_msg_pool;
    message *in_next;
    size_t in_body_offset;

    // map[id->msg_receiver]
    model_map receivers;

    // map[msg_seq->waiter_s]
    model_map waiters;

    ch_notify_state notify_cb;
    void *notify_ctx;
};

struct zt_write_req_s {
    struct zt_conn *conn;
    struct zt_channel *ch;
    const uint8_t *buf;
    size_t len;
    bool eof;
    bool close;

    struct message_s *message;
    zt_write_cb cb;
    uint64_t start_ts;

    void *ctx;

    TAILQ_ENTRY(zt_write_req_s) _next;
    model_list chain;
    size_t chain_len;
};

struct key_pair {
    uint8_t sk[crypto_kx_SECRETKEYBYTES];
    uint8_t pk[crypto_kx_PUBLICKEYBYTES];
};

struct key_exchange {
    uint8_t *rx;
    uint8_t *tx;
};

int init_key_pair(struct key_pair *kp);

int init_crypto(struct key_exchange *key_ex, struct key_pair *kp, const uint8_t *peer_key, bool server);

void free_key_exchange(struct key_exchange *key_ex);

enum zt_conn_type {
    None,
    Transport,
    Server,
};

struct zt_conn {
    struct zt_ctx *zt_ctx;
    enum zt_conn_type type;
    char *service;
    char *source_identity;
    uint32_t conn_id;
    uint32_t rt_conn_id;
    void *data;

    int (*disposer)(struct zt_conn *self);

    zt_close_cb close_cb;
    bool close;
    bool encrypted;

    union {
        struct {
            char *identity;
            uint16_t cost;
            uint8_t precedence;
            int max_bindings;

            zt_listen_cb listen_cb;
            zt_client_cb client_cb;

            bool srv_routers_api_missing;
            model_list routers;
            char *token;
            zt_session *session;
            model_map bindings;
            model_map children;
            deadline_t rebinder;
            unsigned int attempt;
            uint8_t listener_id[32];
        } server;

        struct {
            struct key_pair key_pair;
            struct zt_conn_req *conn_req;

            char marker[MARKER_CHAR_LEN];

            uint32_t edge_msg_seq;
            uint32_t in_msg_seq;
            uint32_t flags;

            zt_channel_t *channel;
            zt_data_cb data_cb;
            conn_state state;
            bool fin_sent;
            int fin_recv; // 0 - not received, 1 - received, 2 - called app data cb
            bool disconnecting;

            deadline_t flusher;
            TAILQ_HEAD(, message_s) in_q;
            buffer *inbound;
            TAILQ_HEAD(, zt_write_req_s) wreqs;
            TAILQ_HEAD(, zt_write_req_s) pending_wreqs;

            struct zt_conn *parent;
            uint32_t dial_req_seq;

            struct key_exchange key_ex;

            crypto_secretstream_xchacha20poly1305_state crypt_o;
            crypto_secretstream_xchacha20poly1305_state crypt_i;

            // stats
            bool bridged;
            uint64_t start;
            uint64_t connect_time;
            uint64_t last_activity;
            uint64_t sent;
            uint64_t received;
        };
    };


};

struct process {
    char *path;
    bool is_running;
    char *sha_512_hash;
    char **signers;
    int num_signers;
};

typedef void (*ztx_work_f)(zt_context ztx, void *w_ctx);

struct ztx_work_s {
    ztx_work_f w;
    void *w_data;
    STAILQ_ENTRY(ztx_work_s) _next;
};

typedef STAILQ_HEAD(work_q, ztx_work_s) ztx_work_q;

struct tls_credentials {
    tlsuv_private_key_t key;
    tlsuv_certificate_t cert;
};

struct zt_ctx {
    zt_config config;
    zt_options opts;
    zt_controller ctrl;
    uint32_t id;

    model_map ctrl_details;

    tls_context *tlsCtx;
    struct tls_credentials id_creds;
    struct tls_credentials session_creds;
    char *sessionCsr;

    bool closing;
    bool enabled;
    int ctrl_status;

    zt_auth_method_t *auth_method;
    zt_auth_state auth_state;
    zt_mfa_cb mfa_cb;
    void *mfa_ctx;

    model_map ext_signers;
    struct ext_oidc_client_s *ext_auth;
    void (*ext_launch_cb)(zt_context, const char*, void*);
    void *ext_launch_ctx;

    // HA access_token(JWT) or legacy zt_api_session.token
    char *session_token;
    timestamp session_expiration;

    zt_identity_data *identity_data;

    bool services_loaded;
    // map<name,zt_service>
    model_map services;
    // map<service_id,zt_session>
    model_map sessions;

    sticky_tokens_map sticky_tokens;

    // map<service_id,*bool>
    model_map service_forced_updates;

    char *last_update;

    // map<erUrl,zt_channel>
    model_map channels;
    // map<id,zt_conn>
    model_map connections;

    // map<conn_id,conn_id> -- connections waiting for a suitable channel
    // map to make removal easier
    model_map waiting_connections;

    uint32_t conn_seq;

    /* context wide metrics */
    uint64_t start;
    rate_t up_rate;
    rate_t down_rate;

    /* posture check support */
    struct posture_checks *posture_checks;

    /* auth query (MFA) support */
    struct auth_queries *auth_queries;

    deadline_t refresh_deadline;
    deadline_list_t deadlines;

    uv_loop_t *loop;
    uv_timer_t deadline_timer;

    uv_prepare_t prepper;
    ztx_work_q w_queue;
};

#ifdef __cplusplus
extern "C" {
#endif

zt_controller *ztx_get_controller(zt_context ztx);

void zt_invalidate_session(zt_context ztx, const char *service_id, zt_session_type type);

void zt_on_channel_event(zt_channel_t *ch, zt_router_status status, int err, zt_context ztx);

void zt_force_api_session_refresh(zt_context ztx);

const char* zt_get_api_session_token(zt_context ztx);

int zt_close_channels(zt_context ztx, int err);

bool zt_channel_is_connected(zt_channel_t *ch);

uint64_t zt_channel_latency(zt_channel_t *ch);

void zt_channel_set_url(zt_channel_t *ch, const char *url);

int zt_channel_force_connect(zt_channel_t *ch);

int zt_channel_update_token(zt_channel_t *ch, const char *token);

int zt_channel_update_posture(zt_channel_t *ch, const uint8_t *data, size_t len);

int zt_channel_connect(zt_context ztx, const zt_edge_router *er);

int zt_channel_prepare(zt_channel_t *ch);

int zt_channel_disconnect(zt_channel_t *ch, int err);
int zt_channel_close(zt_channel_t *ch, int err);

void zt_channel_add_receiver(zt_channel_t *ch, uint32_t id, void *receiver, void (*receive_f)(void *, message *, int));

void zt_channel_rem_receiver(zt_channel_t *ch, uint32_t id);

int zt_channel_send_message(zt_channel_t *ch, message *msg, struct zt_write_req_s *zt_write);

int zt_channel_send(zt_channel_t *ch, uint32_t content, const hdr_t *hdrs, int nhdrs, const uint8_t *body,
                      uint32_t body_len,
                      struct zt_write_req_s *zt_write);

struct waiter_s *
zt_channel_send_for_reply(zt_channel_t *ch, uint32_t content, const hdr_t *headers, int nhdrs, const uint8_t *body,
                            uint32_t body_len, reply_cb,
                            void *reply_ctx);

void zt_channel_remove_waiter(zt_channel_t *ch, struct waiter_s *waiter);

int parse_enrollment_jwt(const char *token, zt_enrollment_jwt_header *zejh, zt_enrollment_jwt *zej, char **sig, size_t *sig_len);

int load_tls(zt_config *cfg, tls_context **tls, struct tls_credentials *creds);

int zt_bind(zt_connection conn, const char *service, const zt_listen_opts *listen_opts,
              zt_listen_cb listen_cb, zt_client_cb on_clt_cb);

void conn_inbound_data_msg(zt_connection conn, message *msg);

void on_write_completed(struct zt_conn *conn, struct zt_write_req_s *req, int status);

void update_bindings(struct zt_conn *conn);
const char *zt_conn_state(zt_connection conn);

int establish_crypto(zt_connection conn, message *msg);


void hexify(const uint8_t *bin, size_t bin_len, char sep, char **buf);

void zt_re_auth_with_cb(zt_context ztx, void(*cb)(zt_api_session *, const zt_error *, void *), void *ctx);

void zt_queue_work(zt_context ztx, ztx_work_f w, void *data);

void zt_force_service_update(zt_context ztx, const char *service_id);

void zt_services_refresh(zt_context ztx, bool now);

extern void zt_send_event(zt_context ztx, const zt_event_t *e);

void reject_dial_request(uint32_t conn_id, zt_channel_t *ch, uint32_t req_id, const char *reason);

const zt_env_info* get_env_info();

int conn_bridge_info(zt_connection conn, char *buf, size_t buflen);

void process_connect(struct zt_conn *conn, zt_session *session);

int ztx_init_external_auth(zt_context ztx, const zt_jwt_signer *signer);

void ztx_auth_state_cb(void *, zt_auth_state , const void *);
zt_channel_t * ztx_get_channel(zt_context ztx, const zt_edge_router *er);

#define ztx_set_deadline(ztx, timeout, d, cb, ctx) do_ztx_set_deadline((ztx), (timeout), (d), (cb), (FILE_BASENAME":"#cb), (ctx))
void do_ztx_set_deadline(zt_context ztx, uint64_t timeout, deadline_t *d, void (*cb)(void *), const char *cb_name, void *ctx);

int ch_send_conn_closed(zt_channel_t *ch, uint32_t conn_id);

#ifdef __cplusplus
}
#endif
#endif //ZT_SDK_ZT_INTERNAL_H
