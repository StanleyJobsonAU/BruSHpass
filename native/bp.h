#ifndef BP_H
#define BP_H
#define _CRT_SECURE_NO_WARNINGS
#define _POSIX_C_SOURCE 200809L
#include <stdint.h>
#include <stdio.h>
#include <stddef.h>
#include <openssl/ssl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
typedef SOCKET bp_socket;
typedef CRITICAL_SECTION bp_mutex;
#define BP_BAD_SOCKET INVALID_SOCKET
#else
#include <pthread.h>
#include <sys/socket.h>
typedef int bp_socket;
typedef pthread_mutex_t bp_mutex;
#define BP_BAD_SOCKET (-1)
#endif

#define BP_CLIENTS 32
#define BP_QUEUE 64
#define BP_BODY 512
#define BP_WIRE 1024
#define BP_EXT 0xff02
#define BP_TIMEOUT 10000
#define BP_CONFIG_SIZE 12288
#define BP_OPEN 1
#define BP_OPEN_REPLY 2
#define BP_DATA 3
#define BP_POLL 0
#define BP_COMMAND 1
#define BP_OUTPUT 2
#define BP_DONE 3

typedef struct {
    uint64_t id, ack, command;
    uint32_t chunk;
    unsigned char kind;
    uint16_t length;
    unsigned char body[BP_BODY];
} bp_frame;

typedef struct {
    int active;
    unsigned char client[16], sid[16], keys[64];
    uint64_t tx, rx, next_id, accepted, running_command;
    uint64_t last_seen;
    bp_frame queue[BP_QUEUE];
    bp_frame last_received;
    unsigned count;
} bp_session;

typedef struct {
    EVP_PKEY *ca_key, *server_key;
    X509 *ca, *server_cert;
} bp_identity;

typedef struct {
    char host[256];
    uint16_t port;
    uint32_t interval;
    unsigned char client[16], server_pin[32];
    EVP_PKEY *key;
    X509 *cert, *ca;
} bp_agent;

typedef struct {
    bp_session sessions[BP_CLIENTS];
    bp_mutex mutex;
    bp_identity identity;
    SSL_CTX *tls;
    bp_socket listener;
    volatile int stop;
    char address[256];
    uint16_t port;
    uint64_t command_counter;
} bp_server;

typedef struct {
    bp_server *server;
    bp_session *session;
    int server_side, opening, parsed, failed;
    unsigned char client[16], nonce[16], sid[16], keys[64];
    unsigned char in[BP_WIRE], out[BP_WIRE];
    size_t inlen, outlen;
    uint64_t incoming_tx;
    bp_frame frame;
} bp_exchange;

int bp_platform_init(void);
void bp_platform_cleanup(void);
uint64_t bp_now(void);
void bp_sleep(unsigned ms);
void bp_mutex_init(bp_mutex *m);
void bp_lock(bp_mutex *m);
void bp_unlock(bp_mutex *m);
void bp_socket_close(bp_socket s);
int bp_interface(const char *input, char output[256]);
bp_socket bp_listen(const char *address, uint16_t port);
bp_socket bp_connect(const char *address, uint16_t port);
int bp_tls_run(SSL *ssl, bp_socket sock, int shutdown);
FILE *bp_private_create(const char *path);
int bp_self_path(char *out, size_t cap);
int bp_cwd(char *out, size_t cap);
int bp_chdir(const char *path);
void bp_print_bytes(const unsigned char *s, size_t n);
int bp_execute(const char *command, unsigned char *output, size_t cap, size_t *length);

void bp_put64(unsigned char *p, uint64_t v);
uint64_t bp_get64(const unsigned char *p);
void bp_hex(const unsigned char *src, size_t n, char *out);
int bp_unhex(const char *src, unsigned char *out, size_t n);
int bp_identity_load(bp_identity *id, const char *path);
void bp_identity_free(bp_identity *id);
int bp_agent_certificate(bp_identity *identity, bp_agent *agent);
SSL_CTX *bp_tls_context(X509 *ca, X509 *cert, EVP_PKEY *key, int server);
int bp_certificate_pin(X509 *cert, unsigned char pin[32]);
int bp_tls_authorized(SSL *ssl, const unsigned char *client, const unsigned char *pin);
int bp_export_keys(SSL *ssl, bp_exchange *ex);
int bp_write_agent(bp_identity *identity, const char *target, const char *output,
                   const char *host, uint16_t port, uint32_t interval, char client_id[33]);
int bp_read_agent(const char *path, bp_agent *agent);
void bp_agent_free(bp_agent *agent);
int bp_register_extension(SSL_CTX *ctx);
int bp_prepare_open(bp_exchange *ex, const unsigned char client[16]);
int bp_prepare_data(bp_exchange *ex, bp_session *session);
int bp_commit(bp_session *session, const bp_exchange *ex, int *new_frame);
int bp_enqueue(bp_session *session, const bp_frame *frame);
void bp_session_clear(bp_session *session);
int bp_selftest(void);

#endif
