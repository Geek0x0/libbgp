#define _POSIX_C_SOURCE 200809L

#include <libbgp/libbgp.h>

#include <errno.h>
#include <inttypes.h>
#include <netinet/in.h>
#include <signal.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/select.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

#define DEFAULT_PORT 1179u
#define DEFAULT_ASN 65000u
#define READ_BUF_LEN 4096u
#define SELECT_TIMEOUT_MS 250u

static void usage(const char *prog)
{
    printf("Usage: %s [--port PORT] [--asn ASN] [--router-id A.B.C.D]\n", prog);
    printf("Listen for one BGP TCP peer, print received packet types, and feed libbgp_fsm.\n");
}

static uint32_t router_id_value(uint8_t a, uint8_t b, uint8_t c, uint8_t d)
{
    return ((uint32_t)a << 24u) |
        ((uint32_t)b << 16u) |
        ((uint32_t)c << 8u) |
        (uint32_t)d;
}

static bool parse_u16(const char *s, uint16_t *out)
{
    char *end = NULL;
    unsigned long value;

    if (s == NULL || *s == '\0') {
        return false;
    }
    errno = 0;
    value = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || value > 65535ul) {
        return false;
    }
    *out = (uint16_t)value;
    return true;
}

static bool parse_u32(const char *s, uint32_t *out)
{
    char *end = NULL;
    unsigned long value;

    if (s == NULL || *s == '\0') {
        return false;
    }
    errno = 0;
    value = strtoul(s, &end, 10);
    if (errno != 0 || end == s || *end != '\0' || value > 4294967295ul) {
        return false;
    }
    *out = (uint32_t)value;
    return true;
}

static bool parse_router_id(const char *s, uint32_t *out)
{
    unsigned int a;
    unsigned int b;
    unsigned int c;
    unsigned int d;
    char tail;

    if (sscanf(s, "%u.%u.%u.%u%c", &a, &b, &c, &d, &tail) != 4) {
        return false;
    }
    if (a > 255u || b > 255u || c > 255u || d > 255u) {
        return false;
    }
    *out = router_id_value((uint8_t)a, (uint8_t)b, (uint8_t)c, (uint8_t)d);
    return true;
}

static const char *packet_type_name(libbgp_packet_type_t type)
{
    switch (type) {
    case LIBBGP_PACKET_OPEN:
        return "OPEN";
    case LIBBGP_PACKET_UPDATE:
        return "UPDATE";
    case LIBBGP_PACKET_NOTIFICATION:
        return "NOTIFICATION";
    case LIBBGP_PACKET_KEEPALIVE:
        return "KEEPALIVE";
    case LIBBGP_PACKET_UNKNOWN:
    default:
        return "UNKNOWN";
    }
}

static uint64_t now_ms(void)
{
    struct timespec ts;

    if (clock_gettime(CLOCK_MONOTONIC, &ts) != 0) {
        return 0u;
    }
    return (uint64_t)ts.tv_sec * 1000u + (uint64_t)ts.tv_nsec / 1000000u;
}

static int listen_socket(uint16_t port)
{
    int fd;
    int yes = 1;
    struct sockaddr_in addr;

    fd = socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) {
        perror("socket");
        return -1;
    }
    if (setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(yes)) != 0) {
        perror("setsockopt");
        close(fd);
        return -1;
    }
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_ANY);
    addr.sin_port = htons(port);
    if (bind(fd, (const struct sockaddr *)&addr, sizeof(addr)) != 0) {
        perror("bind");
        close(fd);
        return -1;
    }
    if (listen(fd, 1) != 0) {
        perror("listen");
        close(fd);
        return -1;
    }
    return fd;
}

static int run_client(int client_fd, const struct libbgp_fsm_config *config)
{
    libbgp_out_handler_t out;
    libbgp_sink_t sink;
    libbgp_fsm_t fsm;
    uint8_t buf[READ_BUF_LEN];
    int rc = 1;
    libbgp_err_t err;

    err = libbgp_out_handler_init(&out);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "out handler init: %s\n", libbgp_strerror(err));
        return 1;
    }
    err = libbgp_sink_init(&sink);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "sink init: %s\n", libbgp_strerror(err));
        libbgp_out_handler_destroy(&out);
        return 1;
    }
    err = libbgp_fsm_init(&fsm, config);
    if (err != LIBBGP_OK) {
        fprintf(stderr, "fsm init: %s\n", libbgp_strerror(err));
        libbgp_sink_destroy(&sink);
        libbgp_out_handler_destroy(&out);
        return 1;
    }
    libbgp_out_handler_set_fd(&out, client_fd);
    libbgp_fsm_set_out_handler(&fsm, &out);
    printf("peer connected\n");

    for (;;) {
        fd_set readfds;
        struct timeval tv;
        int ready;

        FD_ZERO(&readfds);
        FD_SET(client_fd, &readfds);
        tv.tv_sec = 0;
        tv.tv_usec = (suseconds_t)SELECT_TIMEOUT_MS * 1000;
        ready = select(client_fd + 1, &readfds, NULL, NULL, &tv);
        if (ready < 0) {
            if (errno == EINTR) {
                continue;
            }
            perror("select");
            break;
        }
        if (ready > 0 && FD_ISSET(client_fd, &readfds)) {
            ssize_t n = recv(client_fd, buf, sizeof(buf), 0);

            if (n == 0) {
                printf("peer closed connection\n");
                rc = 0;
                break;
            }
            if (n < 0) {
                perror("recv");
                break;
            }
            err = libbgp_sink_feed(&sink, buf, (size_t)n);
            if (err != LIBBGP_OK) {
                fprintf(stderr, "sink feed: %s\n", libbgp_strerror(err));
                break;
            }
            while (libbgp_sink_packet_count(&sink) > 0u) {
                libbgp_packet_t pkt;

                libbgp_packet_init(&pkt);
                err = libbgp_sink_pop(&sink, &pkt);
                if (err != LIBBGP_OK) {
                    fprintf(stderr, "sink pop: %s\n", libbgp_strerror(err));
                    libbgp_packet_destroy(&pkt);
                    goto cleanup;
                }
                printf("received %s\n", packet_type_name(pkt.type));
                err = libbgp_fsm_on_packet(&fsm, &pkt);
                libbgp_packet_destroy(&pkt);
                if (err != LIBBGP_OK) {
                    fprintf(stderr, "fsm packet: %s\n", libbgp_strerror(err));
                    goto cleanup;
                }
            }
        }
        err = libbgp_fsm_tick(&fsm, now_ms());
        if (err != LIBBGP_OK) {
            fprintf(stderr, "fsm tick: %s\n", libbgp_strerror(err));
            break;
        }
    }

cleanup:
    libbgp_fsm_destroy(&fsm);
    libbgp_sink_destroy(&sink);
    libbgp_out_handler_destroy(&out);
    return rc;
}

int main(int argc, char **argv)
{
    uint16_t port = (uint16_t)DEFAULT_PORT;
    struct libbgp_fsm_config config;
    int listen_fd;
    int client_fd;
    int i;

    if (signal(SIGPIPE, SIG_IGN) == SIG_ERR) {
        perror("signal");
        return 1;
    }

    config.local_asn = DEFAULT_ASN;
    config.local_bgp_id = router_id_value(192u, 0u, 2u, 1u);
    config.hold_time = 90u;
    config.keepalive_time = 30u;
    config.enable_4byte_asn = true;
    config.enable_mpbgp_ipv6 = false;

    for (i = 1; i < argc; i++) {
        if (strcmp(argv[i], "--help") == 0 || strcmp(argv[i], "-h") == 0) {
            usage(argv[0]);
            return 0;
        }
        if (strcmp(argv[i], "--port") == 0 && i + 1 < argc) {
            if (!parse_u16(argv[++i], &port) || port == 0u) {
                fprintf(stderr, "invalid --port\n");
                return 2;
            }
            continue;
        }
        if (strcmp(argv[i], "--asn") == 0 && i + 1 < argc) {
            if (!parse_u32(argv[++i], &config.local_asn)) {
                fprintf(stderr, "invalid --asn\n");
                return 2;
            }
            continue;
        }
        if (strcmp(argv[i], "--router-id") == 0 && i + 1 < argc) {
            if (!parse_router_id(argv[++i], &config.local_bgp_id) || config.local_bgp_id == 0u) {
                fprintf(stderr, "invalid --router-id\n");
                return 2;
            }
            continue;
        }
        fprintf(stderr, "unknown argument: %s\n", argv[i]);
        usage(argv[0]);
        return 2;
    }

    listen_fd = listen_socket(port);
    if (listen_fd < 0) {
        return 1;
    }
    printf("listening on 0.0.0.0:%u\n", (unsigned int)port);
    client_fd = accept(listen_fd, NULL, NULL);
    if (client_fd < 0) {
        perror("accept");
        close(listen_fd);
        return 1;
    }
    close(listen_fd);
    i = run_client(client_fd, &config);
    close(client_fd);
    return i;
}
