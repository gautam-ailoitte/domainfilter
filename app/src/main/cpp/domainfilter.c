// domainfilter.c
#include <jni.h>
#include <android/log.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include <fcntl.h>
#include <errno.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>

#define TAG "DomainFilter"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Global variables
static int vpn_fd = -1;
static pthread_t worker_thread;
static int running = 0;
static JNIEnv *jni_env = NULL;
static jobject vpn_service = NULL;
static jmethodID protect_socket_method = NULL;

// Connection tracking structure
typedef struct {
    int protocol;           // IPPROTO_TCP or IPPROTO_UDP
    uint32_t src_ip;
    uint16_t src_port;
    uint32_t dst_ip;
    uint16_t dst_port;
    int socket_fd;          // Socket for forwarding traffic
    uint64_t last_active;   // Timestamp for timeout

    // TCP state tracking
    uint32_t tcp_seq_in;    // Sequence number for incoming data
    uint32_t tcp_seq_out;   // Sequence number for outgoing data
    uint32_t tcp_ack_in;    // Acknowledgment for incoming data
    uint32_t tcp_ack_out;   // Acknowledgment for outgoing data
    int tcp_state;          // TCP connection state
} connection_t;

// Simple connection tracker (in production, use a hash table)
#define MAX_CONNECTIONS 1024
static connection_t connections[MAX_CONNECTIONS];
static int num_connections = 0;
static pthread_mutex_t conn_mutex = PTHREAD_MUTEX_INITIALIZER;

// Forward declarations
static int process_packet(const void *packet, size_t len);
static int handle_outgoing_packet(const void *packet, size_t len);
static int handle_incoming_data();
static int extract_domain(const void *packet, size_t len, char *domain, size_t domain_size);
static int is_domain_blocked(const char *domain);
static connection_t *find_or_create_connection(const void *packet, size_t len);
static void cleanup_connections();
static uint64_t get_time_ms();

// JNI function to initialize the module
JNIEXPORT void JNICALL
Java_com_example_domainfilter_FilterVpnService_jniInit(JNIEnv *env, jobject thiz) {
LOGI("Initializing native module");

// Save JNI environment and VPN service object
jni_env = env;
vpn_service = (*env)->NewGlobalRef(env, thiz);

// Get method ID for protectSocket
jclass vpn_class = (*env)->GetObjectClass(env, vpn_service);
protect_socket_method = (*env)->GetMethodID(env, vpn_class, "protectSocket", "(I)V");

if (protect_socket_method == NULL) {
LOGE("Failed to get protectSocket method");
return;
}

LOGI("Native module initialized");
}

// JNI function to start packet processing
JNIEXPORT void JNICALL
Java_com_example_domainfilter_FilterVpnService_jniStart(JNIEnv *env, jobject thiz, jint fd) {
if (running) {
LOGI("Already running, ignoring start request");
return;
}

LOGI("Starting native packet processing with fd: %d", fd);
vpn_fd = fd;
running = 1;

// Make socket non-blocking
int flags = fcntl(vpn_fd, F_GETFL, 0);
fcntl(vpn_fd, F_SETFL, flags | O_NONBLOCK);

// Initialize connection tracking
memset(connections, 0, sizeof(connections));
num_connections = 0;

// Main processing loop (on this thread)
unsigned char buffer[4096];

while (running) {
// Process outgoing packets (from apps to VPN)
ssize_t length = read(vpn_fd, buffer, sizeof(buffer));
if (length > 0) {
process_packet(buffer, length);
} else if (length < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
LOGE("Error reading from VPN interface: %s", strerror(errno));
}

// Process incoming packets (from network to apps)
handle_incoming_data();

// Cleanup idle connections periodically
static uint64_t last_cleanup = 0;
uint64_t now = get_time_ms();
if (now - last_cleanup > 10000) { // Every 10 seconds
cleanup_connections();
last_cleanup = now;
}

// Small sleep to prevent CPU thrashing
usleep(10000); // 10ms
}

LOGI("Packet processing loop ended");
}

// JNI function to stop packet processing
JNIEXPORT void JNICALL
Java_com_example_domainfilter_FilterVpnService_jniStop(JNIEnv *env, jobject thiz) {
LOGI("Stopping native packet processing");
running = 0;

// Cleanup resources
pthread_mutex_lock(&conn_mutex);
for (int i = 0; i < num_connections; i++) {
if (connections[i].socket_fd > 0) {
close(connections[i].socket_fd);
connections[i].socket_fd = -1;
}
}
num_connections = 0;
pthread_mutex_unlock(&conn_mutex);

if (vpn_service != NULL) {
(*jni_env)->DeleteGlobalRef(jni_env, vpn_service);
vpn_service = NULL;
}

LOGI("Native packet processing stopped");
}

// Main packet processing function
static int process_packet(const void *packet, size_t len) {
    if (len < sizeof(struct iphdr)) {
        LOGE("Packet too small");
        return -1;
    }

    const struct iphdr *ip = packet;

    // Handle only IPv4 packets for simplicity
    if (ip->version != 4) {
        return -1;
    }

    // Extract domain for DNS or HTTP/HTTPS traffic
    char domain[256];
    if (extract_domain(packet, len, domain, sizeof(domain)) > 0) {
        // Check if domain is blocked
        if (is_domain_blocked(domain)) {
            LOGI("Blocking domain: %s", domain);
            // Return without forwarding (block)
            return 0;
        }
    }

    // Forward packet to real network
    return handle_outgoing_packet(packet, len);
}

// Handle outgoing packet (from app to network)
static int handle_outgoing_packet(const void *packet, size_t len) {
    // Find or create connection tracking entry
    connection_t *conn = find_or_create_connection(packet, len);
    if (conn == NULL) {
        LOGE("Failed to create connection");
        return -1;
    }

    const struct iphdr *ip = packet;

    // Extract payload to forward
    const unsigned char *payload;
    size_t payload_len;

    if (ip->protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr *)((const char *)ip + (ip->ihl * 4));
        payload = (const unsigned char *)tcp + (tcp->doff * 4);
        payload_len = ntohs(ip->tot_len) - (ip->ihl * 4) - (tcp->doff * 4);

        // Handle TCP state tracking here (simplified)
        // In reality, you'd need full TCP state machine

    } else if (ip->protocol == IPPROTO_UDP) {
        const struct udphdr *udp = (const struct udphdr *)((const char *)ip + (ip->ihl * 4));
        payload = (const unsigned char *)udp + 8; // UDP header is 8 bytes
        payload_len = ntohs(udp->len) - 8;
    } else {
        // Unsupported protocol
        return -1;
    }

    // Forward payload to real network if there's data to send
    if (payload_len > 0) {
        ssize_t sent = send(conn->socket_fd, payload, payload_len, 0);
        if (sent < 0) {
            LOGE("Failed to send data: %s", strerror(errno));
            return -1;
        }
    }

    // Update last active time
    conn->last_active = get_time_ms();

    return 0;
}

// Handle incoming data (from network to app)
static int handle_incoming_data() {
    fd_set readfds;
    struct timeval tv;

    FD_ZERO(&readfds);
    int max_fd = -1;

    // Add all connection sockets to select set
    pthread_mutex_lock(&conn_mutex);
    for (int i = 0; i < num_connections; i++) {
        if (connections[i].socket_fd > 0) {
            FD_SET(connections[i].socket_fd, &readfds);
            if (connections[i].socket_fd > max_fd) {
                max_fd = connections[i].socket_fd;
            }
        }
    }
    pthread_mutex_unlock(&conn_mutex);

    if (max_fd < 0) {
        return 0; // No connections
    }

    // Set timeout to 10ms
    tv.tv_sec = 0;
    tv.tv_usec = 10000;

    int ready = select(max_fd + 1, &readfds, NULL, NULL, &tv);
    if (ready <= 0) {
        return 0; // No data or error
    }

    // Process readable sockets
    pthread_mutex_lock(&conn_mutex);
    for (int i = 0; i < num_connections; i++) {
        if (connections[i].socket_fd > 0 && FD_ISSET(connections[i].socket_fd, &readfds)) {
            unsigned char buffer[4096];
            ssize_t received = recv(connections[i].socket_fd, buffer, sizeof(buffer), 0);

            if (received > 0) {
                // Update last active time
                connections[i].last_active = get_time_ms();

                // Create a response packet
                unsigned char packet[4096];
                size_t packet_len = 0;

                // Craft IP and TCP/UDP headers (this is complex!)
                // In reality, you need to build proper headers with checksums

                // This is where you'd create a proper response packet
                // with correct IP, TCP/UDP headers for writing to the VPN interface

                // For TCP, you'd also need to update sequence numbers, etc.

                // Write response packet to VPN interface
                if (packet_len > 0) {
                    write(vpn_fd, packet, packet_len);
                }
            } else if (received == 0) {
                // Connection closed
                close(connections[i].socket_fd);
                connections[i].socket_fd = -1;
            } else if (received < 0 && errno != EAGAIN && errno != EWOULDBLOCK) {
                LOGE("Recv error: %s", strerror(errno));
                close(connections[i].socket_fd);
                connections[i].socket_fd = -1;
            }
        }
    }
    pthread_mutex_unlock(&conn_mutex);

    return 0;
}

// Find or create connection tracking entry
static connection_t *find_or_create_connection(const void *packet, size_t len) {
    const struct iphdr *ip = packet;
    uint32_t src_ip = ntohl(ip->saddr);
    uint32_t dst_ip = ntohl(ip->daddr);
    uint16_t src_port = 0, dst_port = 0;

    if (ip->protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr *)((const char *)ip + (ip->ihl * 4));
        src_port = ntohs(tcp->source);
        dst_port = ntohs(tcp->dest);
    } else if (ip->protocol == IPPROTO_UDP) {
        const struct udphdr *udp = (const struct udphdr *)((const char *)ip + (ip->ihl * 4));
        src_port = ntohs(udp->source);
        dst_port = ntohs(udp->dest);
    } else {
        return NULL; // Unsupported protocol
    }

    pthread_mutex_lock(&conn_mutex);

    // Look for existing connection
    for (int i = 0; i < num_connections; i++) {
        if (connections[i].protocol == ip->protocol &&
            connections[i].src_ip == src_ip &&
            connections[i].src_port == src_port &&
            connections[i].dst_ip == dst_ip &&
            connections[i].dst_port == dst_port) {

            pthread_mutex_unlock(&conn_mutex);
            return &connections[i];
        }
    }

    // Create new connection if not found
    if (num_connections < MAX_CONNECTIONS) {
        connection_t *conn = &connections[num_connections];
        memset(conn, 0, sizeof(connection_t));

        conn->protocol = ip->protocol;
        conn->src_ip = src_ip;
        conn->src_port = src_port;
        conn->dst_ip = dst_ip;
        conn->dst_port = dst_port;

        // Create socket for real network
        int sock_type = (ip->protocol == IPPROTO_TCP) ? SOCK_STREAM : SOCK_DGRAM;
        conn->socket_fd = socket(AF_INET, sock_type, 0);

        if (conn->socket_fd < 0) {
            LOGE("Failed to create socket: %s", strerror(errno));
            pthread_mutex_unlock(&conn_mutex);
            return NULL;
        }

        // Protect socket from VPN routing
        if (vpn_service != NULL && protect_socket_method != NULL) {
            (*jni_env)->CallVoidMethod(jni_env, vpn_service, protect_socket_method, conn->socket_fd);
        }

        // For UDP, connect is optional but simplifies sending
        // For TCP, we must connect
        struct sockaddr_in addr;
        memset(&addr, 0, sizeof(addr));
        addr.sin_family = AF_INET;
        addr.sin_port = htons(dst_port);
        addr.sin_addr.s_addr = htonl(dst_ip);

        if (connect(conn->socket_fd, (struct sockaddr *)&addr, sizeof(addr)) < 0) {
            LOGE("Failed to connect socket: %s", strerror(errno));
            close(conn->socket_fd);
            pthread_mutex_unlock(&conn_mutex);
            return NULL;
        }

        // Make socket non-blocking
        int flags = fcntl(conn->socket_fd, F_GETFL, 0);
        fcntl(conn->socket_fd, F_SETFL, flags | O_NONBLOCK);

        conn->last_active = get_time_ms();
        num_connections++;

        pthread_mutex_unlock(&conn_mutex);
        return conn;
    }

    pthread_mutex_unlock(&conn_mutex);
    return NULL; // Too many connections
}

// Extract domain from packet (DNS, HTTP, TLS)
// Returns length of domain or 0 if not found
static int extract_domain(const void *packet, size_t len, char *domain, size_t domain_size) {
    const struct iphdr *ip = packet;

    // This is a simplified implementation
    // In reality, you need full protocol parsing for:
    // 1. DNS queries
    // 2. HTTP Host headers
    // 3. TLS SNI from ClientHello

    // For DNS, check if it's a UDP packet to port 53
    if (ip->protocol == IPPROTO_UDP) {
        const struct udphdr *udp = (const struct udphdr *)((const char *)ip + (ip->ihl * 4));
        if (ntohs(udp->dest) == 53) {
            // Parse DNS query (simplified)
            // ...
        }
    }

        // For HTTP, check if it's a TCP packet to port 80
    else if (ip->protocol == IPPROTO_TCP) {
        const struct tcphdr *tcp = (const struct tcphdr *)((const char *)ip + (ip->ihl * 4));

        // HTTP (port 80)
        if (ntohs(tcp->dest) == 80) {
            // Parse HTTP Host header (simplified)
            // ...
        }
            // HTTPS (port 443) - Check for TLS ClientHello with SNI
        else if (ntohs(tcp->dest) == 443) {
            // Parse TLS SNI (simplified)
            // ...
        }
    }

    return 0; // No domain found
}

// Check if domain is blocked
static int is_domain_blocked(const char *domain) {
    // This is where you'd implement your domain filtering logic
    // Options include:
    // 1. Simple string matching against a blocklist
    // 2. Trie-based matching for efficiency
    // 3. Regex matching for pattern support
    // 4. Bloom filter for memory efficiency

    // Example of simple blocking (replace with your logic)
    static const char *blocked_domains[] = {
            "ads.example.com",
            "tracker.example.com",
            "malware.example.org",
            NULL
    };

    for (int i = 0; blocked_domains[i] != NULL; i++) {
        if (strcmp(domain, blocked_domains[i]) == 0) {
            return 1; // Blocked
        }
    }

    return 0; // Not blocked
}

// Cleanup inactive connections
static void cleanup_connections() {
    pthread_mutex_lock(&conn_mutex);

    uint64_t now = get_time_ms();
    uint64_t timeout = 60000; // 60 seconds timeout

    for (int i = 0; i < num_connections; i++) {
        if (connections[i].socket_fd > 0 && now - connections[i].last_active > timeout) {
            LOGI("Cleaning up inactive connection");
            close(connections[i].socket_fd);
            connections[i].socket_fd = -1;
        }
    }

    // Compact the connections array by removing closed connections
    int j = 0;
    for (int i = 0; i < num_connections; i++) {
        if (connections[i].socket_fd > 0) {
            if (i != j) {
                memcpy(&connections[j], &connections[i], sizeof(connection_t));
            }
            j++;
        }
    }
    num_connections = j;

    pthread_mutex_unlock(&conn_mutex);
}

// Get current time in milliseconds
static uint64_t get_time_ms() {
    struct timespec ts;
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return (ts.tv_sec * 1000ULL) + (ts.tv_nsec / 1000000ULL);
}