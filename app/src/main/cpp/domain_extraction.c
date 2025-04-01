// domain_extraction.c
#include <string.h>
#include <stdint.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <android/log.h>
#include "include/domainfilter.h"

#define TAG "DomainExtract"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Extract domain from DNS packet
static int extract_dns_domain(const uint8_t *dns_data, size_t dns_len, char *domain, size_t domain_size) {
    if (dns_len < 12) {
        return 0; // DNS header is at least 12 bytes
    }

    // Skip DNS header (12 bytes)
    const uint8_t *query = dns_data + 12;
    size_t query_len = dns_len - 12;

    if (query_len <= 0) {
        return 0;
    }

    // Extract query name
    size_t pos = 0;
    size_t label_len = 0;
    size_t domain_pos = 0;
    int first_label = 1;

    while (pos < query_len) {
        label_len = query[pos++];

        // End of name
        if (label_len == 0) {
            break;
        }

        // Compressed pointer - not handling for simplicity
        if ((label_len & 0xC0) == 0xC0) {
            break;
        }

        // Add dot between labels
        if (!first_label) {
            if (domain_pos < domain_size - 1) {
                domain[domain_pos++] = '.';
            }
        }
        first_label = 0;

        // Copy label to domain buffer
        for (int i = 0; i < label_len && pos < query_len; i++) {
            if (domain_pos < domain_size - 1) {
                domain[domain_pos++] = query[pos];
            }
            pos++;
        }
    }

    // Ensure null termination
    if (domain_pos < domain_size) {
        domain[domain_pos] = '\0';
    } else if (domain_size > 0) {
        domain[domain_size - 1] = '\0';
    }

    return domain_pos;
}

// Extract domain from HTTP Host header
static int extract_http_host(const uint8_t *http_data, size_t http_len, char *domain, size_t domain_size) {
    // Look for "Host: " header
    const char *host_header = "Host: ";
    const size_t host_header_len = strlen(host_header);

    // Find Host header
    for (size_t i = 0; i + host_header_len + 2 < http_len; i++) {
        if (memcmp(http_data + i, host_header, host_header_len) == 0) {
            // Extract host value
            size_t domain_pos = 0;
            size_t pos = i + host_header_len;

            // Copy until CR, LF, or end of buffer
            while (pos < http_len && http_data[pos] != '\r' && http_data[pos] != '\n') {
                if (domain_pos < domain_size - 1) {
                    domain[domain_pos++] = http_data[pos];
                }
                pos++;
            }

            // Strip port if present
            for (size_t j = 0; j < domain_pos; j++) {
                if (domain[j] == ':') {
                    domain_pos = j;
                    break;
                }
            }

            // Null terminate
            if (domain_pos < domain_size) {
                domain[domain_pos] = '\0';
            } else if (domain_size > 0) {
                domain[domain_size - 1] = '\0';
            }

            return domain_pos;
        }
    }

    return 0;
}

// Extract SNI from TLS ClientHello
static int extract_tls_sni(const uint8_t *tls_data, size_t tls_len, char *domain, size_t domain_size) {
    // TLS record header (5 bytes)
    if (tls_len < 5) {
        return 0;
    }

    // Check if it's a handshake record
    if (tls_data[0] != 0x16) {
        return 0;
    }

    // Check TLS version (1.0, 1.1, 1.2)
    if (tls_data[1] != 0x03 || (tls_data[2] != 0x01 && tls_data[2] != 0x02 && tls_data[2] != 0x03)) {
        return 0;
    }

    // Parse record length
    uint16_t record_len = (tls_data[3] << 8) | tls_data[4];
    if (record_len + 5 > tls_len) {
        return 0;
    }

    // Skip to handshake message
    const uint8_t *handshake = tls_data + 5;

    // Check if it's a ClientHello
    if (handshake[0] != 0x01) {
        return 0;
    }

    // Skip handshake header (4 bytes)
    if (record_len < 4) {
        return 0;
    }

    // Skip client version (2 bytes) and client random (32 bytes)
    size_t pos = 4 + 2 + 32;
    if (pos + 1 > record_len) {
        return 0;
    }

    // Skip session ID
    uint8_t session_id_len = handshake[pos];
    pos += 1 + session_id_len;
    if (pos + 2 > record_len) {
        return 0;
    }

    // Skip cipher suites
    uint16_t cipher_suites_len = (handshake[pos] << 8) | handshake[pos + 1];
    pos += 2 + cipher_suites_len;
    if (pos + 1 > record_len) {
        return 0;
    }

    // Skip compression methods
    uint8_t compression_methods_len = handshake[pos];
    pos += 1 + compression_methods_len;
    if (pos + 2 > record_len) {
        return 0;
    }

    // Check if we have extensions
    if (pos + 2 > record_len) {
        return 0;
    }

    // Parse extensions length
    uint16_t extensions_len = (handshake[pos] << 8) | handshake[pos + 1];
    pos += 2;
    if (pos + extensions_len > record_len) {
        return 0;
    }

    // Parse extensions
    size_t extensions_end = pos + extensions_len;
    while (pos + 4 <= extensions_end) {
        uint16_t extension_type = (handshake[pos] << 8) | handshake[pos + 1];
        uint16_t extension_len = (handshake[pos + 2] << 8) | handshake[pos + 3];
        pos += 4;

        if (pos + extension_len > extensions_end) {
            break;
        }

        // SNI extension (type 0)
        if (extension_type == 0) {
            // Parse SNI extension
            if (extension_len < 2) {
                break;
            }

            uint16_t sni_list_len = (handshake[pos] << 8) | handshake[pos + 1];
            pos += 2;

            if (pos + sni_list_len > extensions_end || sni_list_len < 3) {
                break;
            }

            // Check entry type (should be 0 for hostname)
            if (handshake[pos] != 0) {
                break;
            }

            // Get hostname length
            uint16_t name_len = (handshake[pos + 1] << 8) | handshake[pos + 2];
            pos += 3;

            if (pos + name_len > extensions_end) {
                break;
            }

            // Copy hostname
            size_t copy_len = name_len < domain_size - 1 ? name_len : domain_size - 1;
            memcpy(domain, handshake + pos, copy_len);
            domain[copy_len] = '\0';

            return copy_len;
        }

        pos += extension_len;
    }

    return 0;
}

// Main domain extraction function - exported
int extract_domain_from_packet(const void *packet, size_t len, char *domain, size_t domain_size) {
    if (len < sizeof(struct iphdr)) {
        return 0;
    }

    const struct iphdr *ip = packet;
    if (ip->version != 4) {
        return 0;
    }

    size_t ip_header_len = ip->ihl * 4;
    if (len < ip_header_len) {
        return 0;
    }

    // DNS query (UDP port 53)
    if (ip->protocol == IPPROTO_UDP) {
        if (len < ip_header_len + sizeof(struct udphdr)) {
            return 0;
        }

        const struct udphdr *udp = (const struct udphdr *)((const char *)ip + ip_header_len);

        if (ntohs(udp->dest) == 53) {
            const uint8_t *dns_data = (const uint8_t *)udp + sizeof(struct udphdr);
            size_t dns_len = ntohs(udp->len) - sizeof(struct udphdr);

            return extract_dns_domain(dns_data, dns_len, domain, domain_size);
        }
    }
        // HTTP/HTTPS (TCP port 80/443)
    else if (ip->protocol == IPPROTO_TCP) {
        if (len < ip_header_len + sizeof(struct tcphdr)) {
            return 0;
        }

        const struct tcphdr *tcp = (const struct tcphdr *)((const char *)ip + ip_header_len);
        size_t tcp_header_len = tcp->doff * 4;

        if (len < ip_header_len + tcp_header_len) {
            return 0;
        }

        const uint8_t *payload = (const uint8_t *)tcp + tcp_header_len;
        size_t payload_len = len - ip_header_len - tcp_header_len;

        // HTTP (port 80)
        if (ntohs(tcp->dest) == 80) {
            return extract_http_host(payload, payload_len, domain, domain_size);
        }
            // HTTPS (port 443)
        else if (ntohs(tcp->dest) == 443) {
            return extract_tls_sni(payload, payload_len, domain, domain_size);
        }
    }

    return 0;
}