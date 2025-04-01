// domain_filter.c
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <pthread.h>
#include <android/log.h>
#include <ctype.h> // Added this header for isdigit()

#define TAG "DomainFilter"
#define LOGI(...) __android_log_print(ANDROID_LOG_INFO, TAG, __VA_ARGS__)
#define LOGE(...) __android_log_print(ANDROID_LOG_ERROR, TAG, __VA_ARGS__)

// Trie node structure for efficient domain filtering
typedef struct trie_node {
    struct trie_node *children[256]; // Support for international domains
    uint8_t is_end;                  // Is this the end of a domain?
    uint8_t wildcard;                // Is this a wildcard node?
} trie_node_t;

// Global filter trie root
static trie_node_t *filter_trie = NULL;
static pthread_mutex_t filter_mutex = PTHREAD_MUTEX_INITIALIZER;

// Create a new trie node
static trie_node_t *create_node() {
    trie_node_t *node = (trie_node_t *)calloc(1, sizeof(trie_node_t));
    return node;
}

// Initialize the filter engine
void filter_init() {
    pthread_mutex_lock(&filter_mutex);

    if (filter_trie == NULL) {
        filter_trie = create_node();
    }

    pthread_mutex_unlock(&filter_mutex);
    LOGI("Domain filter initialized");
}

// Clean up a trie node recursively
static void free_node(trie_node_t *node) {
    if (node == NULL) {
        return;
    }

    for (int i = 0; i < 256; i++) {
        if (node->children[i] != NULL) {
            free_node(node->children[i]);
        }
    }

    free(node);
}

// Clean up the filter engine
void filter_cleanup() {
    pthread_mutex_lock(&filter_mutex);

    if (filter_trie != NULL) {
        free_node(filter_trie);
        filter_trie = NULL;
    }

    pthread_mutex_unlock(&filter_mutex);
    LOGI("Domain filter cleaned up");
}

// Insert a domain into the filter trie
// For blocking example.com, the domain is inserted in reverse order: com.example
// This makes wildcard matching easier
void filter_add_domain(const char *domain) {
    if (domain == NULL || *domain == '\0') {
        return;
    }

    // Reverse domain for insertion
    char reversed[256];
    size_t domain_len = strlen(domain);

    if (domain_len >= sizeof(reversed)) {
        LOGE("Domain too long: %s", domain);
        return;
    }

    // Find domain parts and reverse them
    size_t pos = 0;
    const char *start = domain;
    const char *end = domain + domain_len;
    const char *current = end;

    // Handle trailing dot
    if (domain_len > 0 && domain[domain_len - 1] == '.') {
        current--;
    }

    while (current > start) {
        const char *part_end = current;

        // Find start of part (or end of previous part)
        while (current > start && *(current - 1) != '.') {
            current--;
        }

        // Copy the part
        for (const char *p = current; p < part_end; p++) {
            if (pos < sizeof(reversed) - 1) {
                reversed[pos++] = *p;
            }
        }

        // Add separator
        if (current > start && pos < sizeof(reversed) - 1) {
            reversed[pos++] = '.';
        }

        // Skip the dot
        if (current > start) {
            current--;
        }
    }

    // Null terminate
    reversed[pos] = '\0';

    // Insert into trie
    pthread_mutex_lock(&filter_mutex);

    trie_node_t *node = filter_trie;
    if (node == NULL) {
        // Initialize if needed
        node = filter_trie = create_node();
    }

    // Check for wildcard domain
    int is_wildcard = 0;
    if (pos > 2 && reversed[0] == '*' && reversed[1] == '.') {
        is_wildcard = 1;
        memmove(reversed, reversed + 2, pos - 1); // Remove "*."
        pos -= 2;
    }

    // Insert each character
    for (size_t i = 0; i < pos; i++) {
        unsigned char c = reversed[i];

        if (node->children[c] == NULL) {
            node->children[c] = create_node();
        }

        node = node->children[c];
    }

    node->is_end = 1;
    node->wildcard = is_wildcard;

    pthread_mutex_unlock(&filter_mutex);
    LOGI("Added domain to filter: %s", domain);
}

// Load domains from a file
int filter_load_file(const char *filename) {
    FILE *file = fopen(filename, "r");
    if (file == NULL) {
        LOGE("Failed to open filter file: %s", filename);
        return -1;
    }

    char line[256];
    int count = 0;

    while (fgets(line, sizeof(line), file)) {
        // Remove trailing newline
        size_t len = strlen(line);
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }
        if (len > 0 && (line[len - 1] == '\n' || line[len - 1] == '\r')) {
            line[--len] = '\0';
        }

        // Skip comments and empty lines
        if (len == 0 || line[0] == '#') {
            continue;
        }

        // Skip IP addresses in hosts file format
        if (isdigit(line[0]) || line[0] == ':') {
            // Find the domain part
            char *domain = line;
            while (*domain && !isspace(*domain)) {
                domain++;
            }
            while (*domain && isspace(*domain)) {
                domain++;
            }
            if (*domain) {
                filter_add_domain(domain);
                count++;
            }
        } else {
            // Add domain directly
            filter_add_domain(line);
            count++;
        }
    }

    fclose(file);
    LOGI("Loaded %d domains from %s", count, filename);
    return count;
}

// Check if a domain matches the filter
// For checking example.com, the domain is checked in reverse: com.example
int filter_check_domain(const char *domain) {
    if (domain == NULL || *domain == '\0' || filter_trie == NULL) {
        return 0;
    }

    // Reverse domain for checking
    char reversed[256];
    size_t domain_len = strlen(domain);

    if (domain_len >= sizeof(reversed)) {
        LOGE("Domain too long for checking: %s", domain);
        return 0;
    }

    // Find domain parts and reverse them
    size_t pos = 0;
    const char *start = domain;
    const char *end = domain + domain_len;
    const char *current = end;

    // Handle trailing dot
    if (domain_len > 0 && domain[domain_len - 1] == '.') {
        current--;
    }

    while (current > start) {
        const char *part_end = current;

        // Find start of part (or end of previous part)
        while (current > start && *(current - 1) != '.') {
            current--;
        }

        // Copy the part
        for (const char *p = current; p < part_end; p++) {
            if (pos < sizeof(reversed) - 1) {
                reversed[pos++] = *p;
            }
        }

        // Add separator
        if (current > start && pos < sizeof(reversed) - 1) {
            reversed[pos++] = '.';
        }

        // Skip the dot
        if (current > start) {
            current--;
        }
    }

    // Null terminate
    reversed[pos] = '\0';

    pthread_mutex_lock(&filter_mutex);

    // Exact match check
    int blocked = 0;
    trie_node_t *node = filter_trie;

    for (size_t i = 0; i < pos && node != NULL; i++) {
        unsigned char c = reversed[i];

        // Check for exact match at this level
        if (node->is_end) {
            blocked = 1;
            break;
        }

        node = node->children[c];
    }

    // Check final node
    if (node != NULL && node->is_end) {
        blocked = 1;
    }

    // If not blocked, check for wildcard matches
    if (!blocked) {
        // For each level of the domain, check if there's a wildcard match
        // For example.com, check if *.example.com matches
        for (size_t i = 0; i < pos; i++) {
            // Skip to the next part
            while (i < pos && reversed[i] != '.') {
                i++;
            }
            if (i >= pos) {
                break;
            }

            // Check if wildcard matches from this part forward
            node = filter_trie;

            for (size_t j = i + 1; j < pos && node != NULL; j++) {
                unsigned char c = reversed[j];
                node = node->children[c];
            }

            if (node != NULL && node->is_end && node->wildcard) {
                blocked = 1;
                break;
            }
        }
    }

    pthread_mutex_unlock(&filter_mutex);
    return blocked;
}