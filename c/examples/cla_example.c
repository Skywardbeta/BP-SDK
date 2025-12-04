#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include "bp_sdk.h"

typedef struct {
    int socket;
    struct sockaddr_in local_addr;
    struct sockaddr_in remote_addr;
} udp_cla_context_t;

int udp_send_callback(const void *data, size_t len, const char *dest, void *context) {
    udp_cla_context_t *ctx = (udp_cla_context_t*)context;
    
    char addr_str[64];
    uint16_t port;
    if (sscanf(dest, "%63[^:]:%hu", addr_str, &port) != 2) {
        printf("Invalid destination address format: %s\n", dest);
        return -1;
    }
    
    struct sockaddr_in dest_addr;
    dest_addr.sin_family = AF_INET;
    dest_addr.sin_port = htons(port);
    inet_pton(AF_INET, addr_str, &dest_addr.sin_addr);
    
    ssize_t sent = sendto(ctx->socket, data, len, 0, 
                         (struct sockaddr*)&dest_addr, sizeof(dest_addr));
    
    if (sent != (ssize_t)len) {
        perror("sendto failed");
        return -1;
    }
    
    printf("UDP CLA sent %zu bytes to %s\n", len, dest);
    return 0;
}

int udp_receive_callback(void *data, size_t len, char *source, void *context) {
    udp_cla_context_t *ctx = (udp_cla_context_t*)context;
    
    struct sockaddr_in src_addr;
    socklen_t addr_len = sizeof(src_addr);
    
    ssize_t received = recvfrom(ctx->socket, data, len, 0, 
                               (struct sockaddr*)&src_addr, &addr_len);
    
    if (received < 0) {
        perror("recvfrom failed");
        return -1;
    }
    
    inet_ntop(AF_INET, &src_addr.sin_addr, source, INET_ADDRSTRLEN);
    sprintf(source + strlen(source), ":%u", ntohs(src_addr.sin_port));
    
    printf("UDP CLA received %zd bytes from %s\n", received, source);
    return received;
}

int main(int argc, char *argv[]) {
    if (argc != 3) {
        printf("Usage: %s <local_addr> <local_port>\n", argv[0]);
        printf("Example: %s 127.0.0.1 4556\n", argv[0]);
        return 1;
    }

    const char *local_addr = argv[1];
    uint16_t local_port = (uint16_t)atoi(argv[2]);

    printf("Initializing BP-SDK...\n");
    int result = bp_init("ipn:1.1", NULL);
    if (result != BP_SUCCESS) {
        printf("Failed to initialize BP-SDK: %s\n", bp_strerror(result));
        return 1;
    }

    udp_cla_context_t context;
    context.socket = socket(AF_INET, SOCK_DGRAM, 0);
    if (context.socket < 0) {
        perror("socket creation failed");
        bp_shutdown();
        return 1;
    }

    context.local_addr.sin_family = AF_INET;
    context.local_addr.sin_port = htons(local_port);
    inet_pton(AF_INET, local_addr, &context.local_addr.sin_addr);

    if (bind(context.socket, (struct sockaddr*)&context.local_addr, 
             sizeof(context.local_addr)) < 0) {
        perror("bind failed");
        close(context.socket);
        bp_shutdown();
        return 1;
    }

    bp_cla_t *cla;
    result = bp_cla_create_udp(local_addr, local_port, &cla);
    if (result != BP_SUCCESS) {
        printf("Failed to create UDP CLA: %s\n", bp_strerror(result));
        close(context.socket);
        bp_shutdown();
        return 1;
    }

    cla->context = &context;
    cla->send_callback = udp_send_callback;
    cla->receive_callback = udp_receive_callback;

    result = bp_cla_register(cla);
    if (result != BP_SUCCESS) {
        printf("Failed to register CLA: %s\n", bp_strerror(result));
        bp_cla_destroy(cla);
        close(context.socket);
        bp_shutdown();
        return 1;
    }

    printf("UDP CLA listening on %s:%u\n", local_addr, local_port);
    printf("Press Ctrl+C to stop.\n");

    char buffer[1024];
    char source[64];
    
    while (1) {
        int bytes_received = udp_receive_callback(buffer, sizeof(buffer), source, &context);
        if (bytes_received > 0) {
            printf("Received data from %s: ", source);
            fwrite(buffer, 1, bytes_received, stdout);
            printf("\n");
        }
        
        usleep(100000);
    }

    printf("\nShutting down...\n");
    bp_cla_unregister("udp");
    bp_cla_destroy(cla);
    close(context.socket);
    bp_shutdown();

    return 0;
} 