#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/queue.h>
#include <netinet/in.h>
#include <pbc/pbc.h>
#include <openssl/sha.h>
#include <openssl/ssl.h>
#include <openssl/err.h>
#include <time.h>

#define MAX_SENSORS 100
#define BUFFER_SIZE 4096
#define SERVER_PORT 8082
#define SENSOR_PORT 8081
#define SENSOR_TIMEOUT 5

struct sensor_data {
    element_t T_i;
    element_t tau_i;
    char ID[256];
    element_t PK_Y;
    element_t PK_V;
    time_t timestamp;
    TAILQ_ENTRY(sensor_data) entries;
};

TAILQ_HEAD(data_head, sensor_data);

struct {
    pairing_t pairing;
    element_t PK_tilde;
    element_t V_E;
    struct data_head data_list;
    SSL_CTX *ssl_ctx;
} cluster_ctx;

void init_crypto() {
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(SERVER_PORT), .sin_addr.s_addr=inet_addr("127.0.0.1")};
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    
    unsigned char buf[BUFFER_SIZE];
    read(sock, buf, BUFFER_SIZE);
    
    pbc_param_t param;
    size_t offset = pbc_param_init_set_buf(param, (char*)buf, BUFFER_SIZE);
    pairing_init_pbc_param(cluster_ctx.pairing, param);
    
    element_init_G1(cluster_ctx.PK_tilde, cluster_ctx.pairing);
    element_from_bytes(cluster_ctx.PK_tilde, buf + offset);
    offset += element_length_in_bytes(cluster_ctx.PK_tilde);
    
    element_init_G1(cluster_ctx.V_E, cluster_ctx.pairing);
    element_from_bytes(cluster_ctx.V_E, buf + offset);
    
    close(sock);
}

SSL_CTX* create_ssl_ctx() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_server_method());
    SSL_CTX_use_certificate_chain_file(ctx, "cluster.pem");
    SSL_CTX_use_PrivateKey_file(ctx, "cluster.key", SSL_FILETYPE_PEM);
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, NULL);
    SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    return ctx;
}

int deserialize_data(struct sensor_data *data, unsigned char *buf) {
    size_t offset = 0;
    
    element_init_G1(data->T_i, cluster_ctx.pairing);
    element_from_bytes(data->T_i, buf + offset);
    offset += element_length_in_bytes(data->T_i);
    
    element_init_Zr(data->tau_i, cluster_ctx.pairing);
    element_from_bytes(data->tau_i, buf + offset);
    offset += element_length_in_bytes(data->tau_i);
    
    strncpy(data->ID, (char*)buf + offset, 255);
    offset += strlen((char*)buf + offset) + 1;
    
    element_init_G1(data->PK_Y, cluster_ctx.pairing);
    element_from_bytes(data->PK_Y, buf + offset);
    offset += element_length_in_bytes(data->PK_Y);
    
    element_init_G1(data->PK_V, cluster_ctx.pairing);
    element_from_bytes(data->PK_V, buf + offset);
    offset += element_length_in_bytes(data->PK_V);
    
    memcpy(&data->timestamp, buf + offset, sizeof(time_t));
    offset += sizeof(time_t);
    
    return (offset <= BUFFER_SIZE) ? 0 : -1;
}

void aggregate_signature(element_t *tau_sum, unsigned char *c_hash) {
    element_set0(*tau_sum);
    unsigned char hash_buf[BUFFER_SIZE];
    size_t hash_len = 0;
    
    struct sensor_data *item;
    TAILQ_FOREACH(item, &cluster_ctx.data_list, entries) {
        element_add(*tau_sum, *tau_sum, item->tau_i);
        
        element_t temp;
        element_init_G1(temp, cluster_ctx.pairing);
        element_mul_zn(temp, cluster_ctx.V_E, item->tau_i);
        hash_len += element_to_bytes(hash_buf + hash_len, temp);
        element_clear(temp);
    }
    
    SHA256(hash_buf, hash_len, c_hash);
}

void send_aggregate(element_t tau_sum, unsigned char *c_hash) {
    SSL *ssl = SSL_new(cluster_ctx.ssl_ctx);
    int sock = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_port=htons(SERVER_PORT), .sin_addr.s_addr=inet_addr("127.0.0.1")};
    connect(sock, (struct sockaddr*)&addr, sizeof(addr));
    SSL_set_fd(ssl, sock);
    SSL_connect(ssl);
    
    unsigned char buf[BUFFER_SIZE];
    size_t offset = element_to_bytes(buf, tau_sum);
    
    struct sensor_data *item;
    TAILQ_FOREACH(item, &cluster_ctx.data_list, entries) {
        offset += element_to_bytes(buf + offset, item->T_i);
    }
    
    TAILQ_FOREACH(item, &cluster_ctx.data_list, entries) {
        strncpy((char*)buf + offset, item->ID, BUFFER_SIZE - offset);
        offset += strlen(item->ID) + 1;
    }
    
    memcpy(buf + offset, c_hash, SHA256_DIGEST_LENGTH);
    offset += SHA256_DIGEST_LENGTH;
    
    SSL_write(ssl, buf, offset);
    SSL_shutdown(ssl);
    close(sock);
}

void handle_connection(SSL *ssl) {
    unsigned char buf[BUFFER_SIZE];
    int len = SSL_read(ssl, buf, BUFFER_SIZE);
    
    struct sensor_data *data = malloc(sizeof(struct sensor_data));
    if(deserialize_data(data, buf) == 0 && labs(time(NULL)-data->timestamp) <= SENSOR_TIMEOUT) {
        TAILQ_INSERT_TAIL(&cluster_ctx.data_list, data, entries);
    } else {
        free(data);
    }
}

void main_loop() {
    int server_fd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {.sin_family=AF_INET, .sin_addr.s_addr=INADDR_ANY, .sin_port=htons(SENSOR_PORT)};
    bind(server_fd, (struct sockaddr*)&addr, sizeof(addr));
    listen(server_fd, 5);
    
    time_t last_agg = 0;
    while(1) {
        struct sockaddr_in client_addr;
        socklen_t addr_len = sizeof(client_addr);
        int client_fd = accept(server_fd, (struct sockaddr*)&client_addr, &addr_len);
        
        SSL *ssl = SSL_new(cluster_ctx.ssl_ctx);
        SSL_set_fd(ssl, client_fd);
        if(SSL_accept(ssl) > 0) handle_connection(ssl);
        close(client_fd);
        
        if(time(NULL)-last_agg >= 30) {
            element_t tau_sum;
            unsigned char c_hash[SHA256_DIGEST_LENGTH];
            
            element_init_Zr(tau_sum, cluster_ctx.pairing);
            aggregate_signature(&tau_sum, c_hash);
            send_aggregate(tau_sum, c_hash);
            element_clear(tau_sum);
            
            while(!TAILQ_EMPTY(&cluster_ctx.data_list)) {
                struct sensor_data *data = TAILQ_FIRST(&cluster_ctx.data_list);
                TAILQ_REMOVE(&cluster_ctx.data_list, data, entries);
                element_clear(data->T_i);
                element_clear(data->tau_i);
                element_clear(data->PK_Y);
                element_clear(data->PK_V);
                free(data);
            }
            last_agg = time(NULL);
        }
    }
}

int main() {
    TAILQ_INIT(&cluster_ctx.data_list);
    init_crypto();
    cluster_ctx.ssl_ctx = create_ssl_ctx();
    main_loop();
    return 0;
}