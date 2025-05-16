#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pbc/pbc.h>
#include <openssl/sha.h>
#include <sys/mman.h>
#include <openssl/ssl.h>
#define SERVER_IP "192.168.1.100"
#define SERVER_PORT 8080
#define CLUSTER_PORT 8081
#define BUFFER_SIZE 4096

typedef struct {
    element_t P;          
    element_t PK_tilde;   
    element_t V_E;        
    
    
    char ID[256];        
    element_t di;         
    element_t vi;         
    element_t Yi;         
    element_t Vi;         
    
    pairing_t pairing;    
} SensorContext;

SSL_CTX *create_ssl_context() {
    SSL_CTX *ctx = SSL_CTX_new(TLS_client_method());
    SSL_CTX_set_verify(ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_load_verify_locations(ctx, "ca.crt", NULL);
    return ctx;
}


SSL* secure_connect(const char *host, int port) {
    int sockfd = socket(AF_INET, SOCK_STREAM, 0);
    struct sockaddr_in addr = {
        .sin_family = AF_INET,
        .sin_port = htons(port),
        .sin_addr.s_addr = inet_addr(host)
    };
    
    if (connect(sockfd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("连接失败");
        exit(EXIT_FAILURE);
    }

    SSL *ssl = SSL_new(create_ssl_context());
    SSL_set_fd(ssl, sockfd);
    if (SSL_connect(ssl) != 1) {
        ERR_print_errors_fp(stderr);
        exit(EXIT_FAILURE);
    }
    return ssl;
}

void deserialize_system_params(SensorContext *ctx, unsigned char *data) {
    size_t offset = 0;
    
    pbc_param_t param;
    pbc_param_init_set_buf(param, (char*)data + offset, BUFFER_SIZE);
    offset += strlen((char*)data + offset) + 1;
    
    pairing_init_pbc_param(ctx->pairing, param);
    
    element_init_G1(ctx->P, ctx->pairing);
    element_from_bytes(ctx->P, data + offset);
    offset += element_length_in_bytes(ctx->P);
    
    element_init_G1(ctx->PK_tilde, ctx->pairing);
    element_from_bytes(ctx->PK_tilde, data + offset);
    offset += element_length_in_bytes(ctx->PK_tilde);
    
    element_init_G1(ctx->V_E, ctx->pairing);
    element_from_bytes(ctx->V_E, data + offset);
}


void register_device(SensorContext *ctx) {
    SSL *ssl = secure_connect(SERVER_IP, SERVER_PORT);

    unsigned char req[256];
    snprintf((char*)req, sizeof(req), "R%s", ctx->ID);
    SSL_write(ssl, req, strlen((char*)req)+1);

    unsigned char response[BUFFER_SIZE];
    int total_len = SSL_read(ssl, response, BUFFER_SIZE);
    

    deserialize_system_params(ctx, response);
    
    size_t offset = strlen((char*)response) + 1;
    
    element_init_Zr(ctx->di, ctx->pairing);
    element_from_bytes(ctx->di, response + offset);
    offset += element_length_in_bytes(ctx->di);
    
    element_init_Zr(ctx->vi, ctx->pairing);
    element_from_bytes(ctx->vi, response + offset);
    offset += element_length_in_bytes(ctx->vi);
    
    element_init_G1(ctx->Yi, ctx->pairing);
    element_from_bytes(ctx->Yi, response + offset);
    offset += element_length_in_bytes(ctx->Yi);
    
    element_init_G1(ctx->Vi, ctx->pairing);
    element_from_bytes(ctx->Vi, response + offset);
    

    mlock(ctx, sizeof(SensorContext));
    mlock(ctx->di, element_length_in_bytes(ctx->di));
    mlock(ctx->vi, element_length_in_bytes(ctx->vi));
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
}


void compute_hash(element_t out, pairing_t pairing, 
                 const unsigned char *data[], size_t lens[], int count) {
    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx);
    
    for (int i = 0; i < count; i++) {
        SHA256_Update(&sha_ctx, data[i], lens[i]);
    }
    
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256_Final(digest, &sha_ctx);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
}


void generate_full_signature(SensorContext *ctx, 
                            const unsigned char *msg, size_t msg_len,
                            element_t *T_out, element_t *tau_out) {

    element_t ti;
    element_init_Zr(ti, ctx->pairing);
    element_random(ti);
    
    element_init_G1(*T_out, ctx->pairing);
    element_mul_zn(*T_out, ctx->P, ti);

    const unsigned *hash_components[] = {
        (unsigned char*)*T_out,
        (unsigned char*)ctx->ID,
        (unsigned char*)ctx->Vi,
        (unsigned char*)ctx->PK_tilde
    };
    size_t hash_lens[] = {
        element_length_in_bytes(*T_out),
        strlen(ctx->ID),
        element_length_in_bytes(ctx->Vi),
        element_length_in_bytes(ctx->PK_tilde)
    };
    
    element_t ki;
    compute_hash(ki, ctx->pairing, hash_components, hash_lens, 4);

    const unsigned *msg_components[] = {
        msg,
        (unsigned char*)*T_out,
        (unsigned char*)ctx->ID,
        (unsigned char*)ctx->Vi,
        (unsigned char*)ctx->PK_tilde
    };
    size_t msg_lens[] = {
        msg_len,
        element_length_in_bytes(*T_out),
        strlen(ctx->ID),
        element_length_in_bytes(ctx->Vi),
        element_length_in_bytes(ctx->PK_tilde)
    };
    
    element_t li;
    compute_hash(li, ctx->pairing, msg_components, msg_lens, 5);

    element_t temp1, temp2;
    element_init_Zr(temp1, ctx->pairing);
    element_init_Zr(temp2, ctx->pairing);
    
    element_mul(temp1, ki, ctx->vi);
    
    element_add(temp1, temp1, ctx->di);
    
    element_mul(temp2, temp1, li);

    element_init_Zr(*tau_out, ctx->pairing);
    element_add(*tau_out, ti, temp2);


    element_clear(ti);
    element_clear(ki);
    element_clear(li);
    element_clear(temp1);
    element_clear(temp2);
}

void send_signature(SSL *ssl, element_t T, element_t tau) {
    unsigned char buffer[BUFFER_SIZE];
    size_t offset = 0;
    
    offset += element_to_bytes(buffer + offset, T);
    offset += element_to_bytes(buffer + offset, tau);
    
    time_t timestamp = time(NULL);
    memcpy(buffer + offset, &timestamp, sizeof(timestamp));
    offset += sizeof(timestamp);

    SSL_write(ssl, buffer, offset);
}

void sensor_operation_loop(SensorContext *ctx) {
    SSL *ssl = secure_connect(SERVER_IP, CLUSTER_PORT);
    
    while(1) {
        unsigned char medical_data[] = "默认数据";
        size_t data_len = sizeof(medical_data);
        
        element_t Ti, taui;
        generate_full_signature(ctx, medical_data, data_len, &Ti, &taui);
        
        // 发送签名
        send_signature(ssl, Ti, taui);
        printf("[%s] 数据已签名发送\n", ctx->ID);
        
        sleep(5); 
    }
    
    SSL_shutdown(ssl);
    SSL_free(ssl);
}

int main(int argc, char *argv[]) {
    if (argc != 2) {
        fprintf(stderr, "使用方法: %s <设备ID>\n", argv[0]);
        exit(EXIT_FAILURE);
    }

    SensorContext ctx;
    memset(&ctx, 0, sizeof(ctx));
    strncpy(ctx.ID, argv[1], sizeof(ctx.ID)-1);
    

    register_device(&ctx);

    sensor_operation_loop(&ctx);

    explicit_bzero(&ctx, sizeof(ctx));
    return 0;
}