#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <pbc/pbc.h>
#include <openssl/sha.h>
#include <sys/queue.h>

#define PORT 8080
#define MAX_DEVICES 1000
#define BUFFER_SIZE 4096
#define CURVE_TYPE "type a"

typedef struct {
    pairing_t pairing;
    element_t P, PK_tilde, V_E;
    element_t s_E; 
} SystemParameters;

typedef struct device_record {
    char ID[256];
    element_t di;    
    element_t vi;    
    element_t Yi;    
    element_t Vi;    
    TAILQ_ENTRY(device_record) entries;
} DeviceRecord;

TAILQ_HEAD(device_list, device_record);


SystemParameters sys_params;
struct device_list registered_devices;


size_t serialize_element(unsigned char *buf, element_t e) {
    int len = element_length_in_bytes(e);
    element_to_bytes(buf, e);
    return len;
}

void deserialize_element(unsigned char *buf, element_t e) {
    element_from_bytes(e, buf);
}

void hash_sha256(element_t out, pairing_t pairing, const unsigned char *data, size_t len) {
    unsigned char digest[SHA256_DIGEST_LENGTH];
    SHA256(data, len, digest);
    element_from_hash(out, digest, SHA256_DIGEST_LENGTH);
}


void initialize_crypto_system() {

    pbc_param_t param;
    pbc_param_init_set_str(param, CURVE_TYPE);
    pairing_init_pbc_param(sys_params.pairing, param);

  
    element_init_G1(sys_params.P, sys_params.pairing);
    element_random(sys_params.P);

    element_init_Zr(sys_params.s_E, sys_params.pairing);
    element_random(sys_params.s_E);

    element_init_G1(sys_params.PK_tilde, sys_params.pairing);
    element_mul_zn(sys_params.PK_tilde, sys_params.P, sys_params.s_E);

    TAILQ_INIT(&registered_devices);

    printf("[系统] 密码系统初始化完成\n");
}


DeviceRecord* generate_device_keys(const char *device_id) {
    DeviceRecord *record = malloc(sizeof(DeviceRecord));
    strncpy(record->ID, device_id, sizeof(record->ID));

    element_t yi, hi;
    element_init_Zr(yi, sys_params.pairing);
    element_init_Zr(hi, sys_params.pairing);
    element_random(yi);

    unsigned char hash_input[BUFFER_SIZE];
    int input_len = 0;


    element_init_G1(record->Yi, sys_params.pairing);
    element_mul_zn(record->Yi, sys_params.P, yi);
    input_len += serialize_element(hash_input + input_len, record->Yi);


    input_len += snprintf((char*)hash_input + input_len, 
                        BUFFER_SIZE - input_len, "%s", device_id);
    input_len += serialize_element(hash_input + input_len, sys_params.PK_tilde);

    hash_sha256(hi, sys_params.pairing, hash_input, input_len);

    element_init_Zr(record->di, sys_params.pairing);
    element_mul(record->di, hi, sys_params.s_E);
    element_add(record->di, record->di, yi);

    element_init_Zr(record->vi, sys_params.pairing);
    element_random(record->vi);
    element_init_G1(record->Vi, sys_params.pairing);
    element_mul_zn(record->Vi, sys_params.P, record->vi);

    element_clear(yi);
    element_clear(hi);

    printf("[注册] 设备 %s 密钥生成完成\n", device_id);
    return record;
}

void handle_registration(int client_fd) {
    char device_id[256];
    ssize_t len = read(client_fd, device_id, sizeof(device_id)-1);
    device_id[len] = '\0';

    DeviceRecord *existing;
    TAILQ_FOREACH(existing, &registered_devices, entries) {
        if (strcmp(existing->ID, device_id) == 0) {
            printf("[警告] 设备 %s 已注册\n", device_id);
            const char *resp = "EXISTS";
            write(client_fd, resp, strlen(resp));
            return;
        }
    }

    DeviceRecord *new_dev = generate_device_keys(device_id);
    TAILQ_INSERT_TAIL(&registered_devices, new_dev, entries);

    unsigned char response[BUFFER_SIZE];
    size_t offset = serialize_element(response, new_dev->di);
    offset += serialize_element(response + offset, new_dev->vi);
    offset += serialize_element(response + offset, new_dev->Yi);
    offset += serialize_element(response + offset, new_dev->Vi);

    write(client_fd, response, offset);
    printf("[注册] 设备 %s 注册成功\n", device_id);
}

int verify_aggregate_signature(element_t tau_sum, element_t *Ti_list, 
                              char **device_ids, int num_devices) {
    element_t sum, temp;
    element_init_G1(sum, sys_params.pairing);
    element_set0(sum);

    for (int i = 0; i < num_devices; i++) {
        DeviceRecord *dev = NULL;
        TAILQ_FOREACH(dev, &registered_devices, entries) {
            if (strcmp(dev->ID, device_ids[i]) == 0) break;
        }
        if (!dev) {
            printf("[验证] 未知设备: %s\n", device_ids[i]);
            return 0;
        }

        unsigned char hi_input[BUFFER_SIZE];
        int hi_len = serialize_element(hi_input, dev->Yi);
        hi_len += snprintf((char*)hi_input + hi_len, 
                         BUFFER_SIZE - hi_len, "%s", dev->ID);
        hi_len += serialize_element(hi_input + hi_len, sys_params.PK_tilde);

        element_t hi;
        element_init_Zr(hi, sys_params.pairing);
        hash_sha256(hi, sys_params.pairing, hi_input, hi_len);

        unsigned char ki_input[BUFFER_SIZE];
        int ki_len = serialize_element(ki_input, Ti_list[i]);
        ki_len += snprintf((char*)ki_input + ki_len, 
                         BUFFER_SIZE - ki_len, "%s", dev->ID);
        ki_len += serialize_element(ki_input + ki_len, dev->Vi);
        ki_len += serialize_element(ki_input + ki_len, sys_params.PK_tilde);

        element_t ki;
        element_init_Zr(ki, sys_params.pairing);
        hash_sha256(ki, sys_params.pairing, ki_input, ki_len);


        element_t ci_part1, ci_part2, ci;
        element_init_G1(ci_part1, sys_params.pairing);
        element_init_G1(ci_part2, sys_params.pairing);
        element_init_G1(ci, sys_params.pairing);


        element_mul_zn(ci_part1, dev->Vi, ki);

        element_mul_zn(ci_part2, sys_params.PK_tilde, hi);
        element_add(ci_part2, ci_part2, dev->Yi);
        element_add(ci_part1, ci_part1, ci_part2);
        element_add(ci, Ti_list[i], ci_part1);

        element_add(sum, sum, ci);

        element_clear(hi);
        element_clear(ki);
        element_clear(ci_part1);
        element_clear(ci_part2);
        element_clear(ci);
    }

    element_t tauP;
    element_init_G1(tauP, sys_params.pairing);
    element_mul_zn(tauP, sys_params.P, tau_sum);

    int result = element_cmp(tauP, sum);
    element_clear(tauP);
    element_clear(sum);

    return (result == 0);
}

void handle_verification(int client_fd) {
    unsigned char buffer[BUFFER_SIZE];
    ssize_t len = read(client_fd, buffer, BUFFER_SIZE);

    size_t offset = 0;
    element_t tau_sum;
    element_init_Zr(tau_sum, sys_params.pairing);
    deserialize_element(buffer + offset, tau_sum);
    offset += element_length_in_bytes(tau_sum);

    int num_devices = *(int*)(buffer + offset);
    offset += sizeof(int);

    char *device_ids[num_devices];
    element_t Ti_list[num_devices];

    for (int i = 0; i < num_devices; i++) {
        device_ids[i] = (char*)(buffer + offset);
        offset += strlen(device_ids[i]) + 1;

        element_init_G1(Ti_list[i], sys_params.pairing);
        deserialize_element(buffer + offset, Ti_list[i]);
        offset += element_length_in_bytes(Ti_list[i]);
    }

    int result = verify_aggregate_signature(tau_sum, Ti_list, device_ids, num_devices);
    write(client_fd, &result, sizeof(int));

    printf("[验证] 聚合签名验证结果: %s\n", result ? "有效" : "无效");
}

void run_server() {
    int server_fd, client_fd;
    struct sockaddr_in addr;
    socklen_t addr_len = sizeof(addr);

    if ((server_fd = socket(AF_INET, SOCK_STREAM, 0)) < 0) {
        perror("socket创建失败");
        exit(EXIT_FAILURE);
    }

    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(PORT);

    if (bind(server_fd, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("绑定端口失败");
        exit(EXIT_FAILURE);
    }

    if (listen(server_fd, 5) < 0) {
        perror("监听失败");
        exit(EXIT_FAILURE);
    }

    printf("[网络] 服务器已启动，监听端口 %d\n", PORT);

    while (1) {
        if ((client_fd = accept(server_fd, (struct sockaddr*)&addr, &addr_len)) < 0) {
            perror("接受连接失败");
            continue;
        }

        char req_type;
        read(client_fd, &req_type, 1);

        switch (req_type) {
            case 'R': 
                handle_registration(client_fd);
                break;
            case 'V': 
                handle_verification(client_fd);
                break;
            default:
                printf("[错误] 未知请求类型: %c\n", req_type);
        }

        close(client_fd);
    }
}

int main() {
    initialize_crypto_system();
    run_server();
    return 0;
}