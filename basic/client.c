#include <ucp/api/ucp.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>

#define SERVER_IP "127.0.0.1"  // 修改为服务器的实际IP地址
#define PORT 13337
#define BUFFER_SIZE 1024

void send_callback(void *request, ucs_status_t status, void *user_data){
    if (status != UCS_OK) {
        fprintf(stderr, "Send request failed: %s\n", ucs_status_string(status));
    } else {
        printf("Message sent successfully\n");
    }
}

void request_init(void *request) {
    ucp_request_param_t *param = (ucp_request_param_t*)request;
    param->op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA;
    param->cb.send = send_callback;
    param->user_data = NULL;
}

int main() {
    ucp_context_h ucp_context;
    ucp_params_t ucp_params;
    ucp_config_t *config;
    ucs_status_t status;
    
    // Initialize UCX context
    ucp_params.field_mask = UCP_PARAM_FIELD_FEATURES;
    ucp_params.features = UCP_FEATURE_TAG;

    status = ucp_config_read(NULL, NULL, &config);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to read UCX config: %s\n", ucs_status_string(status));
        return -1;
    }

    status = ucp_init(&ucp_params, config, &ucp_context);
    ucp_config_release(config);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to initialize UCX: %s\n", ucs_status_string(status));
        return -1;
    }

    ucp_worker_h worker;
    ucp_worker_params_t worker_params = {};
    worker_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;
    
    status = ucp_worker_create(ucp_context, &worker_params, &worker);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to create UCX worker: %s\n", ucs_status_string(status));
        ucp_cleanup(ucp_context);
        return -1;
    }

    ucp_ep_h ep;
    ucp_ep_params_t ep_params;
    ep_params.field_mask = UCP_EP_PARAM_FIELD_FLAGS | UCP_EP_PARAM_FIELD_SOCK_ADDR;
    ep_params.flags = UCP_EP_PARAMS_FLAGS_CLIENT_SERVER;
    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);
    ep_params.sockaddr.addr = (const struct sockaddr*)&server_addr;
    ep_params.sockaddr.addrlen = sizeof(server_addr);

    status = ucp_ep_create(worker, &ep_params, &ep);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to create UCX endpoint: %s\n", ucs_status_string(status));
        ucp_worker_destroy(worker);
        ucp_cleanup(ucp_context);
        return -1;
    }

    char buffer[BUFFER_SIZE] = "Hello, UCX!";
    ucp_request_param_t param;
    request_init(&param);

    void *request = ucp_tag_send_nbx(ep, buffer, strlen(buffer) + 1, 0, &param);
    if (UCS_PTR_IS_ERR(request)) {
        fprintf(stderr, "Failed to send message: %s\n", ucs_status_string(UCS_PTR_STATUS(request)));
        ucp_ep_destroy(ep);
        ucp_worker_destroy(worker);
        ucp_cleanup(ucp_context);
        return -1;
    } else if (request != NULL) {
        ucp_request_free(request);
    }

    printf("Message sent: %s\n", buffer);

    ucp_ep_destroy(ep);
    ucp_worker_destroy(worker);
    ucp_cleanup(ucp_context);

    return 0;
}
