#include <ucp/api/ucp.h>
#include <stdio.h>
#include <string.h>
#include <arpa/inet.h>
#include <unistd.h>

#define PORT 13337
#define BUFFER_SIZE 1024

typedef struct {
    ucp_worker_h worker;
    ucp_ep_h ep;
} connection_context_t;

void recv_callback(void *request, ucs_status_t status,
                                            const ucp_tag_recv_info_t *tag_info,
                                            void *user_data){
    if (status != UCS_OK) {
        fprintf(stderr, "Receive request failed: %s\n", ucs_status_string(status));
    } else {
        printf("Message received: %s\n", (char *)user_data);
    }
}

void server_accept_callback(ucp_ep_h ep, void *arg) {
    printf("Connection accepted\n");

    connection_context_t *conn_ctx = (connection_context_t *)arg;
    conn_ctx->ep = ep;

    char buffer[BUFFER_SIZE] = {0};
    ucp_request_param_t param = {
        .op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA,
        .cb.recv = recv_callback,
        .user_data = buffer
    };

    void *request = ucp_tag_recv_nbx(conn_ctx->worker, buffer, sizeof(buffer), 0, 0, &param);
    if (UCS_PTR_IS_ERR(request)) {
        fprintf(stderr, "Failed to post receive request: %s\n", ucs_status_string(UCS_PTR_STATUS(request)));
    } else if (request != NULL) {
        ucp_request_free(request);
    }
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

    ucp_listener_h listener;
    ucp_listener_params_t listener_params;
    listener_params.field_mask = UCP_LISTENER_PARAM_FIELD_SOCK_ADDR | UCP_LISTENER_PARAM_FIELD_ACCEPT_HANDLER;
    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(listen_addr));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listen_addr.sin_port = htons(PORT);
    listener_params.sockaddr.addr = (const struct sockaddr *)&listen_addr;
    listener_params.sockaddr.addrlen = sizeof(listen_addr);
    listener_params.accept_handler.cb = server_accept_callback;
    connection_context_t conn_ctx = {.worker = worker};
    listener_params.accept_handler.arg = &conn_ctx;

    status = ucp_listener_create(worker, &listener_params, &listener);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to create UCX listener: %s\n", ucs_status_string(status));
        ucp_worker_destroy(worker);
        ucp_cleanup(ucp_context);
        return -1;
    }

    printf("Server is listening on port %d\n", PORT);

    // Accept connections and receive messages
    while (1) {
        ucp_worker_progress(worker);
        usleep(1000);  // To prevent busy-wait loop
    }

    ucp_listener_destroy(listener);
    ucp_worker_destroy(worker);
    ucp_cleanup(ucp_context);

    return 0;
}
