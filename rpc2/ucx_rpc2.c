#include "ucx_rpc.h"
#include <ucp/api/ucp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>

static ucp_context_h ucp_context;
static ucp_worker_h ucp_worker;
static ucp_listener_h listener;
static ucp_ep_h server_ep;
static ucp_ep_h client_ep;
static int server_running = 1;

void get_data(const request_t *req, response_t *resp) {
    snprintf(resp->message, sizeof(resp->message), "world");
}

void init_ucx() {
    ucp_params_t ucp_params;
    ucp_config_t *config;
    ucs_status_t status;

    status = ucp_config_read(NULL, NULL, &config);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to read UCX config\n");
        exit(1);
    }

    memset(&ucp_params, 0, sizeof(ucp_params));
    ucp_params.field_mask = UCP_PARAM_FIELD_FEATURES;
    ucp_params.features = UCP_FEATURE_TAG;

    status = ucp_init(&ucp_params, config, &ucp_context);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to initialize UCX\n");
        exit(1);
    }

    ucp_config_release(config);
}

void cleanup_ucx() {
    ucp_cleanup(ucp_context);
}

static void request_completed(void *request, ucs_status_t status, void *user_data) {
    if (status != UCS_OK) {
        fprintf(stderr, "Request failed\n");
    } else {
        printf("send data ok\n");
    }
    ucp_request_free(request);
}

static void recv_handler(void *request, ucs_status_t status,
                         const ucp_tag_recv_info_t *info, void *user_data)
{
    if (status != UCS_OK) {
        fprintf(stderr, "Receive request failed\n");
    } else {
        request_t *req = (request_t *)user_data;
        response_t resp;
        printf("server received data: %s\n", req->message);
        get_data(req, &resp);

        ucp_request_param_t send_param;
        memset(&send_param, 0, sizeof(send_param));
        send_param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA;
        send_param.cb.send = request_completed;
        send_param.user_data = NULL;

        void *send_request = ucp_tag_send_nbx(server_ep, &resp, sizeof(resp), 0, &send_param);
        if (UCS_PTR_IS_ERR(send_request)) {
            fprintf(stderr, "Failed to send response\n");
        } else {
            printf("Server sent response\n");
            ucp_request_free(send_request);
        }
    }
    ucp_request_free(request);
}

static void client_recv_handler(void *request, ucs_status_t status,
                         const ucp_tag_recv_info_t *info, void *user_data)
{
    if (status != UCS_OK) {
        fprintf(stderr, "Receive request failed\n");
    } else {
        request_t *req = (request_t *)user_data;
        printf("client received data: %s\n", req->message);
    }
    ucp_request_free(request);
}


static void server_connection_handler(ucp_conn_request_h conn_request, void *arg) {
    ucp_ep_params_t ep_params;
    ucs_status_t status;

    memset(&ep_params, 0, sizeof(ep_params));
    ep_params.field_mask = UCP_EP_PARAM_FIELD_CONN_REQUEST;
    ep_params.conn_request = conn_request;

    status = ucp_ep_create(ucp_worker, &ep_params, &server_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to create UCX endpoint\n");
        exit(1);
    } else {
        puts("create connection for client");
    }

    request_t *request = (request_t *)malloc(sizeof(request_t));

    ucp_request_param_t recv_param;
    memset(&recv_param, 0, sizeof(recv_param));
    recv_param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA;
    recv_param.cb.recv = recv_handler;
    recv_param.user_data = request;
    puts("start receiving message");

    void *recv_request = ucp_tag_recv_nbx(ucp_worker, request, sizeof(*request), 0, 0, &recv_param);
    if (UCS_PTR_IS_ERR(recv_request)) {
        fprintf(stderr, "Failed to receive request\n");
        free(request);
    } else {
        puts("server receive success");
    }
}

void start_server() {
    ucp_worker_params_t worker_params;
    memset(&worker_params, 0, sizeof(worker_params));
    worker_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;

    ucs_status_t status = ucp_worker_create(ucp_context, &worker_params, &ucp_worker);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to create UCX worker\n");
        exit(1);
    }

    ucp_listener_params_t listener_params;
    memset(&listener_params, 0, sizeof(listener_params));
    listener_params.field_mask = UCP_LISTENER_PARAM_FIELD_SOCK_ADDR |
                                 UCP_LISTENER_PARAM_FIELD_CONN_HANDLER;
    struct sockaddr_in listen_addr;
    memset(&listen_addr, 0, sizeof(struct sockaddr_in));
    listen_addr.sin_family = AF_INET;
    listen_addr.sin_port = htons(12345);
    listen_addr.sin_addr.s_addr = INADDR_ANY;
    listener_params.sockaddr.addr = (const struct sockaddr *)&listen_addr;
    listener_params.sockaddr.addrlen = sizeof(listen_addr);
    listener_params.conn_handler.cb = server_connection_handler;
    listener_params.conn_handler.arg = NULL;

    status = ucp_listener_create(ucp_worker, &listener_params, &listener);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to create UCX listener\n");
        exit(1);
    }

    printf("Server listening on port 12345...\n");
    while (server_running) {
        ucp_worker_progress(ucp_worker);
    }

    ucp_listener_destroy(listener);
    ucp_worker_destroy(ucp_worker);
}

void send_request() {
    ucp_worker_params_t worker_params;
    memset(&worker_params, 0, sizeof(worker_params));
    worker_params.field_mask = UCP_WORKER_PARAM_FIELD_THREAD_MODE;
    worker_params.thread_mode = UCS_THREAD_MODE_SINGLE;

    ucs_status_t status = ucp_worker_create(ucp_context, &worker_params, &ucp_worker);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to create UCX worker\n");
        exit(1);
    }

    ucp_ep_params_t ep_params;
    memset(&ep_params, 0, sizeof(ep_params));
    ep_params.field_mask = UCP_EP_PARAM_FIELD_FLAGS |
                           UCP_EP_PARAM_FIELD_SOCK_ADDR;
    ep_params.flags = UCP_EP_PARAMS_FLAGS_CLIENT_SERVER;

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(struct sockaddr_in));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(12345);
    inet_pton(AF_INET, "127.0.0.1", &server_addr.sin_addr);
    ep_params.sockaddr.addr = (const struct sockaddr *)&server_addr;
    ep_params.sockaddr.addrlen = sizeof(server_addr);

    status = ucp_ep_create(ucp_worker, &ep_params, &client_ep);
    if (status != UCS_OK) {
        fprintf(stderr, "Failed to create UCX endpoint\n");
        exit(1);
    } else {
        printf("create connection\n");
    }

    request_t req;
    response_t resp;
    strcpy(req.message, "hello");

    ucp_request_param_t send_param;
    memset(&send_param, 0, sizeof(send_param));
    send_param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA;
    send_param.cb.send = request_completed;
    send_param.user_data = NULL;

    void *send_request = ucp_tag_send_nbx(client_ep, &req, sizeof(req), 0, &send_param);
    if (UCS_PTR_IS_ERR(send_request)) {
        fprintf(stderr, "Failed to send request\n");
    } else {
        puts("send success");
        ucp_request_free(send_request);
    }

    ucp_request_param_t recv_param;
    memset(&recv_param, 0, sizeof(recv_param));
    recv_param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA;
    recv_param.cb.recv = client_recv_handler;
    recv_param.user_data = &resp;

    void *recv_request = ucp_tag_recv_nbx(ucp_worker, &resp, sizeof(resp), 0, 0, &recv_param);
    if (UCS_PTR_IS_ERR(recv_request)) {
        fprintf(stderr, "Failed to receive response\n");
    } else {
        ucp_request_free(recv_request);
        printf("Client received: %s\n", resp.message);
    }

    ucp_ep_destroy(client_ep);
    ucp_worker_destroy(ucp_worker);
}
