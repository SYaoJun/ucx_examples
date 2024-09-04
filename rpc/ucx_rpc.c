#include "ucx_rpc.h"
#include "hello_world_util.h"
#include <ucp/api/ucp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <pthread.h>
#include <unistd.h>

static ucp_context_h ucp_context;
static ucp_worker_h ucp_worker;
static ucp_listener_h listener;
static ucp_ep_h server_ep;
static ucp_ep_h client_ep;
static int server_running = 1;
static int come_client = 0;
static const ucp_tag_t tag  = 0x1337a880u;
static const ucp_tag_t tag_mask = UINT64_MAX;
static long test_string_length = 16;
static long iov_cnt            = 1;
typedef struct ucx_context {
    int completed;
}ucx_context_t;

// int fill_buffer(ucp_dt_iov_t *iov)
// {

//     for (size_t idx = 0; idx < iov_cnt; idx++) {
//         generate_test_string(iov[idx].buffer, iov[idx].length);

//     }
//     return 0;
// }
static void print_iov(const ucp_dt_iov_t *iov)
{
    char *msg = alloca(test_string_length);
    size_t idx;

    for (idx = 0; idx < iov_cnt; idx++) {
        /* In case of Non-System memory */
        mem_type_memcpy(msg, iov[idx].buffer, test_string_length);
        printf("%s.\n", msg);
    }
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
static void common_cb(void *user_data, const char *type_str)
{
    ucx_context_t *ctx;

    if (user_data == NULL) {
        fprintf(stderr, "user_data passed to %s mustn't be NULL\n", type_str);
        return;
    }

    ctx           = user_data;
    ctx->completed = 1;
}
static void tag_recv_cb(void *request, ucs_status_t status,
                        const ucp_tag_recv_info_t *info, void *user_data)
{
    common_cb(user_data, "tag_recv_cb");
}

static ucs_status_t request_wait(ucp_worker_h ucp_worker, void *request,
                                 ucx_context_t *ctx)
{
    ucs_status_t status;

    /* if operation was completed immediately */
    if (request == NULL) {
        return UCS_OK;
    }

    if (UCS_PTR_IS_ERR(request)) {
        return UCS_PTR_STATUS(request);
    }

    while (ctx->completed == 0) {
        ucp_worker_progress(ucp_worker);
    }
    status = ucp_request_check_status(request);

    ucp_request_free(request);

    return status;
}
static int request_finalize(ucp_worker_h ucp_worker, void* request,
                            ucx_context_t *ctx)
{
    ucs_status_t status;

    status = request_wait(ucp_worker, request, ctx);
    if (status != UCS_OK) {
        fprintf(stderr, "unable to UCX message\n");
        return -1;
    }

   return 0;
}
void buffer_free(ucp_dt_iov_t *iov)
{
    size_t idx;

    for (idx = 0; idx < iov_cnt; idx++) {
        mem_type_free(iov[idx].buffer);
    }
}

int buffer_malloc(ucp_dt_iov_t *iov)
{
    size_t idx;

    for (idx = 0; idx < iov_cnt; idx++) {
        iov[idx].length = test_string_length;
        iov[idx].buffer = mem_type_malloc(iov[idx].length);
        if (iov[idx].buffer == NULL) {
            buffer_free(iov);
            return -1;
        }
    }

    return 0;
}

static void request_completed(void *request, ucs_status_t status, void *user_data) {
    if (status != UCS_OK) {
        fprintf(stderr, "Request failed\n");
    } else {
        fprintf(stdout, "callback send data ok\n");
    }
    if(user_data){
        ucx_context_t *ctx = (ucx_context_t*)user_data;
        ctx->completed = 1;
    }
    
    ucp_request_free(request);
}
static void client_recv_handler(void *request, ucs_status_t status,
                         const ucp_tag_recv_info_t *info, void *user_data)
{
    if (status != UCS_OK) {
        fprintf(stderr, "Receive request failed\n");
    } else {
        fprintf(stdout, "client received data\n");
    }
    if(user_data){
        ucx_context_t *ctx = (ucx_context_t*)user_data;
        ctx->completed = 1;
    }
    ucp_request_free(request);
}
static void recv_handler(void *request, ucs_status_t status,
                         const ucp_tag_recv_info_t *info, void *user_data)
{
    if (status != UCS_OK) {
        fprintf(stderr, "Receive request failed\n");
    } else {
        fprintf(stdout, "receive data from client\n");
    }
    if(user_data){
        ucx_context_t *ctx = (ucx_context_t*)user_data;
        ctx->completed = 1;
    }

    ucp_request_free(request);
}
void do_task(){
    ucp_dt_iov_t *iov = alloca(iov_cnt * sizeof(ucp_dt_iov_t));
    memset(iov, 0, iov_cnt * sizeof(*iov));
    buffer_malloc(iov);
    for (size_t idx = 0; idx < iov_cnt; idx++) {
        generate_test_string(iov[idx].buffer, iov[idx].length);
    }
    char *msg;
    size_t msg_length;
    msg        = iov[0].buffer; 
    msg_length =  iov[0].length;
    strcpy(msg, "hello");
    msg_length = 5;

    ucx_context_t *ctx = (ucx_context_t*)malloc(sizeof(ucx_context_t));
    ctx->completed = 0;

    ucp_request_param_t recv_param;
    memset(&recv_param, 0, sizeof(recv_param));
    recv_param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA;
    recv_param.cb.recv = recv_handler;
    recv_param.user_data = ctx; // how to pass ctx when receive data ?

    void *recv_request = ucp_tag_recv_nbx(ucp_worker, msg, msg_length, tag, tag_mask, &recv_param);
    
    if(request_finalize(ucp_worker, recv_request, ctx) == 0){
        fprintf(stdout, "server recv ok\n");
    }else{
        fprintf(stdout, "server recv failed\n");
    } 
    fprintf(stdout, "server received data: %s\n", msg);

    memset(msg, 0, msg_length);
    strcpy(msg, "world");

    ctx->completed = 0;
    ucp_request_param_t send_param;
    memset(&send_param, 0, sizeof(send_param));
    send_param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA;
    send_param.cb.send = request_completed;
    send_param.user_data = ctx;

    void *send_request = ucp_tag_send_nbx(server_ep, msg, msg_length, tag, &send_param);
    if(request_finalize(ucp_worker, send_request, ctx) == 0){
        fprintf(stdout, "server send send ok\n");
    }else{
        fprintf(stdout, "server send failed\n");
    } 
    free(ctx);
    free(msg);
    buffer_free(iov);
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
        come_client = 1;
        puts("connection for client");
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
        while(come_client == 0){
            ucp_worker_progress(ucp_worker);
        }
        do_task();
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

    // request_t req;
    ucp_dt_iov_t *iov = alloca(iov_cnt * sizeof(ucp_dt_iov_t));
    memset(iov, 0, iov_cnt * sizeof(*iov));
    buffer_malloc(iov);
    for (size_t idx = 0; idx < iov_cnt; idx++) {
        generate_test_string(iov[idx].buffer, iov[idx].length);
    }
    char *msg;
    size_t msg_length;
    msg        = iov[0].buffer; 
    msg_length =  iov[0].length;
    strcpy(msg, "hello");
    msg_length = 5;

    ucp_request_param_t send_param;
    ucx_context_t *ctx = (ucx_context_t*)malloc(sizeof(ucx_context_t));
    ctx->completed = 0;
    memset(&send_param, 0, sizeof(send_param));
    send_param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA;
    send_param.cb.send = request_completed;
    send_param.user_data = ctx;

    void *send_request = ucp_tag_send_nbx(client_ep, msg, msg_length, tag, &send_param);
  
    if(request_finalize(ucp_worker, send_request, ctx) == 0){
        fprintf(stdout, "main send ok\n");
    }else{
        fprintf(stdout, "main send failed\n");
    } 
    
     

    // receive data from server
    ucp_request_param_t recv_param;
    ctx->completed = 0;
    memset(msg, 0, msg_length);
    memset(&recv_param, 0, sizeof(recv_param));
    recv_param.op_attr_mask = UCP_OP_ATTR_FIELD_CALLBACK | UCP_OP_ATTR_FIELD_USER_DATA;
    recv_param.cb.recv = client_recv_handler;
    recv_param.user_data = ctx;

    void *recv_request = ucp_tag_recv_nbx(ucp_worker, msg, msg_length, tag, tag_mask, &recv_param);
    if(request_finalize(ucp_worker, recv_request, ctx) == 0){
        fprintf(stdout, "main send ok\n");

    }else{
        fprintf(stdout, "main send failed\n");
    } 

    // print_iov(iov);
    fprintf(stdout, "client received data: %s\n", msg);
    
    free(ctx);
    buffer_free(iov);
    ucp_ep_destroy(client_ep);
    ucp_worker_destroy(ucp_worker);
}
