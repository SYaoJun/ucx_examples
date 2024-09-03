#include "rpc_server.h"
#include <ucp/api/ucp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void handle_request(ucp_worker_h worker, ucp_ep_h ep) {
    request_t req;
    response_t resp;

    // 模拟接收请求
    snprintf(req.message, sizeof(req.message), "Hello from client!");

    // 处理请求
    get_data(&req, &resp);

    // 模拟发送响应
    printf("Server response: %s\n", resp.message);
}

int main() {
    init_ucx();

    // 模拟UCX通信初始化
    ucp_worker_h worker;
    ucp_ep_h ep;

    // 模拟处理请求
    handle_request(worker, ep);

    cleanup_ucx();

    return 0;
}
