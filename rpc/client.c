#include "rpc_server.h"
#include <ucp/api/ucp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

void send_request(ucp_worker_h worker, ucp_ep_h ep) {
    request_t req;
    response_t resp;

    // 填充请求数据
    snprintf(req.message, sizeof(req.message), "Hello from client!");

    // 模拟发送请求并接收响应
    get_data(&req, &resp);

    // 打印响应
    printf("Client received: %s\n", resp.message);
}

int main() {
    init_ucx();

    // 模拟UCX通信初始化
    ucp_worker_h worker;
    ucp_ep_h ep;

    // 模拟发送请求
    send_request(worker, ep);

    cleanup_ucx();

    return 0;
}
