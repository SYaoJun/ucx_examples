#ifndef RPC_UCX_H
#define RPC_UCX_H
#include <ucs/memory/memory_type.h>
#include <ucp/api/ucp.h>

typedef struct {
    char message[256];
} request_t;

typedef struct {
    char message[256];
} response_t;

void init_ucx();
void cleanup_ucx();
void start_server();
void send_request();

#endif // RPC_UCX_H
