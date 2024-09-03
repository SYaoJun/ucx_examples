
#ifndef RPC_UCX_H
#define RPC_UCX_H
#include <ucp/api/ucp.h>

typedef struct {
    char message[256];
} request_t;

typedef struct {
    char message[256];
} response_t;

void start_server_rpc();
void start_client_rpc();

#endif // RPC_UCX_H