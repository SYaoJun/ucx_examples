#ifndef RPC_SERVER_H
#define RPC_SERVER_H

typedef struct {
    char message[256];
} request_t;

typedef struct {
    char message[256];
} response_t;

void get_data(const request_t *req, response_t *resp);
void init_ucx();
void cleanup_ucx();

#endif // RPC_SERVER_H
