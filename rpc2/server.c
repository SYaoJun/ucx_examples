#include "ucx_rpc.h"
#include <stdio.h>

int main() {
    init_ucx();
    start_server();
    cleanup_ucx();
    return 0;
}
