#include "ucx_rpc.h"
#include <stdio.h>

int main() {
    init_ucx();
    send_request();
    cleanup_ucx();
    return 0;
}
