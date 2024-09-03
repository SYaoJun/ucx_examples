#include "rpc_server.h"
#include <ucp/api/ucp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static ucp_context_h ucp_context;

void get_data(const request_t *req, response_t *resp) {
    // 处理请求并填充响应
    snprintf(resp->message, sizeof(resp->message), "Received: %s", req->message);
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
