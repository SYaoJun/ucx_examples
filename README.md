# UCX Examples
UCP (Unified Communication Protocol)
UCT (Transport)
UCS (Services)
UCM (Memory)
## UCP
UCP 是 UCX 的高级通信协议层，提供了一组抽象的 API，用于高层次的通信操作，如消息传递、同步等。
## Install
- Ubunutu 22.04 
```c
sudo apt-get install libucx-dev
```
## UCP
- ucp_tag_send_nbx 发送消息
- ucp_tag_recv_nbx 接收消息
## TODO
[ ] 测试ucp和socket的性能差异
[ ] 基于ucp的RDMA实现通信的demo
[ ] 支持TCP版RPC的长连接和并发连接

## Acknowledgements
Thanks to [ucx-examples](https://github.com/PrisdxMeany/ucx-examples) and [openucx](https://github.com/openucx/ucx)
