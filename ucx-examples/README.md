# 改进版

## 用法
```c
./ucp_hello_world -h
# server
./ucp_client_server -l 127.0.0.1 -p 31327
# client
./ucp_client_server -a 127.0.0.1 -p 31327
```

## ucp_example的用法
这个二进制文件既可以作为客户端也可以作为服务端，根据传递的参数来区分。
```c
make ucp_example
```
- 主要支持RDMA和AM