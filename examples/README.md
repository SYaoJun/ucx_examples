# ucp_client_server.c
- TAG
- STREAM
- AM
## usage
```c
$./ucp_client_server -h
Usage: ucp_client_server [parameters]
UCP client-server example utility

Parameters are:
  -a Set IP address of the server (required for client and should not be specified for the server)
  -l Set IP address where server listens (If not specified, server uses INADDR_ANY; Irrelevant at client)
  -p Port number to listen/connect to (default = 13337). 0 on the server side means select a random port and print it
  -c Communication type for the client and server.   Valid values are:
      'stream' : Stream API
      'tag'    : Tag API
      'am'     : AM API
     If not specified, STREAM API will be used.
  -i Number of iterations to run. Client and server must have the same value. (default = 1).
  -v Number of buffers in a single data transfer function call. (default = 1).
  -p <port>     Set alternative server port (default:13337)
  -6            Use IPv6 address in data exchange
  -s <size>     Set test string length (default:16)
  -m <mem type> Memory type of messages
                host - system memory (default)
                cuda - NVIDIA GPU memory
                cuda-managed - NVIDIA GPU managed/unified memory
```
## run
```
# server
./ucp_client_server -l 127.0.0.1 -p 13337
# client
./ucp_client_server -a 127.0.0.1 -p 13337
```