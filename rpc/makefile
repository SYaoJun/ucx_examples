all: libucx_rpc client server

libucx_rpc: ucx_rpc.c
	gcc -shared -fPIC -o libucx_rpc.so ucx_rpc.c -lucp -lucs -luct -lpthread -g
client:
	gcc -o client client.c  -lucx_rpc -L/root/ucxtest/rpc/ -lucp -lucs -luct -g
server:
	gcc -o server server.c  -lucx_rpc -L/root/ucxtest/rpc/ -lucp -lucs -luct -g

clean:
	rm -f $(server) $(client) $(libucx_rpc)

.PHONY: all clean