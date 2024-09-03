libucx_rpc: rpc_server.c
	gcc -shared -fPIC -o libucx_rpc.so rpc_server.c
client:
	gcc -o client client.c  -lucx_rpc -L/root/ucxtest/rpc/ -lucp -lucs -luct
server:
	gcc -o server server.c  -lucx_rpc -L/root/ucxtest/rpc/ -lucp -lucs -luct