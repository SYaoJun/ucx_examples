ucp_client_server: ucp_client_server.c
	gcc -o ucp_client_server ucp_client_server.c -lucp -lucs -luct

libucx_rpc: ucp_client_server.c
	gcc -shared -fPIC -o libucx_rpc.so ucp_client_server.c -lucp -lucs -luct -lpthread -g
client:
	gcc -o client client.c  -lucx_rpc -L/root/ucxtest/examples/ -lucp -lucs -luct -g
server:
	gcc -o server server.c  -lucx_rpc -L/root/ucxtest/examples/ -lucp -lucs -luct -g
ucp_example: ucp_example.cpp
	g++ -o ucp_example ucp_example.cpp -lucp -lucs -luct