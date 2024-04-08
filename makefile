all:
	gcc -Wall -DCOLOR simDNSClient.c -o client
	gcc -Wall -DCOLOR simDNSServer.c -o server

nocolor:
	gcc -Wall simDNSClient.c -o client
	gcc -Wall simDNSServer.c -o server

clean:
	rm -f client server