#include <sys/socket.h>
#include <unistd.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int main(int argc, char * argv[]){

	int socketfd, connectedfd, portnum, n;

	char buff[255];

	struct sockaddr_in serv_addr, cli_addr;


	sockaddr sa;
	sockaddr_in *sin = (sockaddr_in *) &sa;

	if(argc < 2){
		printf("Please provide a port number.");
		return 0;
	}

	socketfd = socket(PF_INET, SOCK_STREAM, 0);

	if(socketfd == -1){
		printf("Socket connection failed.");
		return 0;
	}

	bzero((char *) &serv_addr, sizeof(serv_addr));

	serv_addr.sin_family = PF_INET;
	serv_addr.sin_port = htons(atoi(argv[1]));
	serv_addr.sin_addr.s_addr = INADDR_ANY;

	int res = bind(socketfd, (struct sockaddr *) &serv_addr, sizeof(serv_addr));
	if(res < 0){
		printf("Binding connection failed.");
		return 0;
	}

	listen(socketfd, 5);

	socklen_t cliaddrsiz = sizeof(cli_addr);
	connectedfd = accept(socketfd, (struct sockaddr *) &cli_addr, &cliaddrsiz);

	if(connectedfd < 0){
		printf("Problem waiting for client.");
		return 0;
	}

	n = read(connectedfd,buff,255);
	if(n<0){
		printf("Error reading data.");
		return 0;
	}

	while(n == 255){
		printf("%s",buff);
		n = read(connectedfd,buff,255);
		if(n<0){
			printf("Error reading data.");
			return 0;
		}
	}

	for(int i =0; i < n; i++){
		printf("%c", buff[i]);
	}

	return 0;

}