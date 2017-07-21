/*
** talker.c -- a datagram "client" demo
*/

#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>

#define SPORT 2600
#define DPORT "2500"

int main(int argc, char *argv[])
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	int rv;
	int numbytes;

	if (argc != 3) {
		fprintf(stderr,"usage: talker hostname message\n");
		exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(argv[1], DPORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and make a socket
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("talker: socket");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "talker: failed to create socket\n");
		return 2;
	}



	struct sockaddr_in sa;
	int ret, fd;

	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_port = htons(SPORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);

	ret = bind(fd, (struct sockaddr *)&sa, sizeof(struct sockaddr));
#if 1
	int disable = 1;
	if (setsockopt(sockfd, SOL_SOCKET, UDP_NO_CHECK, (void*)&disable, sizeof(disable)) < 0) {
		perror("disable checksum");
	}


	int optval = 1;
	int res = 0;

#define UDP_OPT 8

	if ((setsockopt(sockfd, IPPROTO_UDP, UDP_OPT, &optval, sizeof(int)) != 0)) {
		perror("set UDP_OPT");
	}
#endif

	if ((numbytes = sendto(sockfd, argv[2], strlen(argv[2]), 0,
			 p->ai_addr, p->ai_addrlen)) == -1) {
		perror("talker: sendto");
		exit(1);
	}

	freeaddrinfo(servinfo);

	printf("talker: sent %d bytes to %s\n", numbytes, argv[1]);
	close(sockfd);

	return 0;
}
