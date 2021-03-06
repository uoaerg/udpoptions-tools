#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>

#define PORT "7"	//udp echo

#define MAXBUFLEN 65535

// get sockaddr, IPv4 or IPv6:
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}

	return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

int main(void)
{
	int sockfd, rv, numbytes;
	int optval = 1;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr;
	char buf[MAXBUFLEN];
	char s[INET6_ADDRSTRLEN];
	socklen_t addr_len;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_INET; // set to AF_INET to force IPv4
	hints.ai_socktype = SOCK_DGRAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return 1;
	}

	// loop through all the results and bind to the first we can
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((sockfd = socket(p->ai_family, p->ai_socktype,
				p->ai_protocol)) == -1) {
			perror("echoserver: socket");
			continue;
		}

		if (bind(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			perror("echoserver: bind");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "echoserver: failed to bind socket\n");
		return 2;
	}

#define UDP_OPT             8   /* use udp options */
#define UDP_OPT_MSS         9   /* get opt rtt estimate */
#define UDP_OPT_ECHO        10  /* respond to echo requests estimate */
#define UDP_OPT_PROBE       11  /* perform plpmtud probing */

    if ((setsockopt(sockfd, IPPROTO_UDP, UDP_OPT, &optval, sizeof(int)) != 0)) {
        perror("set UDP_OPT");
    }

    if ((setsockopt(sockfd, IPPROTO_UDP, UDP_OPT_ECHO, &optval, sizeof(int)) != 0)) {
        perror("set UDP_OPT_ECHO");
    }

    if ((setsockopt(sockfd, IPPROTO_UDP, UDP_OPT_PROBE, &optval, sizeof(int)) != 0)) {
        perror("set UDP_OPT_PROBE");
    }

	printf("echoserver: listening on %s:%s\n", 
			inet_ntop(their_addr.ss_family, get_in_addr(p->ai_addr),
			s, sizeof s), 
			PORT);
	freeaddrinfo(servinfo);

	while(1) {
		addr_len = sizeof their_addr;
		if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,
			(struct sockaddr *)&their_addr, &addr_len)) == -1) {
			perror("recvfrom");
			exit(1);
		}

		if (numbytes == 0)
			continue;

		printf("echoserver: received %d bytes from %s\n", numbytes,
			inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s));
		buf[numbytes] = '\0';

		if ((numbytes = sendto(sockfd, buf, numbytes, 0,
			(struct sockaddr *)&their_addr, addr_len)) == -1) { 
			perror("echoserver: sendto");                 
			exit(1);       
		}                  

		printf("echoserver: echo'd   %d bytes to   %s\n", numbytes,
			inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),
			s, sizeof s));
		buf[numbytes] = '\0';


	}	
	close(sockfd);

	return 0;
}
