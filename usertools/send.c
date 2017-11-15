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

#define MAXBUFLEN 65535

//#define SPORT 2600
#define DPORT "2500"

// get sockaddr, IPv4 or IPv6:                        
void *get_in_addr(struct sockaddr *sa)                
{                                                     
    if (sa->sa_family == AF_INET) {                   
        return &(((struct sockaddr_in*)sa)->sin_addr);
    }                                                 
                                                      
    return &(((struct sockaddr_in6*)sa)->sin6_addr);  
}                                                     

int main(int argc, char *argv[])
{
	int sockfd;
	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr;
	char buf[MAXBUFLEN];               
	socklen_t addr_len;
	int rv;
	int numbytes;
	char s[INET6_ADDRSTRLEN];

	if (argc != 3) {
		fprintf(stderr,"usage: send hostname message\n");
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
			perror("send: socket");
			continue;
		}

		break;
	}

	if (p == NULL) {
		fprintf(stderr, "send: failed to create socket\n");
		return 2;
	}



	struct sockaddr_in sa;
	int ret, fd;

	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	//sa.sin_port = htons(SPORT);
	sa.sin_addr.s_addr = htonl(INADDR_ANY);

	ret = bind(fd, (struct sockaddr *)&sa, sizeof(struct sockaddr));

	for (int i = 0;i < 10;i++) {

		int optval = 1;
		int res = 0;

#define UDP_OPT 8 
		if ((setsockopt(sockfd, IPPROTO_UDP, UDP_OPT, &optval, sizeof(int)) != 0)) {
			perror("set UDP_OPT");
		}

		if ((numbytes = sendto(sockfd, argv[2], strlen(argv[2]), 0,
				 p->ai_addr, p->ai_addrlen)) == -1) {
			perror("send: sendto");
			exit(1);
		}
		printf("send: sent %d bytes to %s\n", numbytes, argv[1]);

		addr_len = sizeof their_addr;             
		if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,     
			(struct sockaddr *)&their_addr, &addr_len)) == -1) {   
			perror("recvfrom");                   
			exit(1);   
		}              
					   
		printf("send: loop %d received %d bytes from %s\n", i, numbytes,
			inet_ntop(their_addr.ss_family,                        
			get_in_addr((struct sockaddr *)&their_addr),           
			s, sizeof s));                                         
		buf[numbytes] = '\0';                                      

	}
	freeaddrinfo(servinfo);

	close(sockfd);

	return 0;
}
