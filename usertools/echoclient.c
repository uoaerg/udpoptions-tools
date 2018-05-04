#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <errno.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netinet/in.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <netdb.h>

#define MAXBUFLEN 	65535

uint16_t interval = 2;
uint16_t sendsize = 64;
const char *dstport = "7";			//udp echo

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
	struct sockaddr_in sa;
	socklen_t addr_len;
	int numbytes, rv;
	int optval = 1;
	char buf[MAXBUFLEN];               
	char s[INET6_ADDRSTRLEN];
	struct timeval tv;

	if (argc != 2) {
		fprintf(stderr,"usage: %s hostname\n", argv[0]);
		exit(1);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_DGRAM;

	if ((rv = getaddrinfo(argv[1], dstport, &hints, &servinfo)) != 0) {
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
		fprintf(stderr, "%s: failed to create socket\n", argv[0]);
		return 2;
	}

	memset(&sa, 0, sizeof(struct sockaddr_in));
	sa.sin_family = AF_INET;
	sa.sin_addr.s_addr = htonl(INADDR_ANY);

	rv = bind(sockfd, (struct sockaddr *)&sa, sizeof(struct sockaddr));
	rv = connect(sockfd, (struct sockaddr *)&sa, sizeof(struct sockaddr));

#define UDP_OPT             8   /* use udp options */
#define UDP_OPT_MSS         9   /* get opt rtt estimate */ 

	if ((setsockopt(sockfd, IPPROTO_UDP, UDP_OPT, &optval, sizeof(int)) != 0)) {
		perror("set UDP_OPT");
	}

	tv.tv_sec = 10;
	if (setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO ,&tv, sizeof(tv)) < 0) {
		perror("setting time out");
	}

	memset(buf, '4', sendsize);

	if ((numbytes = sendto(sockfd, buf, sendsize, 0, p->ai_addr, 
		p->ai_addrlen)) == -1) {
		perror("sendto");
		exit(1);
	}

	printf("send: sent %d bytes to %s\n", numbytes, argv[1]);

	addr_len = sizeof their_addr;             
	if ((numbytes = recvfrom(sockfd, buf, MAXBUFLEN-1 , 0,     
		(struct sockaddr *)&their_addr, &addr_len)) == -1) {   
		perror("send: ");                   
		freeaddrinfo(servinfo);
		close(sockfd);
		exit(1);   
	}              
				   
	printf("%s: received %d bytes from %s\n", argv[0], numbytes,
		inet_ntop(their_addr.ss_family,                        
		get_in_addr((struct sockaddr *)&their_addr),           
		s, sizeof s));                                         

	freeaddrinfo(servinfo);
	close(sockfd);

	return 0;
}
