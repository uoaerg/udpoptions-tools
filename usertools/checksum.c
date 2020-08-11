#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>

uint8_t udp_optcksum(uint8_t *, int);

int
main(int argc, char **argv)
{
#define BUFSIZE 256
	uint8_t data[BUFSIZE];
	uint16_t optlen;

	if (argc == 1) {
		printf("need some data to parse\n");
		exit(1);
	}
	if (argc-1 > BUFSIZE) {
		printf("faaaar too much data, we can only take %d of options\n",
			BUFSIZE);
		exit(1);
	}

	for (int count = 1; count < argc; count++, argv++)
		data[optlen++] = (uint8_t)strtol(*argv, NULL, 16);

#if 1
	int toggle = 0;
	for(int i = 0; i < optlen; i++) {
		printf("%02x ", data[i]);
		if(++toggle % 16 == 0)
			printf("\n");
	}
	printf("\n");
#endif	

	printf("optchecksum %x\n", udp_optcksum(data, optlen));

	return 0;
}

uint8_t
udp_optcksum(uint8_t *cp, int len)
{
        uint16_t cksum = 0;

        for(int i = 0; i < len; i++) {
                cksum += cp[i];
        }

        while(cksum > 0x00FF)
                cksum = ((cksum & 0xFF00) >> 8) + (cksum & 0x00FF);

        return (uint8_t)~cksum;
}

