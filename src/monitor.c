#include <stdlib.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <string.h>
#include <unistd.h>
#include <stdbool.h>

#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <arpa/inet.h>

#include <netinet/in_systm.h>

#define BUFFSIZE 1518
#define ETH_TYPE_INDEX 12
#define ARP_TYPE_INDEX 21
#define IP_PROTOCOL_INDEX 23
#define ICMP_TYPE_INDEX 34
#define IP_SRC_INDEX 26
#define IP_DST_INDEX 30
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define ICMP 1
#define TCP 6
#define UDP 17

unsigned char buffer[BUFFSIZE];
int sockd;
int on;
struct ifreq ifr;

bool is_ipv4(unsigned char *buffer);
bool is_udp(int protocol);

bool is_ipv4(unsigned char *buffer) {
	return buffer[0] == 8 && buffer[1] == 0;
}

bool is_udp(int protocol) {
	return protocol == UDP;
}

int main(int argc,char *argv[])
{

	if(argc <= 1) {
		printf("Formato: ./arquivo interface numero-de-pacotes\n");
		return 0;
	}

    if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0) {
    	printf("Erro na criacao do socket.\n");
		exit(1);
    }

	strcpy(ifr.ifr_name, argv[1]);
	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
		printf("erro no ioctl!");
	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);
	while (1) {
		ssize_t package_size = recv(sockd,(char *) &buffer, sizeof(buffer), 0x0);

		if (is_ipv4(&buffer[ETH_TYPE_INDEX])) {
			if (is_udp(buffer[IP_PROTOCOL_INDEX])) {
				int src_port = (buffer[34] << 8) + buffer[35];
				int dst_port = (buffer[36] << 8) + buffer[37];
				if (src_port == 67 && dst_port == 68) {
					printf("dhcp server to host\n");
				}
				if (src_port == 68 && dst_port == 67) {
					printf("dhcp host to server\n");
				}

			}
		}
	}
}
