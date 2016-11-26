#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include "monitor.h"

unsigned char buffer[BUFFSIZE];
int sockd;
int on;
struct ifreq ifr;

bool is_ipv4(unsigned char* buffer)
{
	return buffer[0] == 8 && buffer[1] == 0;
}

bool is_udp(int protocol)
{
	return protocol == UDP;
}

void setup(char* options[])
{
	if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Erro na criação do socket.\n");
		exit(1);
	}

	strcpy(ifr.ifr_name, options[1]);

	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
	{
		printf("Erro no ioctl!\n");
		exit(1);
	}

	eth_header  = (struct ether_header*) buffer;
	ip_header   = (struct iphdr*)   (buffer + sizeof(struct ether_header));
	tcp_header  = (struct tcphdr*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));
	udp_header  = (struct udphdr*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));

	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);
}

int monitor_start(int argc, char* argv[])
{

	if(argc <= 1)
	{
		printf("Format: ./main interface\n");
		return 0;
	}

	setup(argv);

	while (true)
	{
		recv(sockd,(char *) &buffer, sizeof(buffer), 0x0);

		if (is_ipv4(&buffer[ETH_TYPE_INDEX]))
		{
			if (is_udp(buffer[IP_PROTOCOL_INDEX]))
			{
				int src_port = (buffer[34] << 8) + buffer[35];
				int dst_port = (buffer[36] << 8) + buffer[37];

				if (src_port == 67 && dst_port == 68)
				{
					printf("dhcp server to host\n");
				}
				if (src_port == 68 && dst_port == 67)
				{
					printf("dhcp host to server\n");
				}

			}
		}
	}
}
