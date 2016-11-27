#include <linux/tcp.h>
#include <linux/udp.h>
#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <linux/if_packet.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include <stdbool.h>
#include "bensocket.h"
#include "sniffer.h"
#include "monitor.h"

void setup()
{
	if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Socket could not be created.\n");
		exit(1);
	}

	strcpy(ifr.ifr_name, IF_NAME);

	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
	{
		printf("Erro no ioctl!\n");
		exit(1);
	}

	eth_header  = (struct ether_header*) buffer;
	ip_header   = (struct iphdr*)   (buffer + sizeof(struct ether_header));
	tcp_header  = (struct tcphdr*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));
	udp_header  = (struct udphdr*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));
	dhcp_header = (struct dhcp_packet*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)));

	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	int fd;
	fd = socket(PF_INET, SOCK_DGRAM, 0);
	memset(&mac_address, 0x00, sizeof(mac_address));
	strcpy(mac_address.ifr_name, IF_NAME);
	ioctl(fd, SIOCGIFHWADDR, &mac_address);
	strcpy(ip_address.ifr_name, IF_NAME);
	ioctl(fd, SIOCGIFADDR, &ip_address);
	close(fd);
	struct in_addr x =  ((struct sockaddr_in *)&ip_address.ifr_addr)->sin_addr;
	uint32_t y = x.s_addr;
	ip_int = htonl(y);
	ip_str = inet_ntoa(((struct sockaddr_in *)&ip_address.ifr_addr)->sin_addr);
}

void ip_handler()
{
	unsigned int ip_protocol = (unsigned int)ip_header->protocol;

	if (ip_protocol == 0x11)
		udp_handler();

	else if (ip_header->protocol == 6 && (ntohs(tcp_header->dest) == 80 || ntohs(tcp_header->dest) == 8080))
	{
		char* http_header_start = (char*) (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)));
		parse_host_from_http(http_header_start);
	}
}

void sniffer()
{
	while (true)
	{
		recv(sockd,(char *) &buffer, sizeof(buffer), 0x0);

		u_int16_t ether_type = ntohs(eth_header->ether_type);
		if(ether_type == 0x0800)
			ip_handler();
	}
}

int start(int argc, char* argv[])
{

	if(argc <= 1)
	{
		printf("Format: ./main interface\n");
		return 0;
	}
	IF_NAME = argv[1];

	setup();
	sniffer();

	return 0;
}
