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
#include <pthread.h>
#include "monitor.h"
#include "dhcp.h"

unsigned char buffer[BUFFSIZE];
unsigned char send_buffer[BUFFSIZE];

int sockd;
int on;
struct ifreq ifr;
pthread_t receiver_thread, report_thread;

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
	dhcp_header = (struct dhcp_packet*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)) + 4);

	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);
}

void fill_ethernet()
{
	struct ether_header* header;
	header  = (struct ether_header*) send_buffer;
}

void fill_ip()
{
	struct iphdr* header;
	header = (struct iphdr*)   (send_buffer + sizeof(struct ether_header));

}

void send_discovery()
{
	fill_ethernet();
	fill_ip();

}

void dhcp_handler()
{
	unsigned char *options = dhcp_header->options;
	printf("Start of options:\n");
	int i = 0;
	while (true) {
		unsigned char type = options[i++];
		if (type == 255)
			break;
		unsigned char len = options[i++];
		if (type == 53) {
			if (options[i] == 1)
				send_discovery();
			else if (options[i] == 3)
				printf("request\n");
		}
		i+=len;
	}
}

void udp_handler()
{
	unsigned int port_dest = (unsigned int)ntohs(udp_header->dest);
	if (port_dest == 67)
		dhcp_handler();
}

void tcp_handler()
{

}
void ip_handler()
{
	unsigned int ip_protocol = (unsigned int)ip_header->protocol;

	if (ip_protocol == 0x6)
		tcp_handler();

	else if (ip_protocol == 0x11)
		udp_handler();
}

void* sniffer()
{
	while (true)
	{
		recv(sockd,(char *) &buffer, sizeof(buffer), 0x0);

		u_int16_t ether_type = ntohs(eth_header->ether_type);
		if(ether_type == 0x0800)
			ip_handler();

	}
}

int monitor_start(int argc, char* argv[])
{

	if(argc <= 1)
	{
		printf("Format: ./main interface\n");
		return 0;
	}

	setup(argv);
	// pthread_create(&receiver_thread, NULL, sniffer, NULL);
	sniffer();
	return 0;
}
