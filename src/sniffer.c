#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
/*#include <sys/types.h>*/
#include <sys/socket.h>
#include <sys/ioctl.h>
/*#include <unistd.h>*/

#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>

/*#include <linux/icmp.h>*/
#include <linux/tcp.h>
/*#include <linux/udp.h>*/

/*#include <netinet/in_systm.h>*/

#include "sniffer.h"

unsigned char buffer[BUFFSIZE];
int sockd;

struct ifreq ifr;
struct ether_header* eth_header;

struct iphdr* ip_header;
struct arphdr* arp_header;
struct icmphdr* icmp_header;
struct tcphdr* tcp_header;
struct udphdr* udp_header;

static void parse_host_from_http(char* http_buffer)
{
	char* field = strtok(http_buffer, "\n\r");
	char* host;
	while (field != NULL)
	{
		host = strstr(field, "Host");
		if (host != NULL)
		{
			fprintf(stderr, "%s\n", host);
		}
		field = strtok(NULL, "\n\r");
	}
}

static void http_handler()
{
	if (ip_header->protocol == 6 && (ntohs(tcp_header->dest) == 80 || ntohs(tcp_header->dest) == 8080))
	{
		/*fprintf(stderr, "IP PROTOCOL = %u\n", ip_header->protocol);*/
		/*fprintf(stderr, "TCP DESTPOR = %u\n", ntohs(tcp_header->dest));*/
		char* http_header_start = (char*) (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct tcphdr)));
		parse_host_from_http(http_header_start);
	}
}

static void sniff_network(void)
{
	while (1)
	{
		recv(sockd, buffer, BUFFSIZE, 0x0);
		http_handler();
	}
}

static void setup(char* options[])
{
	if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Socket could not be created.\n");
		exit(1);
	}

	strcpy(ifr.ifr_name, options[1]);

	if(ioctl(sockd, SIOCGIFINDEX, &ifr) < 0)
	{
		printf("Error in ioctl!\n");
		exit(1);
	}

	eth_header  = (struct ether_header*) buffer;
	ip_header   = (struct iphdr*)   (buffer + sizeof(struct ether_header));
	arp_header  = (struct arphdr*)  (buffer + sizeof(struct ether_header));
	tcp_header = (struct tcphdr*) (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));


	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);
}

void* sniffer_start(int argc,char *argv[])
{
	if(argc != 2)
	{
		printf("Use %s <IF_NAME>\n", argv[0]);
		return (void*) EXIT_FAILURE;
	}
	setup(argv);
	sniff_network();
	return (void*) EXIT_SUCCESS;
}
