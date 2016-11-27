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
#include <arpa/inet.h>
#include <pthread.h>
#include <unistd.h>
#include "monitor.h"
#include "dhcp.h"
#include "checksum.h"

unsigned char buffer[BUFFSIZE];
unsigned char send_buffer[BUFFSIZE];
char* IF_NAME;

int sockd;
int on;
struct ifreq ifr;
struct ifreq mac_address;
pthread_t receiver_thread, report_thread;

bool is_ipv4(unsigned char* buffer)
{
	return buffer[0] == 8 && buffer[1] == 0;
}

bool is_udp(int protocol)
{
	return protocol == UDP;
}

void setup()
{
	if((sockd = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)
	{
		printf("Erro na criação do socket.\n");
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
	dhcp_header = (struct dhcp_packet*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)) + 4);

	ioctl(sockd, SIOCGIFFLAGS, &ifr);
	ifr.ifr_flags |= IFF_PROMISC;
	ioctl(sockd, SIOCSIFFLAGS, &ifr);

	int s;
	s = socket(PF_INET, SOCK_DGRAM, 0);
	memset(&mac_address, 0x00, sizeof(mac_address));
	strcpy(mac_address.ifr_name, IF_NAME);
	ioctl(sockd, SIOCGIFHWADDR, &mac_address);
	close(s);
}

void fill_ethernet()
{
	struct ether_header* header;
	header  = (struct ether_header*) send_buffer;

	header->ether_type = 0x0800;

	for (int i = 0; i < 6; i++)
	{
		header->ether_shost[i] = mac_address.ifr_hwaddr.sa_data[i];
		header->ether_dhost[i] = eth_header->ether_shost[i];
	}

}

void fill_ip()
{
	struct iphdr* header;
	header = (struct iphdr*) (buffer + sizeof(struct ether_header));

	//TODO: Change this to get correct ip from machine and fake ip for victim.
	char *src_addr="192.168.1.33";
	char *dst_addr="192.168.1.34";

	header->ihl = 5;
	header->version = 4;
	header->tot_len = 20;
	header->protocol = IPPROTO_UDP;
	header->saddr = inet_addr(src_addr);
	header->daddr = inet_addr(dst_addr);
	header->check = in_cksum((unsigned short *)header, sizeof(struct iphdr));
}

void send_discovery()
{
	fill_ethernet();
	fill_ip();
}

void dhcp_handler()
{
	unsigned char *options = dhcp_header->options;
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
				send_discovery();
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
	IF_NAME = argv[1];

	setup();
	// pthread_create(&receiver_thread, NULL, sniffer, NULL);
	sniffer();
	return 0;
}
