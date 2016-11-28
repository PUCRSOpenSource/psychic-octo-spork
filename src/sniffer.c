#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <pthread.h>
#include <sys/socket.h>
#include <sys/ioctl.h>

#include <arpa/inet.h>

#include <net/if.h>
#include <netinet/ether.h>
#include <netinet/in.h>
#include <netinet/ip.h>

#include <linux/tcp.h>

#include "sniffer.h"

unsigned char buffer[BUFFSIZE];
int sockd;

struct ifreq ifr;
struct ether_header* eth_header;

struct iphdr* ip_header;
struct icmphdr* icmp_header;
struct tcphdr* tcp_header;
struct udphdr* udp_header;

char* ip_host[MAPSIZE][3];
int ip_host_counter = 0;

static void save(int ip, char* host, char* location)
{
	ip_host[ip_host_counter][0] = malloc(IPSTRINGSIZE);
	ip_host[ip_host_counter][1] = malloc(strlen(host) + 1);
	ip_host[ip_host_counter][2] = malloc(strlen(location) + 1);
	struct in_addr ip_addr;
	ip_addr.s_addr = ip;
	strcpy(ip_host[ip_host_counter][0], inet_ntoa(ip_addr));
	strcpy(ip_host[ip_host_counter][1], host);
	strcpy(ip_host[ip_host_counter][2], location);
	fprintf(stderr, "%s ", ip_host[ip_host_counter][0]);
	fprintf(stderr, "%s ", ip_host[ip_host_counter][1]);
	fprintf(stderr, "%s\n", ip_host[ip_host_counter][2]);
	ip_host_counter++;
}

void parse_host_from_http(char* http_buffer)
{
	char* field = strtok(http_buffer, "\n\r");
	char* host;
	char* location;
	while (field != NULL)
	{
		host = strstr(field, "Host");
		location = strstr(field, "Location");
		if (host != NULL && location != NULL)
		{
			save(ip_header->saddr, host + strlen("Host: "), location + strlen("Location: "));
		}
		field = strtok(NULL, "\n\r");
	}
}

void write_report(char* url)
{
	FILE* report = fopen("report.html", "a");
	if(report == NULL)
	{
		printf("Error options report file!\n");
		exit(1);
	}
	fprintf(report, "\t\t\t\t\t\t<tr>\n");
	fprintf(report, "\t\t\t\t\t\t\t<td>\n");
	fprintf(report, "%s", url);
	fprintf(report, "\t\t\t\t\t\t\t<\\td>\n");
	fprintf(report, "\t\t\t\t\t\t<\\tr>\n");
}
