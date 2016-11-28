#ifndef BENSOCKET_H
#define BENSOCKET_H

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
#define BUFFSIZE 1518

unsigned char buffer[BUFFSIZE];
char* IF_NAME;
char *ip_str;
int ip_int;
int sockd;
char *hostname;
struct ifreq ifr;
struct ifreq mac_address;
struct ifreq ip_address;
struct dhcp_packet* dhcp_header;
struct iphdr* ip_header;
struct ether_header* eth_header;
struct icmphdr* icmp_header;
struct tcphdr* tcp_header;
struct udphdr* udp_header;

void setup();
int start(int argc, char* argv[]);
#endif /* BENSOCKET_H */
