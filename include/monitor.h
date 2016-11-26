#ifndef MONITOR_H
#define MONITOR_H

#include <stdbool.h>

#define BUFFSIZE 1518
#define ETH_TYPE_INDEX 12
#define ARP_TYPE_INDEX 21
#define IP_PROTOCOL_INDEX 23
#define ICMP_TYPE_INDEX 34
#define IP_SRC_INDEX 26
#define IP_DST_INDEX 30
#define ARP_REQUEST 1
#define ARP_REPLY 2
#define ICMP_ECHO_REQUEST 8
#define ICMP_ECHO_REPLY 0
#define ICMP 1
#define TCP 6
#define UDP 17

extern struct ether_header* eth_header;
extern struct iphdr* ip_header;
extern struct tcphdr* tcp_header;
extern struct udphdr* udp_header;

extern unsigned char buffer[BUFFSIZE];
extern int sockd;
extern int on;
extern struct ifreq ifr;

bool is_ipv4(unsigned char* buffer);
bool is_udp(int protocol);
int monitor_start(int argc, char* argv[]);

#endif /* MONITOR_H */
