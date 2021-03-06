#ifndef SNIFFER_H
#define SNIFFER_H

#define BUFFSIZE 1518
#define MAPSIZE 2000
#define IPSTRINGSIZE 16

extern unsigned char buffer[BUFFSIZE];
extern int sockd;

extern struct ifreq ifr;
extern struct ether_header* eth_header;

extern struct iphdr* ip_header;
extern struct arphdr* arp_header;
extern struct icmphdr* icmp_header;
extern struct tcphdr* tcp_header;
extern struct udphdr* udp_header;

extern char* ip_host[MAPSIZE][2];
extern int ip_host_counter;

void parse_host_from_http(char* http_buffer);

#endif /* SNIFFER_H */
