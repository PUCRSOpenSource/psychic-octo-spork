#ifndef SNIFFER_H
#define SNIFFER_H

#define BUFFSIZE 1518

extern unsigned char buffer[BUFFSIZE];
extern int sockd;

extern struct ifreq ifr;
extern struct ether_header* eth_header;

extern struct iphdr* ip_header;
extern struct arphdr* arp_header;
extern struct icmphdr* icmp_header;
extern struct tcphdr* tcp_header;
extern struct udphdr* udp_header;

void* sniffer_start(int argc, char* argv[]);

#endif /* SNIFFER_H */
