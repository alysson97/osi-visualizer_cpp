#ifndef HEADER_H
#define HEADER_H

#include <pcap.h>
#include <iostream>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ether.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <net/ethernet.h>
#include <cstring>
#include <cctype>
#include <unistd.h>




// Estrutura do Cabeçalho DNS
struct dnshdr {
    uint16_t id;
    uint16_t flags;
    uint16_t q_count;
    uint16_t ans_count;
    uint16_t auth_count;
    uint16_t add_count;
};


std::string dnsLabelToString(const unsigned char* dnsName);
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet);
void listAllDevices();
std::string getHostname(const char* ip);

#endif