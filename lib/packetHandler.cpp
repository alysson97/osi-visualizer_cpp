#include "../header/header.h"


#define DNS_PORT 53

// Callback para processamento dos pacotes capturados
void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    std::cout << "Pacote capturado de comprimento: " << pkthdr->len << std::endl;

    struct ether_header *ethHeader;
    ethHeader = (struct ether_header *) packet;

    char srcMac[18], dstMac[18];
    snprintf(srcMac, sizeof(srcMac), "%02x:%02x:%02x:%02x:%02x:%02x",
             ethHeader->ether_shost[0], ethHeader->ether_shost[1], ethHeader->ether_shost[2],
             ethHeader->ether_shost[3], ethHeader->ether_shost[4], ethHeader->ether_shost[5]);
    snprintf(dstMac, sizeof(dstMac), "%02x:%02x:%02x:%02x:%02x:%02x",
             ethHeader->ether_dhost[0], ethHeader->ether_dhost[1], ethHeader->ether_dhost[2],
             ethHeader->ether_dhost[3], ethHeader->ether_dhost[4], ethHeader->ether_dhost[5]);

    if (ntohs(ethHeader->ether_type) == ETHERTYPE_IP) {
        const struct ip* ipHeader;
        ipHeader = (struct ip*)(packet + sizeof(struct ether_header));
        if (ipHeader->ip_p == IPPROTO_TCP || ipHeader->ip_p == IPPROTO_UDP) {
            const struct tcphdr* tcpHeader = nullptr;
            const struct udphdr* udpHeader = nullptr;
            const u_char* data = nullptr;
            int dataLength = 0;

            std::string srcIp = inet_ntoa(ipHeader->ip_src);
            std::string hostname = getHostname(srcIp.c_str());

            if (ipHeader->ip_p == IPPROTO_TCP) {
                tcpHeader = (struct tcphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                if (ntohs(tcpHeader->th_dport) == 80 || ntohs(tcpHeader->th_dport) == 443) {
                    std::cout << "recebendo pacote..." << std::endl;
                    std:: cout << std::endl;
                    std::cout << "pacote recebido de: " << hostname << std::endl;
                    std::cout << "\nCamada Física e Enlace:" << std::endl;
                    std::cout << "MAC de Origem: " << srcMac << std::endl;
                    std::cout << "MAC de Destino: " << dstMac << std::endl;
                    std::cout << "\nCamada de Rede:" << std::endl;
                    std::cout << "Protocolo: IPv4" << std::endl;
                    std::cout << "IP de Origem: " << srcIp << std::endl;
                    std::cout << "IP de Destino: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
                    std::cout << "\nCamada de Transporte: TCP" << std::endl;
                    std::cout << "Porta de Origem: " << ntohs(tcpHeader->th_sport) << std::endl;
                    std::cout << "Porta de Destino: " << ntohs(tcpHeader->th_dport) << std::endl;
                    std::cout << "\nFlags: " << tcpHeader->th_flags << std::endl;
                    data = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr);
                    dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct tcphdr));
                    std::cout << "\nCamada de Aplicação: HTTP/HTTPS" << std::endl;
                    std::cout << "Dados (Hex): ";
                    for (int i = 0; i < dataLength; i++) {
                        printf("%02x ", data[i]);
                    }
                    std::cout << std::endl << "Dados (ASCII): ";
                    for (int i = 0; i < dataLength; i++) {
                        if (isprint(data[i])) {
                            std::cout << data[i];
                        } else {
                            std::cout << ".";
                        }
                    }
                    std::cout << std::endl;
                }
            } else if (ipHeader->ip_p == IPPROTO_UDP) {
                udpHeader = (struct udphdr*)(packet + sizeof(struct ether_header) + sizeof(struct ip));
                if (ntohs(udpHeader->uh_dport) == DNS_PORT) {
                    std::cout << "recebendo pacote..." << std::endl;
                    std:: cout << std::endl;
                    std::cout << "\nCamada Física e Enlace:" << std::endl;
                    std::cout << "MAC de Origem: " << srcMac << std::endl;
                    std::cout << "MAC de Destino: " << dstMac << std::endl;
                    std::cout << "\nCamada de Rede:" << std::endl;
                    std::cout << "Protocolo: IPv4" << std::endl;
                    std::cout << "IP de Origem: " << inet_ntoa(ipHeader->ip_src) << std::endl;
                    std::cout << "IP de Destino: " << inet_ntoa(ipHeader->ip_dst) << std::endl;
                    std::cout << "\nCamada de Transporte: UDP" << std::endl;
                    std::cout << "Porta de Origem: " << ntohs(udpHeader->uh_sport) << std::endl;
                    std::cout << "Porta de Destino: " << ntohs(udpHeader->uh_dport) << std::endl;
                    data = packet + sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr);
                    dataLength = pkthdr->len - (sizeof(struct ether_header) + sizeof(struct ip) + sizeof(struct udphdr));
                    std::cout << "\nCamada de Aplicação: DNS" << std::endl;
                    std::cout << "Dados: ";
                    for (int i = 0; i < dataLength; i++) {
                        std::cout << data[i];
                    }
                    std::cout << std::endl;
                }
            }
        }
    }
}