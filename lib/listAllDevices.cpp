#include "./../header/header.h"


void listAllDevices() {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_if_t *alldevs;
    pcap_if_t *device;
    
    // Obtém a lista de interfaces de rede disponíveis
    if (pcap_findalldevs(&alldevs, errbuf) == -1) {
        std::cerr << "Erro ao encontrar dispositivos: " << errbuf << std::endl;
        return;
    }
    
    std::cout << "Dispositivos disponíveis:" << std::endl;
    for (device = alldevs; device; device = device->next) {
        std::cout << device->name;
        if (device->description)
            std::cout << " (" << device->description << ")";
        std::cout << std::endl;
    }
    
    pcap_freealldevs(alldevs);
}