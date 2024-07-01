#include "header/header.h"


int main() {
 

    //inicia o programa
    std::cout << "Iniciando..." << std::endl;
    sleep(2);
    system("clear");
    listAllDevices();



    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *descr;
    struct bpf_program fp;

    // Abre a interface para captura
    descr = pcap_open_live("eth0", BUFSIZ, 1, 1000, errbuf);
    if (descr == nullptr) {
        std::cerr << "pcap_open_live() falhou: " << errbuf << std::endl;
        return 1;
    }

    // Compila e aplica o filtro
    if (pcap_compile(descr, &fp, "port 80 or port 443 or port 53", 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Erro ao compilar o filtro: " << pcap_geterr(descr) << std::endl;
        return 1;
    }

    if (pcap_setfilter(descr, &fp) == -1) {
        std::cerr << "Erro ao aplicar o filtro: " << pcap_geterr(descr) << std::endl;
        return 1;
    }

    // Captura os pacotes e chama o callback
    std::cout << "Aguardando pacotes...\n" << std::endl;
    pcap_loop(descr, 0, packetHandler, nullptr);

    pcap_close(descr);
    return 0;
}

