#include "./../header/header.h"

// Função para converter um nome de domínio de rótulos DNS para uma string legível
std::string dnsLabelToString(const unsigned char* dnsName) {
    std::string name;
    int i = 0, j;
    while (dnsName[i] != 0) {
        if (i != 0) {
            name += ".";
        }
        int labelLength = dnsName[i];
        for (j = 0; j < labelLength; j++) {
            name += dnsName[i + j + 1];
        }
        i += labelLength + 1;
    }
    return name;
}