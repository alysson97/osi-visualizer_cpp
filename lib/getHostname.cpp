#include "../header/header.h"

// Função para obter o hostname a partir do endereço IP
std::string getHostname(const char* ip) {
    struct sockaddr_in sa;
    char host[1024];
    char service[20];

    sa.sin_family = AF_INET;
    sa.sin_addr.s_addr = inet_addr(ip);

    if (getnameinfo((struct sockaddr*)&sa, sizeof(sa), host, sizeof(host), service, sizeof(service), 0) != 0) {
        return std::string("Hostname não encontrado");
    }

    return std::string(host);
}