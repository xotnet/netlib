#ifndef NET_XOTNET_LIB_H
#define NET_XOTNET_LIB_H

#ifdef _WIN32
    #include <winsock2.h>
    #include <ws2tcpip.h>
#else
    #include <arpa/inet.h>
    #include <unistd.h>
#endif
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

// Based on RFC1035 nov 1987

enum options{setTCP=0x000F, setUDP=0x00F0, setIPv4=0x0F00, setIPv6=0xF000};
static void itos(int32_t N, char* str);

// RETURN VALUE
// int listener
// -1 TCP or UDP option not selected
// -2 can't create system socket
// -3 socket binding error
// -4 listener creation error
int32_t listen_net(const char* ip, const char* port, const int32_t opt) {
    #ifdef __WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
    #endif
    int family = AF_INET;
    if ((opt & setIPv6) == setIPv6) {family = AF_INET6;}
    int32_t listener;
    if ((setTCP & opt) == setTCP) {listener = socket(family, SOCK_STREAM, 0);}
    else if ((setUDP & opt) == setUDP) {listener = socket(family, SOCK_DGRAM, 0);}
    else {return -1;}
    if (listener == -1) {return -2;}
    int8_t enable = 1;
    setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*)&enable, sizeof(uint8_t));
    if ((opt & setIPv6) == setIPv6) { // v6
        struct sockaddr_in6 addr;
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(atoi(port));
        inet_pton(AF_INET6, ip, (void*)&addr.sin6_addr.s6_addr);
        addr.sin6_scope_id = 0;
        if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == -1) {return -3;}
    }
    else { // ipv4
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(port));
        inet_pton(AF_INET, ip, (void*)&addr.sin_addr.s_addr);
        if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == -1) {return -3;}
    }
    if (listen(listener, SOMAXCONN) == -1) {return -4;}
    return listener;
}

int32_t accept_net(int32_t listener) {
    return accept(listener, 0, 0);
}

// RETURN VALUE
// int connected socket
// -1 can't create system socket
// -2 connection interrupted
int32_t connect_net(const char* ip, const char* port, const int opt) {
    #ifdef __WIN32
        WSADATA wsa;
        WSAStartup(MAKEWORD(2,2), &wsa);
    #endif
    int family = AF_INET;
    if ((opt & setIPv6) == setIPv6) {family = AF_INET6;}
    int32_t conn = 0;
    if ((setTCP & opt) == setTCP) {conn = socket(family, SOCK_STREAM, 0);}
    else if ((setUDP & opt) == setUDP) {conn = socket(family, SOCK_DGRAM, 0);}
    if (conn == -1) {return -1;}
    if ((opt & setIPv6) == setIPv6) {
        struct sockaddr_in6 addr;
        addr.sin6_family = AF_INET6;
        addr.sin6_port = htons(atoi(port));
        inet_pton(AF_INET6, ip, (void*)&addr.sin6_addr.s6_addr);
        addr.sin6_scope_id = 0;
        if (connect(conn, (struct sockaddr*)&addr, sizeof(addr)) == -1) {return -2;}
    } else { // v4
        struct sockaddr_in addr;
        addr.sin_family = AF_INET;
        addr.sin_port = htons(atoi(port));
        addr.sin_addr.s_addr = inet_addr(ip);
        if (connect(conn, (struct sockaddr*)&addr, sizeof(addr)) == -1) {return -2;}
    }
    return conn;
}

int32_t send_net(int32_t socket, char* buf, uint32_t size) {
    #ifdef __WIN32
        return send(socket, buf, size, 0);
    #else
        return send(socket, buf, size, MSG_NOSIGNAL);
    #endif
}

int32_t recv_net(int32_t socket, char* buf, uint32_t size) {
    return recv(socket, buf, size, 0);
}

void getPeerIp_net(int32_t socket, char* ip) {
    struct sockaddr_storage addr;
    socklen_t addr_len = sizeof(addr);
    getpeername(socket, (struct sockaddr*)&addr, &addr_len);
    if (addr.ss_family == AF_INET) {
        struct sockaddr_in *addr_in = (struct sockaddr_in *)&addr;
        inet_ntop(AF_INET, &addr_in->sin_addr, ip, INET_ADDRSTRLEN);
    } else {
        struct sockaddr_in6 *addr_in6 = (struct sockaddr_in6 *)&addr;
        inet_ntop(AF_INET6, &addr_in6->sin6_addr, ip, INET6_ADDRSTRLEN);
    }
}

int32_t close_net(int32_t conn) {
    #ifdef __WIN32
        return closesocket(conn);
    #elif __linux__
        return close(conn);
    #endif
}

uint8_t socks5_connect(int32_t sock, const char *ip, uint16_t port) {
    char buf[64];
    buf[0] = 0x05;
    buf[1] = 0x01;
    buf[2] = 0x00;
    send_net(sock, buf, 3);
    recv_net(sock, buf, 2);
    if (buf[1] != 0x00) {
        return 1;
    }
    buf[0] = 0x05;
    buf[1] = 0x01;
    buf[2] = 0x00;
    buf[3] = 0x01;
    inet_pton(AF_INET, ip, &buf[4]);
    buf[8] = (port >> 8) & 0xFF;
    buf[9] = port & 0xFF;
    send_net(sock, buf, 10);
    recv_net(sock, buf, 10);
    if (buf[1] != 0x00) {
        return (unsigned short int)buf[1];
    }
    return 0;
}
#include <stdio.h>
char dnsIP[16] = "1.1.1.1";
enum dnsType {dnsANY, dnsA = 1, dnsNS, dnsMD, dnsMF, dnsCNAME, dnsSOA, dnsMB, dnsMG, dnsMR, dnsMX=15, dnsTXT=16, dnsRP, dnsAFSDB, dnsAAAA=28, dnsLOC, dnsSRV=33, dnsHTTPS=65, dnsSPF=99, dnsCAA=257};
int8_t resolve_net(char* domain, char* output, uint16_t nsType) {
    char buf[512];
    memset(buf, 0, 512); // HEADER
    buf[0] = 0xa3 ^ domain[0]; // 16 bit ID of DNS program
    buf[1] = 0x23 ^ domain[0];
    buf[2] = 0b00000001; // query | Recursion Available | 
    buf[5] = 0x01; // QDCOUNT

    uint8_t domainLen = strlen(domain); // RDATA LENGTH 16 bit
    char qname[domainLen+2]; // len byte + domain + 0x00
    uint8_t octetCounter = 0;
    for (int16_t i = domainLen-1; i>= 0; i--) { // RDATA
        if (domain[i] == '.') {
            qname[i+1] = 0x00 + octetCounter;
            octetCounter = 0;
            continue;
        }
        qname[i+1] = domain[i];
        octetCounter++;
    }
    qname[0] = 0x00 + octetCounter;
    qname[domainLen+1] = 0;
    strcpy(buf+12, qname);

    uint16_t typePos = 12+domainLen+2; // header + domain + octetCounter + \0
    buf[typePos] = (nsType >> 8) & 0xFF; // set type
    buf[typePos+1] = nsType & 0xFF;
    buf[typePos+3] = 0x01;
    int32_t conn = -1;
    uint8_t maxDnsServerReconnect = 2;
    for (uint8_t i = 0; i<maxDnsServerReconnect; ++i) { // x attempts
        conn = connect_net(dnsIP, "53", setUDP | setIPv4);
        
        // set recv timeout
        #ifdef _WIN32
        DWORD timeout = 1500; // milliseconds
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, (const char*)&timeout, sizeof timeout);
        #else
        struct timeval tv;
        tv.tv_sec = 1; // seconds
        tv.tv_usec = 500; // milliseconds
        setsockopt(conn, SOL_SOCKET, SO_RCVTIMEO, (const char*)&tv, sizeof tv);
        #endif

        send_net(conn, buf, typePos+4);
        memset(buf, 0, 512);
        if (recv_net(conn, buf, 512) < domainLen) { // net error while receiving a response
            if (i == 0) strcpy(output, "Net error");
            close_net(conn);
            if (i == maxDnsServerReconnect - 1) return -1;
        } else {
            break;
        }
    }
    uint16_t answerCount = (buf[6] << 8) | (buf[7]); // 4 and 5 bytes from HEADER
    if (answerCount == 0) { // no results
        strcpy(output, "No results");
        close_net(conn);
        return -2;
    }
    output[0] = 0;
    uint16_t answStart = 12 + domainLen + 2 + 4; // header(12) + QName + QTYPEQCLASS(4) | header + question
    for (uint8_t v = 0; v<answerCount; v++) {
        // answStart + 0  | 2b NAME pointer
        // answStart + 2  | 2b Dns type
        // answStart + 4  | 2b Class
        // answStart + 6  | 4b TTL
        // answStart + 10 | 2b RDATA len
        // answStart + 12 | xb RDATA
        uint16_t rdatalen = (buf[answStart+10] << 8) | (buf[answStart+11]);
        uint16_t outputLen = strlen(output);
        if (outputLen != 0) {output[outputLen] = ';'; outputLen++; output[outputLen] = 0;}
        if (nsType == dnsA) { // A
            if ((buf[answStart+2] << 8 | (buf[answStart+3]) == nsType)) {
                char ipbytes[5] = "";
                uint16_t ipIndex = answStart+12;
                ipbytes[0] = buf[ipIndex];
                ipbytes[1] = buf[ipIndex+1];
                ipbytes[2] = buf[ipIndex+2];
                ipbytes[3] = buf[ipIndex+3];
                inet_ntop(AF_INET, ipbytes, output+outputLen, INET_ADDRSTRLEN);
            }
        } else if (nsType == dnsMX) { // MX
            uint16_t outputInd = strlen(output);
            itos((buf[answStart+12] << 8) | (buf[answStart+13] & 0xFF), output+outputInd); // priority
            outputInd = strlen(output);
            output[outputInd] = ' ';
            outputInd++;
            uint8_t lblLen = buf[answStart+14];
            int32_t i=0;
            while(1) {
                for(uint8_t u = 0;u<lblLen;u++) {
                    output[outputInd+i] = buf[answStart+15+i];
                    i++;
                }
                lblLen = buf[answStart+15+i];
                if (lblLen == 0) {break;}
                output[outputInd+i] = '.';
                i++;
            }
            output[outputInd+i] = 0;
        } else if (nsType == dnsCAA) { // CAA
            itos(buf[answStart+12], output); // flags
            uint32_t outputInd = strlen(output);
            output[outputInd] = ' ';
            outputInd++;
            uint8_t tagSize = buf[answStart+13];
            for (uint8_t i=0;i<tagSize;i++) { // issue
                output[outputInd] = buf[answStart+14+i];
                outputInd++;
            }
            output[outputInd] = ' ';
            outputInd++;
            answStart += 14+tagSize;
            uint8_t lblLen = buf[answStart];
            int32_t i=0;
            while(1) {
                for(uint8_t u = 0;u<lblLen;u++) {
                    output[outputInd+i] = buf[answStart+i];
                    i++;
                }
                lblLen = buf[answStart+i];
                if (lblLen == 0) {break;}
                output[outputInd+i] = '.';
                i++;
            }
        } else if (nsType == dnsSRV) { // SRV
            itos((buf[answStart+12] << 8) | (buf[answStart+13] & 0xFF), output); // priority
            uint16_t outputInd = strlen(output);
            output[outputInd] = ' ';
            itos((buf[answStart+14] << 8) | (buf[answStart+15] & 0xFF), output+outputInd+1); // weight
            outputInd = strlen(output);
            output[outputInd] = ' ';
            itos((buf[answStart+16] << 8) | (buf[answStart+17] & 0xFF), output+outputInd+1); // port
            outputInd = strlen(output);
            output[outputInd] = ' ';
            outputInd++;
            uint8_t lblLen = buf[answStart+18];
            int32_t i=0;
            while(1) {
                for(uint8_t u = 0;u<lblLen;u++) {
                    output[outputInd+i] = buf[answStart+19+i];
                    i++;
                }
                lblLen = buf[answStart+19+i];
                if (lblLen == 0) {break;}
                output[outputInd+i] = '.';
                i++;
            }
        } else if (nsType == dnsCNAME) { // CNAME
            uint16_t outputInd = strlen(output);
            int i = 0, j = 0;
            while (buf[answStart+12+i] != 0) {
                int length = buf[answStart+12+i];
                i++;
                for (int k = 0; k < length; k++) {
                    output[outputInd+(j++)] = buf[answStart+12+(i++)];
                }
                output[outputInd+(j++)] = '.';
            }
            output[outputInd+j-1] = 0;
        } else { // TXT, CNAME...
            uint16_t e = 0;
            char rdata[rdatalen+1];
            for (; e<rdatalen; e++) {
                rdata[e] = buf[answStart+13+e];
            }
            rdata[rdatalen-1] = 0;
            strcpy(output+outputLen, rdata);
        }
        answStart += 12+rdatalen;
    }
    close_net(conn);
    return 0;
}

static void itos(int32_t N, char* str) {
    int32_t isNegative = 0;
    if (N < 0) {
        isNegative = 1;
        N = -N;
    }
    int32_t index = 0;
    do {
        str[index++] = (N % 10) + '0';
        N /= 10;
    } while (N > 0);
    if (isNegative) {
        str[index++] = '-';
    }
    str[index] = '\0';
    for (int32_t i = 0; i < index / 2; i++) {
        char temp = str[i];
        str[i] = str[index - i - 1];
        str[index - i - 1] = temp;
    }
}

#endif