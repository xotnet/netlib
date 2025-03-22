#ifdef __WIN32
	#include <winsock2.h>
	#include <ws2tcpip.h>
#else
	#include <arpa/inet.h>
	#include <unistd.h>
#endif
#include <string.h>
#include <stdint.h>
#include <stdlib.h>

void itos(int32_t N, char* str);

int32_t listen_net(const char* ip, const char* port, const uint8_t protocol /* 0 - TCP | 1 - UDP*/ ) {
	#ifdef __WIN32
		WSADATA wsa;
		WSAStartup(MAKEWORD(2,2), &wsa);
	#endif
	int32_t listener = 0;
	if (protocol == 0) {listener = socket(AF_INET, SOCK_STREAM, 0);}
	else if (protocol == 1) {listener = socket(AF_INET, SOCK_DGRAM, 0);}
	else {return -1;}
	const int8_t enable = 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*)&enable, sizeof(uint8_t));
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));
	addr.sin_addr.s_addr = atoi(ip);
	bind(listener, (struct sockaddr*)&addr, sizeof(addr));
	listen(listener, SOMAXCONN);
	return listener;
}

int32_t accept_net(int32_t listener) {
	return accept(listener, 0, 0);
}

int32_t connect_net(const char* ip, const char* port, const uint8_t protocol /* 0 - TCP | 1 - UDP*/ ) {
	#ifdef __WIN32
		WSADATA wsa;
		WSAStartup(MAKEWORD(2,2), &wsa);
	#endif
	int32_t conn = 0;
	if (protocol == 0) {conn = socket(AF_INET, SOCK_STREAM, 0);}
	else if (protocol == 1) {conn = socket(AF_INET, SOCK_DGRAM, 0);}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));
	addr.sin_addr.s_addr = inet_addr(ip);
	if (connect(conn, (struct sockaddr*)&addr, sizeof(addr)) < 0) {return -1;}
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
	struct sockaddr_in client_addr;
	socklen_t addr_len = sizeof(client_addr);
	getpeername(socket, (struct sockaddr *)&client_addr, &addr_len);
	strcpy(ip, inet_ntoa(client_addr.sin_addr));
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
char dnsIP[16] = "1.1.1.1";
enum dnsType {dnsANY, dnsA = 1, dnsNS, dnsMD, dnsMF, dnsCNAME, dnsSOA, dnsMB, dnsMG, dnsMR, dnsMX, dnsTXT=16, dnsRP, dnsAFSDB, dnsAAAA=28, dnsLOC, dnsSRV=33, dnsHTTPS=65, dnsSPF=99, dnsCAA=257};
void resolve_net(char* domain, char* output, uint16_t nsType) {
	int32_t conn = connect_net(dnsIP, "53", 1);
	char buf[128];
	memset(buf, 0, 128);
	buf[0] = 0x12;
	buf[2] = 0x01;
    buf[5] = 0x01;
    uint16_t nameLen = strlen(domain);
    char domainCpy[nameLen+1];
    uint8_t lblLen = 0;
    for (uint16_t nameLenCpy = nameLen; nameLenCpy != 0; nameLenCpy--) {
		if (*(domain+nameLenCpy-1) == '.') {
			domainCpy[nameLenCpy] = 0x00 + lblLen;
			lblLen = 0;
			continue;
		}
		domainCpy[nameLenCpy] = domain[nameLenCpy-1];
		lblLen++;
    }
    domainCpy[0] = 0x00 + lblLen;
    strcpy(buf+12, domainCpy);
    uint16_t pos = nameLen + 13;
    buf[pos] = 0x00;
    buf[pos+1] = (unsigned char)(nsType >> 8);
    buf[pos+2] = (unsigned char)(nsType & 0xFF);
    buf[pos+3] = 0x00;
    buf[pos+4] = 0x01;
    send_net(conn, buf, pos+5);
    memset(buf, 0, 128);
    if (recv_net(conn, buf, 128) < 32) {strcpy(output, "dnsErr: netErr"); return;}
    if ((buf[6] << 8) + buf[7] == 0) {strcpy(output, "Err: No records"); return;}
    uint16_t answer_start = 12 + strlen(buf+12) + 5 + 12;
	if (nsType == dnsA) {
		char ipbytes[4];
		strcpy(ipbytes, buf+answer_start);
		inet_ntop(AF_INET, ipbytes, output, 15);
	} else if (nsType == dnsCAA) {
		itos(buf[answer_start], output);
		uint8_t outputLen = strlen(output);
		*(output+outputLen) = ' ';
		strcpy(output+outputLen+1, buf+answer_start+2);
		*(output+outputLen+6) = ' ';
		strcpy(output+outputLen+7, buf+answer_start+7);
	} else if (nsType == dnsSRV) {
		itos((*(buf+answer_start) << 8) | (*(buf+answer_start+1) & 0xFF), output);
		uint8_t p = 2;
		uint8_t l;
		for (uint8_t i = 1; i<3; i++) {
			l = strlen(output);
			*(output+l) = ' ';
			itos((*(buf+answer_start+p) << 8) | (*(buf+answer_start+p+1) & 0xFF), output+l+1);
			p = p+2;
		}
		l = strlen(output);
		*(output+l) = ' ';
		l++;
		while (*(buf+answer_start+p) != 0) {
			uint8_t labelLen = *(buf+answer_start+p);
			p++;
			for (uint8_t g = 0; g<=labelLen; g++) {
				*(output+l) = *(buf+answer_start+p);
				p++;
				l++;
			}
			*(output+l-1) = '.';
			p--;
		}
		*(output+l-1) = 0;
	} else {
	    uint8_t labelLen = 0;
	    int16_t p = -1;
	    while (1) {
	    	labelLen = buf[answer_start];
		    if (labelLen == 0) {break;}
	        answer_start++;
	        p++;
	        for (uint8_t i = 0; i<labelLen; i++) {
	            *(output+p) = buf[answer_start+i];
	        	p++;
		    }
		    answer_start = answer_start + labelLen;
		    if (buf[answer_start] != 0) {*(output+p) = '.';}
		}
    }
    close_net(conn);
}

void itos(int32_t N, char* str) {
    int16_t i = 0;
    int32_t sign = N;
    if (N < 0)
        N = -N;
    while (N > 0) {
        str[i++] = N % 10 + '0';
      	N /= 10;
    } 
    if (sign < 0) {
        str[i++] = '-';
    }
    str[i] = '\0';
    for (int32_t j = 0, k = i - 1; j < k; j++, k--) {
        char temp = str[j];
        str[j] = str[k];
        str[k] = temp;
    }
}
