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

void itos(int32_t N, char* str);

// RETURN VALUE
// int listener
// -1 TCP or UDP option not selected
// -2 can't create system socket
// -3 socket binding error
// -4 listener creation error
int32_t listen_net(const char* ip, const char* port, const uint8_t protocol /* 0 - TCP | 1 - UDP*/ ) {
	#ifdef __WIN32
		WSADATA wsa;
		WSAStartup(MAKEWORD(2,2), &wsa);
	#endif
	int32_t listener;
	if (protocol == 0) {listener = socket(AF_INET, SOCK_STREAM, 0);}
	else if (protocol == 1) {listener = socket(AF_INET, SOCK_DGRAM, 0);}
	else {return -1;}
	if (listener == -1) {return -2;}
	int8_t enable = 1;
	setsockopt(listener, SOL_SOCKET, SO_REUSEADDR, (char*)&enable, sizeof(uint8_t));
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));
	addr.sin_addr.s_addr = atoi(ip);
	if (bind(listener, (struct sockaddr*)&addr, sizeof(addr)) == -1) {return -3;}
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
int32_t connect_net(const char* ip, const char* port, const uint8_t protocol /* 0 - TCP | 1 - UDP*/ ) {
	#ifdef __WIN32
		WSADATA wsa;
		WSAStartup(MAKEWORD(2,2), &wsa);
	#endif
	int32_t conn = 0;
	if (protocol == 0) {conn = socket(AF_INET, SOCK_STREAM, 0);}
	else if (protocol == 1) {conn = socket(AF_INET, SOCK_DGRAM, 0);}
	if (conn == -1) {return -1;}
	struct sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(atoi(port));
	addr.sin_addr.s_addr = inet_addr(ip);
	if (connect(conn, (struct sockaddr*)&addr, sizeof(addr)) == -1) {return -2;}
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
int8_t resolve_net(char* domain, char* output, uint16_t nsType) {
	int32_t conn = connect_net(dnsIP, "53", 1);
	char buf[512];
	memset(buf, 0, 512);
	buf[0] = 0xa3 ^ domain[0];
	buf[1] = 0x23 ^ domain[0];
	buf[2] = 0x01; // get request
	buf[5] = 0x01; // QDCOUNT

	uint8_t domainLen = strlen(domain);
	char qname[domainLen+2]; // len byte + domain + 0x00
	uint8_t octetCounter = 0;
	for (int16_t i = domainLen-1; i>= 0; i--) {
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

	uint8_t typePos = 12+domainLen+2; // header + domain + octetCounter + \0
	buf[typePos] = (unsigned char)(nsType >> 8);
	buf[typePos+1] = (unsigned char)(nsType & 0xFF);
	//buf[typePos+2] = 0x00;
	buf[typePos+3] = 0x01;
    send_net(conn, buf, typePos+4);
    memset(buf, 0, 512);
    if (recv_net(conn, buf, 512) < domainLen) { // net error
    	strcpy(output, "Net error");
    	return -1;
	}
    uint16_t answerCount = (buf[6] << 8) | (buf[7]);
    if (answerCount == 0) { // no results
    	strcpy(output, "No results");
    	return -2;
	}
	uint16_t answStart = 12 + domainLen+2 + 4; // header(12) + QName + QTYPEQCLASS(4)
    for (uint8_t i = 0; i<answerCount; i++) {
    	// answStart + 0  | 2b NAME pointer
    	// answStart + 2  | 2b Dns type
    	// answStart + 4  | 2b Class
    	// answStart + 6  | 4b TTL
    	// answStart + 10 | 2b RDATA len
    	// answStart + 12 | xb RDATA
    	uint16_t rdatalen = (buf[answStart+10] << 8) | (buf[answStart+11]) - 1;
    	uint16_t outputLen = strlen(output);
    	uint8_t addSpace = 0;
    	if (outputLen != 0) {addSpace = 1;}
    	if (nsType == dnsA) { // A
    		char ipbytes[4];
    		strcpy(ipbytes, buf+answStart+12);
    		inet_ntop(AF_INET, ipbytes, output+outputLen+addSpace, 15);
    	} else if (nsType == dnsCAA) { // CAA

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
    		// xxxx2eu3com3org0
    		outputInd++;
    		uint8_t lblLen = buf[answStart+18];
		    int i=0;
		    while(1) {
		    	for(int u = 0;u<lblLen;u++) {
		    		output[outputInd+i] = buf[answStart+19+i];
		    		i++;
		    	}
		    	lblLen = buf[answStart+19+i];
		    	if (lblLen == 0) {break;}
		    	output[outputInd+i] = '.';
		    	i++;
		    }
    	} else { // TXT, CNAME...
    		uint16_t e = 0;
	    	for (; e<rdatalen; e++) {
				char rdata[rdatalen];
				rdata[e] = buf[answStart+13+e];
				strcpy(output+outputLen+addSpace, rdata);
	    	}
	    	output[e] = 0;
    	}
    	answStart = answStart+rdatalen+12;
    	i++;
    }
    close_net(conn);
    return 0;
}

void itos(int32_t N, char* str) {
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