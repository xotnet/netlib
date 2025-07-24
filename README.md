C/C++ multiplatform network(TCP/UDP) lib for server and client

[Download library header](https://github.com/xotnet/NetLib/releases/latest/download/net.c)

## FUNCTIONS

**listen_net**(char* ip, char* port, int options)
> int server = listen_net("0.0.0.0", "1234", setTCP | setIPv4) - Create a TCP listener at 0.0.0.0:1234 

**accept_net**(listener)
> int client = accept_net(server)

**connect_net**(char* ip, char* port, int options)
> int socket = connect_net("1.1.1.1", "53", setUDP | setIPv4) - UDP connect to 1.1.1.1:53

**send_net**(int socket, char* buf, int bufSize)
> int sentBytes = send_net(socket, "Hello!", 6)

**recv_net**(int socket, char* buf, int bufSize)
> int receivedBytes = recv_net(socket, recvBuf, 1024)

**getPeerIp_net**(int socket, char* ip)
> getPeerIp_net(socket, ip) - get the socket IP and write to the ip(15 bytes)

**close_net(int socket)**
> close_net(socket) - close this socket

**socks5_connect**(int socket, char* destinationIP, int destinationPort)
> socks5_connect(socks5Socket, "1.1.1.1", "443") - connect to 1.1.1.1:443 through socks5 socket

**resolve_net**(char* domain, char* output, int nsType)
> resolve_net("srv.slowdns.org", output, dnsSRV) - get srv record srv.slowdns.org and write to the output(128 bytes)

>Avaiable nsTypes - dnsANY(only if the type is not known!), dnsA, dnsNS, dnsMD, dnsMF, dnsCNAME, dnsSOA, dnsMB, dnsMG, dnsMR, dnsMX, dnsTXT, dnsRP, dnsAFSDB, dnsAAAA, dnsLOC, dnsSRV, dnsHTTPS, dnsSPF, dnsCAA

>Avaiable options - setTCP, setUDP, setIPv4, setIPv6
