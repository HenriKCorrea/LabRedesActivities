#if !defined(SOCKETUTILS_HH)
#define SOCKETUTILS_HH

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <net/if.h>
#include <netinet/ether.h>

#define DEFAULT_IF	"eth0"
#define IPV4_LEN	4

//Auxiliary struct that holds essential information to send / receive data using sockets
typedef struct  {
	int sockfd;                         	//Holds the file descritor of the created socket
	struct sockaddr_ll socket_address;  
	uint8_t this_mac[6];                   	//Current PC MAC Address
	uint8_t this_ip[4];						//Current PC IP Address
}socketAux_t;

//Create a RAW socket, set interface to promiscuous mode, get the interface MAC and IP Address
//Returns int(1) if operation was a success
//The argument char* argv[1] shall contain the interface name to be used
//All socket related information is returned by the socket_data pointer
int socketSetup(char* ifNameArg, socketAux_t* socket_data);

//Create a RAW socket and set interface to promiscuous mode.
//Useful for simple server applications that waits to receive a packet
int socketSetupSimpleServer(char* ifNameArg);

//Calculate IP Header checksum
//NOTE: Checksum must be calculaed with initial value of zero
//E.G.: ip.sum = 0; ipHdrChksum((uint8_t*) &ip);
uint16_t ipHdrChksum(uint8_t* packet);

#endif // SOCKETUTILS_HH
