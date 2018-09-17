#include "socketUtils.h"

//Create a RAW socket, set interface to promiscuous mode, get the interface MAC and IP Address
//Returns int(1) if operation was a success
//The argument char* argv[1] shall contain the interface name to be used
//All socket related information is returned by the socket_data pointer
int socketSetup(char* ifNameArg, socketAux_t* socket_data)
{
	int result = 1;	//Operation result: 1 = success
	struct ifreq if_idx, if_mac, ifopts, if_ip;	//struct used for interface related system calls
	char ifName[IFNAMSIZ];

	/* Get interface name */
	if ((ifNameArg == NULL) || (strlen(ifNameArg) == 0))
		strcpy(ifName, DEFAULT_IF);
	else
		strcpy(ifName, ifNameArg);

	/* Open RAW socket */
	if ((socket_data->sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		result = -1;
		perror("Fail to open socket (SOCK_RAW)");
	}
		
	//Continue only if previous operation was completed with success
	if(result == 1)
	{
		/* Set interface to promiscuous mode */
		strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
		if(ioctl(socket_data->sockfd, SIOCGIFFLAGS, &ifopts) < 0)
		{
			result = -2;
			perror("Fail to get interface data (SIOCGIFFLAGS)");
            shutdown(socket_data->sockfd, 2);   //Stop both reception and transmission of the socket
		}
		else
		{
			ifopts.ifr_flags |= IFF_PROMISC;
			if(ioctl(socket_data->sockfd, SIOCSIFFLAGS, &ifopts) < 0)
			{
				result = -3;
				perror("Fail to set interface to promiscuous mode (SIOCSIFFLAGS)");
                shutdown(socket_data->sockfd, 2);   //Stop both reception and transmission of the socket
			}		
		}
		
	}

	//Continue only if previous operation was completed with success
	if(result == 1)
	{
		/* Get the index of the interface */
		memset(&if_idx, 0, sizeof(struct ifreq));
		strncpy(if_idx.ifr_name, ifName, IFNAMSIZ-1);
		if (ioctl(socket_data->sockfd, SIOCGIFINDEX, &if_idx) < 0)
		{
			result = -4;
			perror("Fail to get the interface index (SIOCGIFINDEX)");
            shutdown(socket_data->sockfd, 2);   //Stop both reception and transmission of the socket
		}
		socket_data->socket_address.sll_ifindex = if_idx.ifr_ifindex;
		socket_data->socket_address.sll_halen = ETH_ALEN;
	}


	//Continue only if previous operation was completed with success
	if(result == 1)
	{
		/* Get the MAC address of the interface */
		memset(&if_mac, 0, sizeof(struct ifreq));
		strncpy(if_mac.ifr_name, ifName, IFNAMSIZ-1);
		if (ioctl(socket_data->sockfd, SIOCGIFHWADDR, &if_mac) < 0)
		{
			result = -5;
			perror("Fail to get the interface MAC Address (SIOCGIFHWADDR)");	
            shutdown(socket_data->sockfd, 2);   //Stop both reception and transmission of the socket
		}
		//Copy the MAC address to the sockaddr member
		memcpy(socket_data->this_mac, if_mac.ifr_hwaddr.sa_data, ETH_ALEN);
	}

	//Continue only if previous operation was completed with success
	if(result == 1)
	{
		/* Get the IPV4 address of the interface */
		memset(&if_ip, 0, sizeof(struct ifreq));
		strncpy(if_ip.ifr_name, ifName, IFNAMSIZ-1);
		if (ioctl(socket_data->sockfd, SIOCGIFADDR, &if_ip) < 0)
		{
			result = -6;
			perror("Fail to get the interface IP Address (SIOCGIFADDR)");	
            shutdown(socket_data->sockfd, 2);   //Stop both reception and transmission of the socket
		}
		//Copy the IP address to the sockaddr member
		struct sockaddr_in* ipaddr = (struct sockaddr_in*)&if_ip.ifr_addr;
		memcpy(socket_data->this_ip, (uint8_t*)&ipaddr->sin_addr, IPV4_LEN);
	}

	return result;
}

//Create a RAW socket and set interface to promiscuous mode.
//Useful for simple server applications that waits to receive a packet
int socketSetupSimpleServer(char* ifNameArg)
{
	int result = 1;	//Operation result: 1 = success
	int sockfd = -1;		//Socket file descriptor
	struct ifreq ifopts;	//struct used for interface related system calls
	char ifName[IFNAMSIZ];

	/* Get interface name */
	if ((ifNameArg == NULL) || (strlen(ifNameArg) == 0))
		strcpy(ifName, DEFAULT_IF);
	else
		strcpy(ifName, ifNameArg);	


	/* Open RAW socket */
	if ((sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL))) == -1)
	{
		result = -1;
		perror("Fail to open socket (SOCK_RAW)");
	}
		
	//Continue only if previous operation was completed with success
	if(result == 1)
	{
		/* Set interface to promiscuous mode */
		strncpy(ifopts.ifr_name, ifName, IFNAMSIZ-1);
		if(ioctl(sockfd, SIOCGIFFLAGS, &ifopts) < 0)
		{
			result = -2;
			perror("Fail to get interface data (SIOCGIFFLAGS)");
            shutdown(sockfd, 2);   //Stop both reception and transmission of the socket
		}
		else
		{
			ifopts.ifr_flags |= IFF_PROMISC;
			if(ioctl(sockfd, SIOCSIFFLAGS, &ifopts) < 0)
			{
				result = -3;
				perror("Fail to set interface to promiscuous mode (SIOCSIFFLAGS)");
                shutdown(sockfd, 2);   //Stop both reception and transmission of the socket
			}		
		}
	}

	
	if (result == 1) 
	{
		//Success: return socket file descriptor
		return sockfd;
	}
	else
	{
		//Fail during socket setup
		return result;
	}
	
}


//Calculate IP Header checksum
//NOTE: Checksum must be calculaed with initial value of zero
//E.G.: ip.sum = 0; ipHdrChksum((uint8_t*) &ip);
uint16_t ipHdrChksum(uint8_t* packet)
{
	uint32_t sum=0;
	uint16_t i;

	for(i = 0; i < 20; i += 2)
		sum += ((uint32_t)packet[i] << 8) | (uint32_t)packet[i + 1];
	while (sum & 0xffff0000)
		sum = (sum & 0xffff) + (sum >> 16);

	sum = ~sum;
	sum = sum & 0xffff;
	sum = htons(sum);
	return (uint16_t)sum;
}