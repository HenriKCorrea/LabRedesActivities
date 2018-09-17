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
#include "raw.h"

#include "socketUtils.h"

#define PROTO_UDP	17
#define DST_PORT	7

//Create echo packet based on received packet from the client
//Returns (1) if operation was a success
int buildEchoPacket(const union eth_buffer* packet_in, union eth_buffer* packet_out, const socketAux_t* socketData)
{
	int result = 1; //procedure status

	//Check if received packet is valid
	if ((packet_in->cooked_data.ethernet.eth_type == ntohs(ETH_P_IP)) && 
		(memcmp((const void*)packet_in->cooked_data.ethernet.dst_addr, (const void*)socketData->this_mac, ETH_ALEN) == 0) &&
		(packet_in->cooked_data.payload.ip.proto == PROTO_UDP) && 
		(memcmp(packet_in->cooked_data.payload.ip.dst, socketData->this_ip, IPV4_LEN) == 0) &&
		(packet_in->cooked_data.payload.udp.udphdr.dst_port == ntohs(DST_PORT)))
	{
		//Copy all content
		memcpy(packet_out->raw_data, packet_in->raw_data, sizeof(packet_out->raw_data));	

		////Swap source / dest information
		//Ethernet header
		memcpy(packet_out->cooked_data.ethernet.dst_addr, packet_in->cooked_data.ethernet.src_addr, ETH_ALEN);
		memcpy(packet_out->cooked_data.ethernet.src_addr, packet_in->cooked_data.ethernet.dst_addr, ETH_ALEN);

		//IP Header
		memcpy(packet_out->cooked_data.payload.ip.dst, packet_in->cooked_data.payload.ip.src, IPV4_LEN);
		memcpy(packet_out->cooked_data.payload.ip.src, packet_in->cooked_data.payload.ip.dst, IPV4_LEN);
		if (packet_out->cooked_data.payload.ip.sum != 0) 
		{
			packet_out->cooked_data.payload.ip.sum = 0;
			packet_out->cooked_data.payload.ip.sum = ipHdrChksum((uint8_t*)&packet_out->cooked_data.payload.ip);
		}
		
		//UDP Header
		packet_out->cooked_data.payload.udp.udphdr.dst_port = packet_in->cooked_data.payload.udp.udphdr.src_port;
		packet_out->cooked_data.payload.udp.udphdr.src_port = packet_in->cooked_data.payload.udp.udphdr.dst_port;
		packet_out->cooked_data.payload.udp.udphdr.udp_chksum = 0;	//TODO: Calculate UDP checksum
	}
	else
	{
		//Fail during packet validation
		result = -1;
	}

	return result;
}

void printHelp(char* programName)
{
	printf("Usage: %s <interface_name>\n", programName);
	printf("Default server_port is 7\n");
}

int main(int argc, char *argv[])
{
	int result = 1;	//Operation return status
	socketAux_t socketData;	//All necessary information to send / receive sockets	
	

	//Check if number of arguments are correct
	if ((argc != 2))
	{
		printHelp(argv[0]);
		result = -1;
	}

	/* Open RAW socket */
	if (result == 1) 
	{
		result = socketSetup(argv[1], &socketData);
	}

	/* End of socket configuration. */
	if (result == 1) 
	{
		union eth_buffer packet_in;		//Received packet from clients
		union eth_buffer packet_out;	//Echo packet to clients
		int numbytes;					//Received packet number of bytes

		//Listen clients
		while (1){
			//Receive packet
			numbytes = recvfrom(socketData.sockfd, packet_in.raw_data, ETH_LEN, 0, NULL, NULL);

			if ((numbytes > 0) &&
				(buildEchoPacket(&packet_in, &packet_out, &socketData) == 1)) 
			{
				//Send echo packet
				memcpy(socketData.socket_address.sll_addr, packet_out.cooked_data.ethernet.dst_addr, ETH_ALEN);
				sendto(socketData.sockfd, packet_out.raw_data, numbytes, 0, (struct sockaddr*)&socketData.socket_address, sizeof(struct sockaddr_ll));
			}
		}

		shutdown(socketData.sockfd, 2);   //Stop both reception and transmission of the socket
	}

	return result;
}
