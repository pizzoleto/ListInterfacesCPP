#include <stdio.h>
#include <iostream>
#include <fstream>

#include "pcap.h"

#ifndef WIN32
#include <sys/socket.h>
#include <netinet/in.h>
#else
#include <winsock.h>
#endif

#include "Packet32.h"
#include <ntddndis.h>

#include <windows.h>





typedef struct ip_address {
	u_char byte1;
	u_char byte2;
	u_char byte3;
	u_char byte4;
}ip_address;

/* IPv4 header */
typedef struct ip_header {
	u_char  ver_ihl;        // Version (4 bits) + Internet header length (4 bits)
	u_char  tos;            // Type of service 
	u_short tlen;           // Total length 
	u_short identification; // Identification
	u_short flags_fo;       // Flags (3 bits) + Fragment offset (13 bits)
	u_char  ttl;            // Time to live
	u_char  proto;          // Protocol
	u_short crc;            // Header checksum
	ip_address  saddr;      // Source address
	ip_address  daddr;      // Destination address
	u_int   op_pad;         // Option + Padding
}ip_header;

/* UDP header*/
typedef struct udp_header {
	u_short sport;          // Source port
	u_short dport;          // Destination port
	u_short len;            // Datagram length
	u_short crc;            // Checksum
}udp_header;

using namespace std;

// Function prototypes
void ifprint(pcap_if_t *d);
char *iptos(u_long in);
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen);

//#define PCAP_SRC_IF_STRING "rpcap://"

int main()
{
  		pcap_if_t *alldevs, *alldevsp, *temp;
		//int i = 0;
		pcap_if_t *d;
		char errbuf[PCAP_ERRBUF_SIZE + 1];
		char source[PCAP_ERRBUF_SIZE + 1];

		int res;
	
		struct tm ltime;
		char timestr[16];
		struct pcap_pkthdr *header;
		const u_char *pkt_data;
		time_t local_tv_sec;

		pcap_t *adhandle;

		ip_header *ih;
		udp_header *uh;
		u_int ip_len;
		u_short sport, dport;
	 

		LPADAPTER  lpAdapter = 0;
		//define a pointer to a PACKET structure

		LPPACKET   lpPacket;

		int        i;
		DWORD      dwErrorCode;

		//ascii strings
		char		AdapterName[8192]; // string that contains a list of the network adapters
		char		 *temp1;

		// printf("Packet.dll test application. Library version:%s\n", PacketGetVersion());


		if (pcap_findalldevs_ex((char*)"rpcap://", NULL, &alldevs, errbuf) == -1) //PCAP_SRC_IF_STRING

		{
			fprintf(stderr, "Error in pcap_findalldevs: %s\n", errbuf);
			exit(1);
		}

		/* Scan the list printing every entry */
		for (d = alldevs; d; d = d->next)
		{
			ifprint(d);
		}

		pcap_freealldevs(alldevs);


		for (d = alldevs, i = 0; i < 5; d = d->next, i++);

		/* Open the device */
		if ((adhandle = pcap_open(d->name,          // name of the device
			65536,            // portion of the packet to capture. 
							  // 65536 guarantees that the whole packet will be captured on all the link layers
			PCAP_OPENFLAG_PROMISCUOUS,    // promiscuous mode
			1000,             // read timeout
			NULL,             // authentication on the remote machine
			errbuf            // error buffer
		)) == NULL)
		{
			fprintf(stderr, "\nUnable to open the adapter. %s is not supported by WinPcap\n", d->name);
			/* Free the device list */
			pcap_freealldevs(alldevs);
			return -1;
		}

		ofstream outfile;
		outfile.open("afile.txt");
		char ipOrigen[] = { '0','0','0','0' };
		//int ipString = "";
		 

		/* Retrieve the packets */
		while ((res = pcap_next_ex(adhandle, &header, &pkt_data)) >= 0) {

			if (res == 0)
				/* Timeout elapsed */
				continue;

			/* convert the timestamp to readable format */
			
			local_tv_sec = header->ts.tv_sec;
			localtime_s(&ltime, &local_tv_sec);
			strftime(timestr, sizeof timestr, "%H:%M:%S", &ltime);
			ih = (ip_header *)(pkt_data +
				14); //length of ethernet header



			//string ipOrigen = ih->saddr.byte1 + ih->saddr.byte2 + ih->saddr.byte3 + ih->saddr.byte4;

			//printf("%s,%s,%.6d len:%d\n", ih->saddr.byte1, timestr, header->ts.tv_usec, header->len);

			printf("%s: %d.%d.%d.%d -->  %d.%d.%d.%d  - ", timestr,
				ih->saddr.byte1, ih->saddr.byte2, ih->saddr.byte3, ih->saddr.byte4, ih->daddr.byte1, ih->daddr.byte2, ih->daddr.byte3, ih->daddr.byte4 );
			
				ipOrigen[0] = ih->saddr.byte1;
			ipOrigen[1] = ih->saddr.byte2;
			ipOrigen[2] = ih->saddr.byte3;
			ipOrigen[3] = ih->saddr.byte4;

			//std::int32_t s(1, ih->saddr.byte1);

			outfile << "IP Origen: " << (int)ih->saddr.byte1 << "." << (int)ih->saddr.byte2 << "." << (int)ih->saddr.byte3 << "." << (int)ih->saddr.byte4 << 
				"IP Destino: " << (int)ih->daddr.byte1 << "." << (int)ih->daddr.byte2 << "." << (int)ih->daddr.byte3 << "." << (int)ih->daddr.byte4 <<
				endl;
			std::cout << "\n";

			

		}

		if (res == -1) {
			printf("Error reading the packets: %s\n", pcap_geterr(adhandle));
			return -1;
		}


		std::cout << "\n";
		system("pause");
		

		return 0;
	}

string convertToString(char* a, int size)
	{
		int i;
		string s = "";
		for (i = 0; i < size; i++) {
			s = s + a[i];
		}
		return s;
	}

/* Print all the available information on the given interface */
void ifprint(pcap_if_t *d)
{
	pcap_addr_t *a;
	char ip6str[128];

	/* Name */
	printf("%s\n", d->name);

	/* Description */
	if (d->description)
		printf("\tDescription: %s\n", d->description);

	/* Loopback Address*/
	printf("\tLoopback: %s\n", (d->flags & PCAP_IF_LOOPBACK) ? "yes" : "no");

	/* IP addresses */
	for (a = d->addresses; a; a = a->next) {
		printf("\tAddress Family: #%d\n", a->addr->sa_family);

		switch (a->addr->sa_family)
		{
		case AF_INET:
			printf("\tAddress Family Name: AF_INET\n");
			if (a->addr)
				printf("\tAddress: %s\n", iptos(((struct sockaddr_in *)a->addr)->sin_addr.s_addr));
			if (a->netmask)
				printf("\tNetmask: %s\n", iptos(((struct sockaddr_in *)a->netmask)->sin_addr.s_addr));
			if (a->broadaddr)
				printf("\tBroadcast Address: %s\n", iptos(((struct sockaddr_in *)a->broadaddr)->sin_addr.s_addr));
			if (a->dstaddr)
				printf("\tDestination Address: %s\n", iptos(((struct sockaddr_in *)a->dstaddr)->sin_addr.s_addr));
			break;

		/*case AF_INET6:
			printf("\tAddress Family Name: AF_INET6\n");
			if (a->addr)
				printf("\tAddress: %s\n", ip6tos(a->addr, ip6str, sizeof(ip6str)));
			break; */

		default:
			printf("\tAddress Family Name: Unknown\n");
			break;
		}
	}
	printf("\n");
}



/* From tcptraceroute, convert a numeric IP address to a string */
#define IPTOSBUFFERS	12
char *iptos(u_long in)
{
	static char output[IPTOSBUFFERS][3 * 4 + 3 + 1];
	static short which;
	u_char *p;

	p = (u_char *)&in;
	which = (which + 1 == IPTOSBUFFERS ? 0 : which + 1);
	_snprintf_s(output[which], sizeof(output[which]), sizeof(output[which]), "%d.%d.%d.%d", p[0], p[1], p[2], p[3]);
	return output[which];
}

/*
char* ip6tos(struct sockaddr *sockaddr, char *address, int addrlen)
{
	socklen_t sockaddrlen;

#ifdef WIN32
	sockaddrlen = sizeof(struct sockaddr_in6);
#else
	sockaddrlen = sizeof(struct sockaddr_storage);
#endif


	if (getnameinfo(sockaddr,
		sockaddrlen,
		address,
		addrlen,
		NULL,
		0,
		NI_NUMERICHOST) != 0) address = NULL;

	return address;
}

*/

