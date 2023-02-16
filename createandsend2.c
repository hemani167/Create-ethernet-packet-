#include<stdio.h>
#include<stdlib.h>
#include<sys/socket.h>
#include<features.h>
#include<linux/if_packet.h>
#include<linux/if_ether.h>
#include<errno.h>
#include<sys/ioctl.h>
#include<net/if.h>
#include<net/ethernet.h>
#include<string.h>
#include<sys/socket.h>
#include <sys/types.h>


#include<unistd.h>
#include<arpa/inet.h> 
#include<ctype.h>
#define SRC_ETHER_ADDR  "00:1b:21:8f:1f:0c"
#define DST_ETHER_ADDR	"00:1b:21:8f:1f:0d"

int string_to_mac(const char *str, unsigned char *mac)
{
    int i;
    unsigned int x;

    for (i = 0; i < 6; i++) {
        if (sscanf(str + i * 3, "%02x", &x) != 1)
            return -1;
        mac[i] = x;
        if (i < 5 && str[i * 3 + 2] != ':')
            return -1;
    }

    return 0;
}

int CreateRawSocket(int protocol_to_sniff)
{
	int rawsock;

	if((rawsock = socket(PF_PACKET, SOCK_RAW, htons(protocol_to_sniff)))== -1)
	{
		perror("Error creating raw socket: ");
		exit(-1);
	}

	return rawsock;
}

int BindRawSocketToInterface(char *device, int rawsock, int protocol)
{
	
	struct sockaddr_ll sll;
	struct ifreq ifr;

	bzero(&sll, sizeof(sll));
	bzero(&ifr, sizeof(ifr));
	
	/* First Get the Interface Index  */


	strncpy((char *)ifr.ifr_name, device, IFNAMSIZ);
	if((ioctl(rawsock, SIOCGIFINDEX, &ifr)) == -1)
	{
		printf("Error getting Interface index !\n");
		exit(-1);
	}

	/* Bind our raw socket to this interface */

	sll.sll_family = AF_PACKET;
	sll.sll_ifindex = ifr.ifr_ifindex;
	sll.sll_protocol = htons(protocol); 


	if((bind(rawsock, (struct sockaddr *)&sll, sizeof(sll)))== -1)
	{
		perror("Error binding raw socket to interface\n");
		exit(-1);
	}

	return 1;
	
}


int SendRawPacket(int rawsock, unsigned char *pkt, int pkt_len)
{
	int sent= 0;
	printf("Packet len: %d\n", pkt_len);
	/* A simple write on the socket ..thats all it takes ! */

	if((sent = write(rawsock, pkt, pkt_len)) ==-1)
	{
		/* Error */
		printf("Could only send %d bytes of packet of length %d\n", sent, pkt_len);
		return 0;
	}

	return 1;
	

}

unsigned char* CreateEthernetHeader(char *src_mac, char *dst_mac, int protocol, 
                                     unsigned char *data, int data_len, 
                                     int *header_len) {
  unsigned char *packet;
  struct ether_header *eth_header;

  *header_len = sizeof(struct ether_header) + data_len;
  packet = (unsigned char*) malloc(*header_len);
  if (packet == NULL) {
    return NULL;
  }

  eth_header = (struct ether_header *) packet;

  sscanf(dst_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
         &eth_header->ether_dhost[0], &eth_header->ether_dhost[1],
         &eth_header->ether_dhost[2], &eth_header->ether_dhost[3],
         &eth_header->ether_dhost[4], &eth_header->ether_dhost[5]);
  sscanf(src_mac, "%hhx:%hhx:%hhx:%hhx:%hhx:%hhx",
         &eth_header->ether_shost[0], &eth_header->ether_shost[1],
         &eth_header->ether_shost[2], &eth_header->ether_shost[3],
         &eth_header->ether_shost[4], &eth_header->ether_shost[5]);
  eth_header->ether_type = htons(protocol);

  memcpy(packet + sizeof(struct ether_header), data, data_len);
  //printf("size of packet: %d \n",strlen(packet));
  //strcpy(packet+14,data);
  printf("Ethernet packet:\n");
  for (int i = 0; i < *header_len; i++) {
    printf("%02x ", packet[i]);
  }

  return packet;
}



/* argv[1] is the device e.g. eth0    */
 
int main()
{

	int raw;
	unsigned char *packet;
	int ethhdr_len;

	/* Create the raw socket */

	raw = CreateRawSocket(ETH_P_ALL);
   printf("Socket created\n");

	/* Bind raw socket to interface */

	BindRawSocketToInterface("enp96s0f0", raw, ETH_P_ALL);
   printf("Binded\n");
	/* create Ethernet header */
  unsigned char* data="**HEMANI BHARADWAJ**";
  //ethhdr_len = sizeof(struct ether_header);
  int header_len;
	packet = CreateEthernetHeader(SRC_ETHER_ADDR, DST_ETHER_ADDR, ETH_P_ARP , data ,sizeof(data),&header_len);
  printf("\nEthernet injected\n");
	

  //int *header_len = sizeof(struct ether_header) + data_len;
	if(!SendRawPacket(raw, packet, header_len))
	{
		perror("Error sending packet");
	}
	else
		printf("Packet sent successfully\n");

	/* Free the ethernet_header back to the heavenly heap */

	//free(packet);

	close(raw);

	return 0;
}