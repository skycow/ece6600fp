#include "frameio.h"
#include "util.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <pthread.h>
#include "checksum.h"
#include <map>
#include <queue>
#include <iostream>
#include <string>
#include <time.h>

frameio net;             // gives us access to the raw network
message_queue ip_queue;  // message queue for the IP protocol stack
message_queue arp_queue; // message queue for the ARP protocol stack

octet curr_ip = 10;
const char * adap_name = "enp3s0";
// const char * adap_name = "eth0";

std::map<int, octet *> cache;

struct ether_frame       // handy template for 802.3/DIX frames
{
  	octet dst_mac[6];     // destination MAC address
  	octet src_mac[6];     // source MAC address
  	octet prot[2];        // protocol (or length)
  	octet data[1500];     // payload
};

struct arp_payload
{
  	octet hardwaretype[2];
  	octet protocoltype[2];
  	octet hal;
  	octet pal;
  	octet opcode[2];
  	octet sha[6];
  	octet sip[4];
  	octet tha[6];
  	octet tip[4];
};

struct cache_info
{
  	octet mac[6];
  	octet ip[4];
};

//
// This thread sits around and receives frames from the network.
// When it gets one, it dispatches it to the proper protocol stack.
//
void *protocol_loop(void *arg)
{
  	ether_frame buf;
  	while(1)
  	{
    	int n = net.recv_frame(&buf,sizeof(buf));
    	if ( n < 42 ) continue; // bad frame!
    	switch ( buf.prot[0]<<8 | buf.prot[1] )
    	{
      		case 0x800:
        		ip_queue.send(PACKET,&buf,n);
        		break;
      		case 0x806:
        		arp_queue.send(PACKET,&buf,n);
        		break;
    	}
  	}
}

//
// To handle IP packets
//
void *ip_protocol_loop(void *arg)
{
  	ether_frame buf;
  	event_kind event;
  	int timer_no = 1;
  	cache_info temp;
  	int n = 0;
    unsigned int length;
  
  	while(1)
  	{
    	ip_queue.recv(&event,&buf,sizeof(buf));
    	if(buf.data[9] == 0x11 && buf.data[23] == 0x07)
    		{
      		printf("*** UDP-Echo request received ***\n");
          length = (buf.data[2] << 8) + buf.data[3];
        	ether_frame fake;
          while(length >= 1500){
          memcpy(fake.dst_mac, buf.src_mac, sizeof(buf.src_mac));
          memcpy(fake.src_mac, net.get_mac(), sizeof(net.get_mac()));
          fake.prot[0] = buf.prot[0];
          fake.prot[1] = buf.prot[1];
          fake.data[0] = buf.data[0]; // IP Version (4) & IP Header Length (5)
          fake.data[1] = buf.data[1]; // Type of Service
          fake.data[2] = buf.data[2]; // Total Length (byte0)
          fake.data[3] = buf.data[3]; // Total Length (byte1)
          fake.data[4] = buf.data[4]; // ID >> 8; // ID (b0)
          fake.data[5] = buf.data[5]; // ID & 0xff; // ID (b1)
          // unsigned int frag = 0x2000 + frag_off;
          // frag_off++;
          fake.data[6] = buf.data[6]; // frag >> 8; // F & Fragment (b0.5)
          fake.data[7] = buf.data[7]; // frag & 0xff; // Fragment (b1)
          fake.data[8] = buf.data[8]; // 0x40; // Time to Live
          fake.data[9] = buf.data[9]; // 0x11; // Protocol
          fake.data[10] = 0x0; // Header checksum (b0) - initialized as 0
          fake.data[11] = 0x0; // Header checksum (b1)
          fake.data[12] = 192; // Source IP
          fake.data[13] = 168;
          fake.data[14] = 1;
          fake.data[15] = curr_ip;
          fake.data[16] = buf.data[12]; // userReq[0]; // Destination IP
          fake.data[17] = buf.data[13]; // userReq[1];
          fake.data[18] = buf.data[14]; // userReq[2];
          fake.data[19] = buf.data[15]; // userReq[3];
          int sum = checksum(&fake.data[0], 20, 0);
          fake.data[10] = ~sum >> 8; // Header checksum (b0)
          fake.data[11] = ~sum & 0xff; // Header checksum (b1)
          fake.data[20] = buf.data[22]; // 0x0; // UDP Header - Source Port Number (b0)
          fake.data[21] = buf.data[23]; // 0x7; // UDP Header - Source Port Number (b1)
          fake.data[22] = buf.data[20]; // 0x0; // UDP Header - Destination Port Number (b0)
          fake.data[23] = buf.data[21]; // 0x7; // UDP Header - Destination Port Number (b1)
          fake.data[24] = buf.data[24]; // 0x05; // UDP Header - UDP message length (b0)
          fake.data[25] = buf.data[25]; // 0xc0; // UDP Header - UDP message length (b1)
          fake.data[26] = 0x00; // UDP Header - checksum (b0) - initialized as 0
          fake.data[27] = 0x00; // UDP Header - checksum (b1)
          for (int i = 28; i < (length-28); i++) // Data
            fake.data[i] = buf.data[i]; // 0x0;
          /*fake.data[28] = 0x0; // Data
          fake.data[29] = 0x0;
          fake.data[30] = 0x0;
          fake.data[31] = 0x0;
          fake.data[32] = 0x0;
          fake.data[33] = 0x0;
          fake.data[34] = 0x0;
          fake.data[35] = 0x0;*/
          sum = checksum(&fake.data[20], length-28, 0);
          fake.data[26] = ~sum >> 8; // Header checksum (b0)
          fake.data[27] = ~sum & 0xff; // Header checksum (b1)

          printf("Ethernet header (source mac): %02x.%02x.%02x.%02x.%02x.%02x = %d.%d.%d.%d.%d.%d\n",
            buf.src_mac[0], buf.src_mac[1], buf.src_mac[2], buf.src_mac[3], buf.src_mac[4], buf.src_mac[5],
            buf.src_mac[0], buf.src_mac[1], buf.src_mac[2], buf.src_mac[3], buf.src_mac[4], buf.src_mac[5]);
          printf("IP header (source IP): %02x.%02x.%02x.%02x = %d.%d.%d.%d\n",
            buf.data[12], buf.data[13], buf.data[14], buf.data[15],
            buf.data[12], buf.data[13], buf.data[14], buf.data[15]);
          printf("ID: 0x%04x (%d)\n",(fake.data[4] << 8)+fake.data[5],(fake.data[4] << 8)+fake.data[5]);
          printf("Frag: 0x%04x (%d)\n",(fake.data[6] << 8)+fake.data[7],(fake.data[6] << 8)+fake.data[7]);
          printf("Length: 0x%04x (%d)\n", length, length);
          printf("Length in packet: 0x%02x%02x (%d%d)\n", buf.data[2], buf.data[3], buf.data[2], buf.data[3]);
          /*printf("Data: ");
            for(int i = 28; i < 1500; i++)
              printf("%02x ",fake.data[i]);*/
            printf("*********************************\n\n");

          // Send UDP reply
            net.send_frame(&fake, 1514);
            // sleep(3);
            length -= 1500;
            /*for (int i = 1; i < 4; i ++)
            {
              fake.data[27] = i;
              fake.data[22] = 0x0; // ICMP Header - checksum (b0) - initialized as 0
              fake.data[23] = 0x0; // ICMP Header - checksum (b1)
              sum = checksum(&fake.data[20], 35, 0);
              fake.data[22] = ~sum >> 8; // Header checksum (b0)
              fake.data[23] = ~sum & 0xff; // Header checksum (b1)
              net.send_frame(&fake, 98);
              sleep(3);
            }*/
        }
      if(length > 0 && length < 1500){
        // IP-MAC pair is located in the cache - Form packet and send ARP reply
          memcpy(fake.dst_mac, buf.src_mac, sizeof(buf.src_mac));
          memcpy(fake.src_mac, net.get_mac(), sizeof(net.get_mac()));
          fake.prot[0] = buf.prot[0];
          fake.prot[1] = buf.prot[1];
          fake.data[0] = buf.data[0]; // IP Version (4) & IP Header Length (5)
          fake.data[1] = buf.data[1]; // Type of Service
          fake.data[2] = buf.data[2]; // Total Length (byte0)
          fake.data[3] = buf.data[3]; // Total Length (byte1)
          fake.data[4] = buf.data[4]; // ID >> 8; // ID (b0)
          fake.data[5] = buf.data[5]; // ID & 0xff; // ID (b1)
          // unsigned int frag = 0x2000 + frag_off;
          // frag_off++;
          fake.data[6] = buf.data[6]; // frag >> 8; // F & Fragment (b0.5)
          fake.data[7] = buf.data[7]; // frag & 0xff; // Fragment (b1)
          fake.data[8] = buf.data[8]; // 0x40; // Time to Live
          fake.data[9] = buf.data[9]; // 0x11; // Protocol
          fake.data[10] = 0x0; // Header checksum (b0) - initialized as 0
          fake.data[11] = 0x0; // Header checksum (b1)
          fake.data[12] = 192; // Source IP
          fake.data[13] = 168;
          fake.data[14] = 1;
          fake.data[15] = curr_ip;
          fake.data[16] = buf.data[12]; // userReq[0]; // Destination IP
          fake.data[17] = buf.data[13]; // userReq[1];
          fake.data[18] = buf.data[14]; // userReq[2];
          fake.data[19] = buf.data[15]; // userReq[3];
          int sum = checksum(&fake.data[0], 20, 0);
          fake.data[10] = ~sum >> 8; // Header checksum (b0)
          fake.data[11] = ~sum & 0xff; // Header checksum (b1)
          fake.data[20] = buf.data[22]; // 0x0; // UDP Header - Source Port Number (b0)
          fake.data[21] = buf.data[23]; // 0x7; // UDP Header - Source Port Number (b1)
          fake.data[22] = buf.data[20]; // 0x0; // UDP Header - Destination Port Number (b0)
          fake.data[23] = buf.data[21]; // 0x7; // UDP Header - Destination Port Number (b1)
          fake.data[24] = buf.data[24]; // 0x05; // UDP Header - UDP message length (b0)
          fake.data[25] = buf.data[25]; // 0xc0; // UDP Header - UDP message length (b1)
          fake.data[26] = 0x00; // UDP Header - checksum (b0) - initialized as 0
          fake.data[27] = 0x00; // UDP Header - checksum (b1)
          for (int i = 28; i < (length-28); i++) // Data
            fake.data[i] = buf.data[i]; // 0x0;
          /*fake.data[28] = 0x0; // Data
          fake.data[29] = 0x0;
          fake.data[30] = 0x0;
          fake.data[31] = 0x0;
          fake.data[32] = 0x0;
          fake.data[33] = 0x0;
          fake.data[34] = 0x0;
          fake.data[35] = 0x0;*/
          sum = checksum(&fake.data[20], length-28, 0);
          fake.data[26] = ~sum >> 8; // Header checksum (b0)
          fake.data[27] = ~sum & 0xff; // Header checksum (b1)

          printf("Ethernet header (source mac): %02x.%02x.%02x.%02x.%02x.%02x = %d.%d.%d.%d.%d.%d\n",
            buf.src_mac[0], buf.src_mac[1], buf.src_mac[2], buf.src_mac[3], buf.src_mac[4], buf.src_mac[5],
            buf.src_mac[0], buf.src_mac[1], buf.src_mac[2], buf.src_mac[3], buf.src_mac[4], buf.src_mac[5]);
          printf("IP header (source IP): %02x.%02x.%02x.%02x = %d.%d.%d.%d\n",
            buf.data[12], buf.data[13], buf.data[14], buf.data[15],
            buf.data[12], buf.data[13], buf.data[14], buf.data[15]);
          printf("ID: 0x%04x (%d)\n",(fake.data[4] << 8)+fake.data[5],(fake.data[4] << 8)+fake.data[5]);
          printf("Frag: 0x%04x (%d)\n",(fake.data[6] << 8)+fake.data[7],(fake.data[6] << 8)+fake.data[7]);
          printf("Length: 0x%04x (%d)\n", length, length);
          printf("Length in packet: 0x%02x%02x (%d%d)\n", buf.data[2], buf.data[3], buf.data[2], buf.data[3]);
          /*printf("Data: ");
            for(int i = 28; i < 1500; i++)
              printf("%02x ",fake.data[i]);*/
            printf("*********************************\n\n");

          // Send UDP reply
            net.send_frame(&fake, length);
            // sleep(3);
            /*for (int i = 1; i < 4; i ++)
            {
              fake.data[27] = i;
              fake.data[22] = 0x0; // ICMP Header - checksum (b0) - initialized as 0
              fake.data[23] = 0x0; // ICMP Header - checksum (b1)
              sum = checksum(&fake.data[20], 35, 0);
              fake.data[22] = ~sum >> 8; // Header checksum (b0)
              fake.data[23] = ~sum & 0xff; // Header checksum (b1)
              net.send_frame(&fake, 98);
              sleep(3);
            }*/
        }
      		// IP-MAC pair is located in the cache - Form packet and send ARP reply
          	/*memcpy(fake.dst_mac, buf.src_mac, sizeof(buf.src_mac));
          	memcpy(fake.src_mac, net.get_mac(), sizeof(net.get_mac()));
          	fake.prot[0] = 0x08;
          	fake.prot[1] = 0x00;
          	fake.data[0] = 0x45; // IP Version (4) & IP Header Length (5)
          	fake.data[1] = 0x00; // Type of Service
          	fake.data[2] = 0x00; // Total Length (byte0)
          	fake.data[3] = 0x54; // Total Length (byte1)
          	fake.data[4] = buf.data[4]; // ID (b0)
          	fake.data[5] = buf.data[5]; // ID (b1)
          	fake.data[6] = 0x40; // F & Fragment (b0.5)
          	fake.data[7] = 0x0; // Fragment (b1)
          	fake.data[8] = buf.data[8]; // Time to Live
          	fake.data[9] = buf.data[9]; // Protocol
          	fake.data[10] = 0x0; // Header checksum (b0) - initialized as 0
          	fake.data[11] = 0x0; // Header checksum (b1)
          	fake.data[12] = 192; // Source IP
          	fake.data[13] = 168;
          	fake.data[14] = 1;
          	fake.data[15] = curr_ip;
          	fake.data[16] = buf.data[12]; // Destination IP
          	fake.data[17] = buf.data[13];
          	fake.data[18] = buf.data[14];
          	fake.data[19] = buf.data[15];
          	int sum = checksum(&fake.data[0], 20, 0);
          	fake.data[10] = ~sum >> 8; // Header checksum (b0)
          	fake.data[11] = ~sum & 0xff; // Header checksum (b1)
          	fake.data[20] = 0x0; // ICMP Header - Type - ICMP Request - 8, Reply - 0
          	fake.data[21] = 0x0; // ICMP Header - Code - 0
          	fake.data[22] = 0x0; // ICMP Header - checksum (b0) - initialized as 0
          	fake.data[23] = 0x0; // ICMP Header - checksum (b1)
          	fake.data[24] = buf.data[24]; // ICMP Header - ID (b0)
          	fake.data[25] = buf.data[25]; // ICMP Header - ID (b1)
          	fake.data[26] = buf.data[26]; // ICMP Header - Sequence (b0)
          	fake.data[27] = buf.data[27]; // ICMP Header - Sequence (b1)
          	fake.data[28] = buf.data[28]; // Time Stamp
          	fake.data[29] = buf.data[29];
          	fake.data[30] = buf.data[30];
          	fake.data[31] = buf.data[31];
          	fake.data[32] = buf.data[32];
          	fake.data[33] = buf.data[33];
          	fake.data[34] = buf.data[34];
          	fake.data[35] = buf.data[35];
          	memcpy(&fake.data[36], &buf.data[36], 48); // Data
          	sum = checksum(&fake.data[20], 35, 0);
          	fake.data[22] = ~sum >> 8; // Header checksum (b0)
          	fake.data[23] = ~sum & 0xff; // Header checksum (b1)

          	printf("Ethernet header (destination mac): %02x.%02x.%02x.%02x.%02x.%02x = %d.%d.%d.%d.%d.%d\n",
            	fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5],
            	fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5]);
          	printf("IP header (destination IP): %02x.%02x.%02x.%02x = %d.%d.%d.%d\n",
            	buf.data[12], buf.data[13], buf.data[14], buf.data[15],
            	buf.data[12], buf.data[13], buf.data[14], buf.data[15]);
          	printf("Data: ");
          	for(int i = 28; i < 84; i++)
            	printf("%02x ",fake.data[i]);
          	printf(" = ");
          	for(int i = 28; i < 84; i++)
            	printf("%c",fake.data[i]);
          	printf("\n**************************\n\n");
          	// Send ICMP reply
          	net.send_frame(&fake, 98);*/
        }
    }
}

//
// Function to handle ARP packets
//
void *arp_protocol_loop(void *arg)
{
	ether_frame buf;
	event_kind event;
	cache_info temp;
	ether_frame sending;
	arp_payload tosend;
	while (1) // always
	{
    	arp_queue.recv(&event, &buf, sizeof(buf));
		if(buf.data[7] == 1){ // If ARP request...
    		memcpy(sending.dst_mac, buf.src_mac, sizeof(buf.src_mac));
    		memcpy(sending.src_mac, net.get_mac(), sizeof(net.get_mac()));
    		memcpy(sending.prot, buf.prot, sizeof(buf.prot));
    		tosend.hardwaretype[0] = 0x00;
    		tosend.hardwaretype[1] = 0x01;
    		tosend.protocoltype[0] = 0x08;
    		tosend.protocoltype[1] = 0x00;
    		tosend.hal = 0x6;
    		tosend.pal = 0x4;
    		tosend.opcode[0] = 0x0;
    		tosend.opcode[1] = 0x2;
    		memcpy(tosend.sha, net.get_mac(), sizeof(net.get_mac()));
    		tosend.sip[0] = 192;
    		tosend.sip[1] = 168;
    		tosend.sip[2] = 1;
    		tosend.sip[3] = curr_ip;
    		memcpy(tosend.tha, buf.src_mac, sizeof(buf.src_mac));
    		memcpy(tosend.tip, &buf.data[14], 4);
    		memcpy(&sending.data, &tosend, 28);
    		int flag = 0;
    		for(int i = 0; i < 4; i++)
        		flag += (buf.data[24+i] - tosend.sip[i]);
      		if(flag == 0)
        		int n = net.send_frame(&sending, 42);
    	}
    	cache_info temp;
    	memcpy(temp.mac, &buf.data[8], 6);
    	memcpy(temp.ip, &buf.data[14], 4);
    	unsigned int ipint = (temp.ip[0] << 24) + (temp.ip[1] << 16) + (temp.ip[2] << 8) + temp.ip[3];
    	if(cache.find(ipint) == cache.end())
    	{
      		cache[ipint] = new octet;
      		memcpy(cache[ipint], temp.mac, sizeof(temp.mac));
    	}
  	}
}

// Waits for input from the user.  Either prints off stored IP-MAC pairs or pings desired IP address.
void *main_protocol_loop(void *arg)
{
  	while(1){
    	char input;
    	unsigned int userReq[4];
      unsigned int length;
    	printf("Enter desired IP address: ");
      	std::cin >> userReq[0];
      	std::cin >> userReq[1];
      	std::cin >> userReq[2];
      	std::cin >> userReq[3];

      printf("Enter desired length of UDP packet (header + data): ");
        std::cin >> length;

      	unsigned int concatd = (userReq[0] << 24) + (userReq[1] << 16) + (userReq[2] << 8) + userReq[3];
	
		// check if target IP is in the lab
      	if (userReq[0] == 192 && userReq[1] == 168 && userReq[2] == 1)
      	{
        	printf("\n**************************\n");
		    printf("Target IP is in the lab...\n");
    	}
		else 
		{
        	printf("\n**************************\n");
		    printf("Target IP is NOT in the lab...\n");
		    concatd = (192 << 24) + (168 << 16) + (001 << 8) + 001;
		}
        srand(time(NULL));
        unsigned int ID = rand()%0x10000;
      	ether_frame fake;
        unsigned int frag_off = 0x0;
      	// IP-MAC pair is located in the cache - Form packet and send ARP reply
      	if(cache.find(concatd) != cache.end()){
          while(length >= 1500){
        	memcpy(fake.dst_mac, cache[concatd], sizeof(cache[concatd]));
        	memcpy(fake.src_mac, net.get_mac(), sizeof(net.get_mac()));
        	fake.prot[0] = 0x08;
        	fake.prot[1] = 0x00;
        	fake.data[0] = 0x45; // IP Version (4) & IP Header Length (5)
        	fake.data[1] = 0x00; // Type of Service
        	fake.data[2] = 0x05; // Total Length (byte0)
        	fake.data[3] = 0xdc; // Total Length (byte1)
        	fake.data[4] = ID >> 8; // ID (b0)
        	fake.data[5] = ID & 0xff; // ID (b1)
          unsigned int frag = 0x2000 + frag_off;
          frag_off++;
        	fake.data[6] = frag >> 8; // F & Fragment (b0.5)
        	fake.data[7] = frag & 0xff; // Fragment (b1)
        	fake.data[8] = 0x40; // Time to Live
        	fake.data[9] = 0x11; // Protocol
        	fake.data[10] = 0x0; // Header checksum (b0) - initialized as 0
        	fake.data[11] = 0x0; // Header checksum (b1)
        	fake.data[12] = 192; // Source IP
        	fake.data[13] = 168;
        	fake.data[14] = 1;
        	fake.data[15] = curr_ip;
        	fake.data[16] = userReq[0]; // Destination IP
        	fake.data[17] = userReq[1];
        	fake.data[18] = userReq[2];
        	fake.data[19] = userReq[3];
        	int sum = checksum(&fake.data[0], 20, 0);
        	fake.data[10] = ~sum >> 8; // Header checksum (b0)
        	fake.data[11] = ~sum & 0xff; // Header checksum (b1)
        	fake.data[20] = 0x0; // UDP Header - Source Port Number (b0)
        	fake.data[21] = 0x4; // UDP Header - Source Port Number (b1)
        	fake.data[22] = 0x0; // UDP Header - Destination Port Number (b0)
        	fake.data[23] = 0x7; // UDP Header - Destination Port Number (b1)
        	fake.data[24] = 0x05; // UDP Header - UDP message length (b0)
        	fake.data[25] = 0xc0; // UDP Header - UDP message length (b1)
        	fake.data[26] = 0x00; // UDP Header - checksum (b0) - initialized as 0
        	fake.data[27] = 0x00; // UDP Header - checksum (b1)
          for (int i = 28; i < 1500; i++) // Data
            fake.data[i] = 0x0;
          /*fake.data[28] = 0x0; // Data
        	fake.data[29] = 0x0;
        	fake.data[30] = 0x0;
        	fake.data[31] = 0x0;
        	fake.data[32] = 0x0;
        	fake.data[33] = 0x0;
        	fake.data[34] = 0x0;
        	fake.data[35] = 0x0;*/
        	sum = checksum(&fake.data[20], 1471, 0);
        	fake.data[26] = ~sum >> 8; // Header checksum (b0)
        	fake.data[27] = ~sum & 0xff; // Header checksum (b1)

        	printf("Ethernet header (destination mac): %02x.%02x.%02x.%02x.%02x.%02x = %d.%d.%d.%d.%d.%d\n",
        		fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5],
        		fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5]);
        	printf("IP header (destination IP): %02x.%02x.%02x.%02x = %d.%d.%d.%d\n",
        		userReq[0], userReq[1], userReq[2], userReq[3],
        		userReq[0], userReq[1], userReq[2], userReq[3]);
          printf("ID: 0x%04x (%d)\n",(fake.data[4] << 8)+fake.data[5],(fake.data[4] << 8)+fake.data[5]);
          printf("Frag: 0x%04x (%d)\n",(fake.data[6] << 8)+fake.data[7],(fake.data[6] << 8)+fake.data[7]);
        	/*printf("Data: ");
          	for(int i = 28; i < 1500; i++)
            	printf("%02x ",fake.data[i]);*/
          	printf("**************************\n\n");

        	// Send UDP reply
            net.send_frame(&fake, 1500);
            // sleep(3);
            length -= 1500;
          	/*for (int i = 1; i < 4; i ++)
          	{
            	fake.data[27] = i;
            	fake.data[22] = 0x0; // ICMP Header - checksum (b0) - initialized as 0
            	fake.data[23] = 0x0; // ICMP Header - checksum (b1)
            	sum = checksum(&fake.data[20], 35, 0);
            	fake.data[22] = ~sum >> 8; // Header checksum (b0)
            	fake.data[23] = ~sum & 0xff; // Header checksum (b1)
        	  	net.send_frame(&fake, 98);
            	sleep(3);
          	}*/
      	}
      if(length < 1500){
        // IP-MAC pair is located in the cache - Form packet and send ARP reply
          memcpy(fake.dst_mac, cache[concatd], sizeof(cache[concatd]));
          memcpy(fake.src_mac, net.get_mac(), sizeof(net.get_mac()));
          fake.prot[0] = 0x08;
          fake.prot[1] = 0x00;
          fake.data[0] = 0x45; // IP Version (4) & IP Header Length (5)
          fake.data[1] = 0x00; // Type of Service
          fake.data[2] = length >> 8;; // Total Length (byte0)
          fake.data[3] = length & 0xff; // Total Length (byte1)
          fake.data[4] = ID >> 8; // ID (b0)
          fake.data[5] = ID & 0xff; // ID (b1)
          unsigned int frag = 0x0000 + frag_off;
          frag_off++;
          fake.data[6] = frag >> 8; // F & Fragment (b0.5)
          fake.data[7] = frag & 0xff; // Fragment (b1)
          fake.data[8] = 0x40; // Time to Live
          fake.data[9] = 0x11; // Protocol
          fake.data[10] = 0x0; // Header checksum (b0) - initialized as 0
          fake.data[11] = 0x0; // Header checksum (b1)
          fake.data[12] = 192; // Source IP
          fake.data[13] = 168;
          fake.data[14] = 1;
          fake.data[15] = curr_ip;
          fake.data[16] = userReq[0]; // Destination IP
          fake.data[17] = userReq[1];
          fake.data[18] = userReq[2];
          fake.data[19] = userReq[3];
          int sum = checksum(&fake.data[0], 20, 0);
          fake.data[10] = ~sum >> 8; // Header checksum (b0)
          fake.data[11] = ~sum & 0xff; // Header checksum (b1)
          fake.data[20] = 0x0; // UDP Header - Source Port Number (b0)
          fake.data[21] = 0x4; // UDP Header - Source Port Number (b1)
          fake.data[22] = 0x0; // UDP Header - Destination Port Number (b0)
          fake.data[23] = 0x7; // UDP Header - Destination Port Number (b1)
          fake.data[24] = length >> 8; // UDP Header - UDP message length (b0)
          fake.data[25] = (length - 28) & 0xff; // UDP Header - UDP message length (b1)
          fake.data[26] = 0x00; // UDP Header - checksum (b0) - initialized as 0
          fake.data[27] = 0x00; // UDP Header - checksum (b1)
          for (int i = 28; i < length; i++) // Data
            fake.data[i] = 0x0;
          /*fake.data[28] = 0x0; // Data
          fake.data[29] = 0x0;
          fake.data[30] = 0x0;
          fake.data[31] = 0x0;
          fake.data[32] = 0x0;
          fake.data[33] = 0x0;
          fake.data[34] = 0x0;
          fake.data[35] = 0x0;*/
          sum = checksum(&fake.data[20], length-28, 0);
          fake.data[26] = ~sum >> 8; // Header checksum (b0)
          fake.data[27] = ~sum & 0xff; // Header checksum (b1)

          printf("Ethernet header (destination mac): %02x.%02x.%02x.%02x.%02x.%02x = %d.%d.%d.%d.%d.%d\n",
            fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5],
            fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5]);
          printf("IP header (destination IP): %02x.%02x.%02x.%02x = %d.%d.%d.%d\n",
            userReq[0], userReq[1], userReq[2], userReq[3],
            userReq[0], userReq[1], userReq[2], userReq[3]);
          printf("ID: 0x%04x (%d)\n",(fake.data[4] << 8)+fake.data[5],(fake.data[4] << 8)+fake.data[5]);
          printf("Frag: 0x%04x (%d)\n",(fake.data[6] << 8)+fake.data[7],(fake.data[6] << 8)+fake.data[7]);
          /*printf("Data: ");
            for(int i = 28; i < length; i++)
              printf("%02x ",fake.data[i]);*/
            printf("**************************\n\n");

          // Send UDP reply
            net.send_frame(&fake, length);
            // sleep(3);
            /*for (int i = 1; i < 4; i ++)
            {
              fake.data[27] = i;
              fake.data[22] = 0x0; // ICMP Header - checksum (b0) - initialized as 0
              fake.data[23] = 0x0; // ICMP Header - checksum (b1)
              sum = checksum(&fake.data[20], 35, 0);
              fake.data[22] = ~sum >> 8; // Header checksum (b0)
              fake.data[23] = ~sum & 0xff; // Header checksum (b1)
              net.send_frame(&fake, 98);
              sleep(3);
            }*/
        }
      }

      		// IP-MAC pair is not found in the cache - Form packet and send ARP request to desired IP address to obtain MAC address
      	if(cache.find(concatd) == cache.end()){
        	fake.dst_mac[0] = 0xff;
        	fake.dst_mac[1] = 0xff;
        	fake.dst_mac[2] = 0xff;
        	fake.dst_mac[3] = 0xff;
        	fake.dst_mac[4] = 0xff;
        	fake.dst_mac[5] = 0xff;

        	memcpy(fake.src_mac, net.get_mac(), sizeof(net.get_mac()));
        	fake.prot[0] = 0x08;
        	fake.prot[1] = 0x06;
        	fake.data[0] = 0x00;
        	fake.data[1] = 0x01;
        	fake.data[2] = 0x08;
        	fake.data[3] = 0x00;
        	fake.data[4] = 0x6;
        	fake.data[5] = 0x4;
        	fake.data[6] = 0x0;
        	fake.data[7] = 0x1;
        	memcpy(&fake.data[8], net.get_mac(), sizeof(net.get_mac()));
        	fake.data[14] = 192;
        	fake.data[15] = 168;
        	fake.data[16] = 1;
        	fake.data[17] = curr_ip;          
        	fake.data[18] = 0x00;
        	fake.data[19] = 0x00;
        	fake.data[20] = 0x00;
        	fake.data[21] = 0x00;
        	fake.data[22] = 0x00;
        	fake.data[23] = 0x00;
        	fake.data[24] = userReq[0];
        	fake.data[25] = userReq[1];
        	fake.data[26] = userReq[2];
        	fake.data[27] = userReq[3];

        	// Send ARP Request
        	int n = net.send_frame(&fake, 42);
      
      		// Allow a moment for chatter (sometimes in the baseball field, however, preferably would be on the ethernet cables)
      		while(cache.find(concatd) == cache.end()){}
          while(length >= 1500){
          memcpy(fake.dst_mac, cache[concatd], sizeof(cache[concatd]));
          memcpy(fake.src_mac, net.get_mac(), sizeof(net.get_mac()));
          fake.prot[0] = 0x08;
          fake.prot[1] = 0x00;
          fake.data[0] = 0x45; // IP Version (4) & IP Header Length (5)
          fake.data[1] = 0x00; // Type of Service
          fake.data[2] = 0x05; // Total Length (byte0)
          fake.data[3] = 0xdc; // Total Length (byte1)
          fake.data[4] = ID >> 8; // ID (b0)
          fake.data[5] = ID & 0xff; // ID (b1)
          unsigned int frag = 0x2000 + frag_off;
          frag_off++;
          fake.data[6] = frag >> 8; // F & Fragment (b0.5)
          fake.data[7] = frag & 0xff; // Fragment (b1)
          fake.data[8] = 0x40; // Time to Live
          fake.data[9] = 0x11; // Protocol
          fake.data[10] = 0x0; // Header checksum (b0) - initialized as 0
          fake.data[11] = 0x0; // Header checksum (b1)
          fake.data[12] = 192; // Source IP
          fake.data[13] = 168;
          fake.data[14] = 1;
          fake.data[15] = curr_ip;
          fake.data[16] = userReq[0]; // Destination IP
          fake.data[17] = userReq[1];
          fake.data[18] = userReq[2];
          fake.data[19] = userReq[3];
          int sum = checksum(&fake.data[0], 20, 0);
          fake.data[10] = ~sum >> 8; // Header checksum (b0)
          fake.data[11] = ~sum & 0xff; // Header checksum (b1)
          fake.data[20] = 0x0; // UDP Header - Source Port Number (b0)
          fake.data[21] = 0x4; // UDP Header - Source Port Number (b1)
          fake.data[22] = 0x0; // UDP Header - Destination Port Number (b0)
          fake.data[23] = 0x7; // UDP Header - Destination Port Number (b1)
          fake.data[24] = 0x05; // UDP Header - UDP message length (b0)
          fake.data[25] = 0xc0; // UDP Header - UDP message length (b1)
          fake.data[26] = 0x00; // UDP Header - checksum (b0) - initialized as 0
          fake.data[27] = 0x00; // UDP Header - checksum (b1)
          for (int i = 28; i < 1500; i++) // Data
            fake.data[i] = 0x0;
          /*fake.data[28] = 0x0; // Data
          fake.data[29] = 0x0;
          fake.data[30] = 0x0;
          fake.data[31] = 0x0;
          fake.data[32] = 0x0;
          fake.data[33] = 0x0;
          fake.data[34] = 0x0;
          fake.data[35] = 0x0;*/
          sum = checksum(&fake.data[20], 1471, 0);
          fake.data[26] = ~sum >> 8; // Header checksum (b0)
          fake.data[27] = ~sum & 0xff; // Header checksum (b1)

          printf("Ethernet header (destination mac): %02x.%02x.%02x.%02x.%02x.%02x = %d.%d.%d.%d.%d.%d\n",
            fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5],
            fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5]);
          printf("IP header (destination IP): %02x.%02x.%02x.%02x = %d.%d.%d.%d\n",
            userReq[0], userReq[1], userReq[2], userReq[3],
            userReq[0], userReq[1], userReq[2], userReq[3]);
          printf("ID: 0x%04x (%d)\n",(fake.data[4] << 8)+fake.data[5],(fake.data[4] << 8)+fake.data[5]);
          printf("Frag: 0x%04x (%d)\n",(fake.data[6] << 8)+fake.data[7],(fake.data[6] << 8)+fake.data[7]);
          /*printf("Data: ");
            for(int i = 28; i < 1500; i++)
              printf("%02x ",fake.data[i]);*/
            printf("**************************\n\n");

          // Send UDP reply
            net.send_frame(&fake, 1500);
            // sleep(3);
            length -= 1500;
            /*for (int i = 1; i < 4; i ++)
            {
              fake.data[27] = i;
              fake.data[22] = 0x0; // ICMP Header - checksum (b0) - initialized as 0
              fake.data[23] = 0x0; // ICMP Header - checksum (b1)
              sum = checksum(&fake.data[20], 35, 0);
              fake.data[22] = ~sum >> 8; // Header checksum (b0)
              fake.data[23] = ~sum & 0xff; // Header checksum (b1)
              net.send_frame(&fake, 98);
              sleep(3);
            }*/
        }
      if(length < 1500){
        // IP-MAC pair is located in the cache - Form packet and send ARP reply
          memcpy(fake.dst_mac, cache[concatd], sizeof(cache[concatd]));
          memcpy(fake.src_mac, net.get_mac(), sizeof(net.get_mac()));
          fake.prot[0] = 0x08;
          fake.prot[1] = 0x00;
          fake.data[0] = 0x45; // IP Version (4) & IP Header Length (5)
          fake.data[1] = 0x00; // Type of Service
          fake.data[2] = length >> 8;; // Total Length (byte0)
          fake.data[3] = length & 0xff; // Total Length (byte1)
          fake.data[4] = ID >> 8; // ID (b0)
          fake.data[5] = ID & 0xff; // ID (b1)
          unsigned int frag = 0x0000 + frag_off;
          frag_off++;
          fake.data[6] = frag >> 8; // F & Fragment (b0.5)
          fake.data[7] = frag & 0xff; // Fragment (b1)
          fake.data[8] = 0x40; // Time to Live
          fake.data[9] = 0x11; // Protocol
          fake.data[10] = 0x0; // Header checksum (b0) - initialized as 0
          fake.data[11] = 0x0; // Header checksum (b1)
          fake.data[12] = 192; // Source IP
          fake.data[13] = 168;
          fake.data[14] = 1;
          fake.data[15] = curr_ip;
          fake.data[16] = userReq[0]; // Destination IP
          fake.data[17] = userReq[1];
          fake.data[18] = userReq[2];
          fake.data[19] = userReq[3];
          int sum = checksum(&fake.data[0], 20, 0);
          fake.data[10] = ~sum >> 8; // Header checksum (b0)
          fake.data[11] = ~sum & 0xff; // Header checksum (b1)
          fake.data[20] = 0x0; // UDP Header - Source Port Number (b0)
          fake.data[21] = 0x4; // UDP Header - Source Port Number (b1)
          fake.data[22] = 0x0; // UDP Header - Destination Port Number (b0)
          fake.data[23] = 0x7; // UDP Header - Destination Port Number (b1)
          fake.data[24] = length >> 8; // UDP Header - UDP message length (b0)
          fake.data[25] = (length - 28) & 0xff; // UDP Header - UDP message length (b1)
          fake.data[26] = 0x00; // UDP Header - checksum (b0) - initialized as 0
          fake.data[27] = 0x00; // UDP Header - checksum (b1)
          for (int i = 28; i < length; i++) // Data
            fake.data[i] = 0x0;
          /*fake.data[28] = 0x0; // Data
          fake.data[29] = 0x0;
          fake.data[30] = 0x0;
          fake.data[31] = 0x0;
          fake.data[32] = 0x0;
          fake.data[33] = 0x0;
          fake.data[34] = 0x0;
          fake.data[35] = 0x0;*/
          sum = checksum(&fake.data[20], length-28, 0);
          fake.data[26] = ~sum >> 8; // Header checksum (b0)
          fake.data[27] = ~sum & 0xff; // Header checksum (b1)

          printf("Ethernet header (destination mac): %02x.%02x.%02x.%02x.%02x.%02x = %d.%d.%d.%d.%d.%d\n",
            fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5],
            fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5]);
          printf("IP header (destination IP): %02x.%02x.%02x.%02x = %d.%d.%d.%d\n",
            userReq[0], userReq[1], userReq[2], userReq[3],
            userReq[0], userReq[1], userReq[2], userReq[3]);
          printf("ID: 0x%04x (%d)\n",(fake.data[4] << 8)+fake.data[5],(fake.data[4] << 8)+fake.data[5]);
          printf("Frag: 0x%04x (%d)\n",(fake.data[6] << 8)+fake.data[7],(fake.data[6] << 8)+fake.data[7]);
          /*printf("Data: ");
            for(int i = 28; i < length; i++)
              printf("%02x ",fake.data[i]);*/
            printf("**************************\n\n");

          // Send UDP reply
            net.send_frame(&fake, length);
            // sleep(3);
            /*for (int i = 1; i < 4; i ++)
            {
              fake.data[27] = i;
              fake.data[22] = 0x0; // ICMP Header - checksum (b0) - initialized as 0
              fake.data[23] = 0x0; // ICMP Header - checksum (b1)
              sum = checksum(&fake.data[20], 35, 0);
              fake.data[22] = ~sum >> 8; // Header checksum (b0)
              fake.data[23] = ~sum & 0xff; // Header checksum (b1)
              net.send_frame(&fake, 98);
              sleep(3);
            }*/
        }
	        /*memcpy(fake.dst_mac, cache[concatd], sizeof(cache[concatd]));
        	memcpy(fake.src_mac, net.get_mac(), sizeof(net.get_mac()));
        	fake.prot[0] = 0x08;
        	fake.prot[1] = 0x00;
        	fake.data[0] = 0x45; // IP Version (4) & IP Header Length (5)
        	fake.data[1] = 0x00; // Type of Service
        	fake.data[2] = 0x00; // Total Length (byte0)
        	fake.data[3] = 0x54; // Total Length (byte1)
        	fake.data[4] = 0x52; // ID (b0)
        	fake.data[5] = 0x6f; // ID (b1)
        	fake.data[6] = 0x40; // F & Fragment (b0.5)
        	fake.data[7] = 0x0; // Fragment (b1)
        	fake.data[8] = 0x40; // Time to Live
        	fake.data[9] = 0x17; // Protocol
        	fake.data[10] = 0x0; // Header checksum (b0) - initialized as 0
        	fake.data[11] = 0x0; // Header checksum (b1)
        	fake.data[12] = 192; // Source IP
        	fake.data[13] = 168;
        	fake.data[14] = 1;
        	fake.data[15] = curr_ip;
        	fake.data[16] = userReq[0]; // Destination IP
        	fake.data[17] = userReq[1];
        	fake.data[18] = userReq[2];
        	fake.data[19] = userReq[3];
        	int sum = checksum(&fake.data[0], 20, 0);
        	fake.data[10] = ~sum >> 8; // Header checksum (b0)
        	fake.data[11] = ~sum & 0xff; // Header checksum (b1)
        	fake.data[20] = 0x8; // ICMP Header - Type - ICMP Request - 8, Reply - 0
        	fake.data[21] = 0x0; // ICMP Header - Code - 0
        	fake.data[22] = 0x0; // ICMP Header - checksum (b0) - initialized as 0
        	fake.data[23] = 0x0; // ICMP Header - checksum (b1)
        	fake.data[24] = 0x52; // ICMP Header - ID (b0)
        	fake.data[25] = 0x6d; // ICMP Header - ID (b1)
        	fake.data[26] = 0x00; // ICMP Header - Sequence (b0)
        	fake.data[27] = 0x01; // ICMP Header - Sequence (b1)
        	fake.data[28] = 0x0; // Data
        	fake.data[29] = 0x0;
        	fake.data[30] = 0x0;
        	fake.data[31] = 0x0;
        	fake.data[32] = 0x0;
        	fake.data[33] = 0x0;
        	fake.data[34] = 0x0;
        	fake.data[35] = 0x0;
        	sum = checksum(&fake.data[20], 35, 0);
        	fake.data[22] = ~sum >> 8; // Header checksum (b0)
        	fake.data[23] = ~sum & 0xff; // Header checksum (b1)

        	printf("Ethernet header (destination mac): %02x.%02x.%02x.%02x.%02x.%02x = %d.%d.%d.%d.%d.%d\n",
        	fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5],
        	fake.dst_mac[0], fake.dst_mac[1], fake.dst_mac[2], fake.dst_mac[3], fake.dst_mac[4], fake.dst_mac[5]);
        	printf("IP header (destination IP): %02x.%02x.%02x.%02x = %d.%d.%d.%d\n",
        	userReq[0], userReq[1], userReq[2], userReq[3],
        	userReq[0], userReq[1], userReq[2], userReq[3]);
        	printf("Data: ");
          	for(int i = 28; i < 36; i++)
            	printf("%02x ",fake.data[i]);
          	printf("\n**************************\n\n");

        	// Send ICMP reply
        	for (int i = 1; i < 4; i ++)
          	{
            	fake.data[27] = i;
            	fake.data[22] = 0x0; // ICMP Header - checksum (b0) - initialized as 0
            	fake.data[23] = 0x0; // ICMP Header - checksum (b1)
            	sum = checksum(&fake.data[20], 35, 0);
            	fake.data[22] = ~sum >> 8; // Header checksum (b0)
            	fake.data[23] = ~sum & 0xff; // Header checksum (b1)
            	net.send_frame(&fake, 98);
            	sleep(3);
          	}*/
    	}
	}
}

//
// if you're going to have pthreads, you'll need some thread descriptors
//
pthread_t loop_thread, arp_thread, ip_thread, main_thread;

//
// start all the threads then step back and watch (actually, the timer
// thread will be started later, but that is invisible to us.)
//
int main()
{
	net.open_net(adap_name);
	pthread_create(&loop_thread,NULL,protocol_loop,NULL);
	pthread_create(&arp_thread,NULL,arp_protocol_loop,NULL);
	pthread_create(&ip_thread,NULL,ip_protocol_loop,NULL);
	pthread_create(&main_thread,NULL,main_protocol_loop,NULL);
	for ( ; ; )
	{
    	sleep(1);
	}
}