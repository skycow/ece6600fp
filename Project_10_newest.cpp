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

frameio net;             // gives us access to the raw network
message_queue ip_queue;  // message queue for the IP protocol stack
message_queue arp_queue; // message queue for the ARP protocol stack

octet curr_ip = 10;
// const char * adap_name = "enp3s0";
const char * adap_name = "eth0";

std::map<int, octet *> cache;

struct ether_frame       // handy template for 802.3/DIX frames
{
  	octet dst_mac[6];     // destination MAC address
  	octet src_mac[6];     // source MAC address
  	octet prot[2];        // protocol (or length)
  	octet data[1500];     // payload
    octet crc[4];         // cyclic redundancy check(checksum)
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
  
  	while(1)
  	{
    	ip_queue.recv(&event,&buf,sizeof(buf));
    	if(buf.data[9] == 0x01 && buf.data[20] == 0x08)
    		{
        	ether_frame fake;

      		// IP-MAC pair is located in the cache - Form packet and send ARP reply
          	memcpy(fake.dst_mac, buf.src_mac, sizeof(buf.src_mac));
          	memcpy(fake.src_mac, net.get_mac(), sizeof(net.get_mac()));
            // Header
          	fake.prot[0] = 0x08;
          	fake.prot[1] = 0x00;
          	fake.data[0] = 0x45; // IP Version (4) & IP Header Length (5)
          	fake.data[1] = 0x00; // Type of Service
          	fake.data[2] = buf.data[2]; //0x00; // Total Length (byte0)
          	fake.data[3] = buf.data[3]; //0x54; // Total Length (byte1)
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

            // ICMP Header
          	fake.data[20] = 0x0; // ICMP Header - Type - ICMP Request - 8, Reply - 0
          	fake.data[21] = 0x0; // ICMP Header - Code - 0
          	fake.data[22] = 0x0; // ICMP Header - checksum (b0) - initialized as 0
          	fake.data[23] = 0x0; // ICMP Header - checksum (b1)
          	fake.data[24] = buf.data[24]; // ICMP Header - ID (b0)
          	fake.data[25] = buf.data[25]; // ICMP Header - ID (b1)
          	fake.data[26] = buf.data[26]; // ICMP Header - Sequence (b0)
          	fake.data[27] = buf.data[27]; // ICMP Header - Sequence (b1)

            // Data
          	fake.data[28] = buf.data[28]; // Time Stamp
          	fake.data[29] = buf.data[29];
          	fake.data[30] = buf.data[30];
          	fake.data[31] = buf.data[31];
          	fake.data[32] = buf.data[32];
          	fake.data[33] = buf.data[33];
          	fake.data[34] = buf.data[34];
          	fake.data[35] = buf.data[35];
          	memcpy(&fake.data[36], &buf.data[36], 1464); // Data
            sum = checksum(&fake.data[20], 1480, 0);
          	fake.data[22] = ~sum >> 8; // Header checksum (b0)
          	fake.data[23] = ~sum & 0xff; // Header checksum (b1)
			// Send ICMP reply
			net.send_frame(&fake, 1514);

			// Print to console
            printf("From: %02x.%02x.%02x.%02x.%02x.%02x; %d.%d.%d.%d\n",
              buf.src_mac[0], buf.src_mac[1], buf.src_mac[2], buf.src_mac[3], buf.src_mac[4], buf.src_mac[5],
              buf.data[12], buf.data[13], buf.data[14], buf.data[15]);
          	printf("Timestamp: ");
          	for(int i = 28; i < 36; i++)
            	printf("%d:",buf.data[i]);
          	printf("\n");
			printf("<other user> says: \n");
          	for(int i = 36; i < 1500; i++)
            	printf("%c",buf.data[i]);
          	printf("\n\nSend to <other user>: ");
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

int send_packet(ether_frame &fake)
{
  // printf("Entering send_packet...\n");
  char input;
  std::string message = "";
  printf("Send to <other user>: ");
  // std::cin >> message;
  std::getline(std::cin, message);
  int size = message.size();

  std::cout << "Size: "<<size<<std::endl;
  std::cout << "Message: "<<message<<std::endl;

  unsigned int concatd = (192 << 24) + (168 << 16) + (1 << 8) + 20;

	memcpy(fake.dst_mac, cache[concatd], sizeof(cache[concatd]));
	memcpy(fake.src_mac, net.get_mac(), sizeof(net.get_mac()));
  // Header
	fake.prot[0] = 0x08;
	fake.prot[1] = 0x00;
	fake.data[0] = 0x45; // IP Version (4) & IP Header Length (5)
	fake.data[1] = 0x00; // Type of Service
	fake.data[2] = 0x05; // Total Length (byte0)
	fake.data[3] = 0xdc; // Total Length (byte1)
	fake.data[4] = 0x52; // ID (b0)
	fake.data[5] = 0x6f; // ID (b1)
	fake.data[6] = 0x40; // F & Fragment (b0.5)
	fake.data[7] = 0x0; // Fragment (b1)
	fake.data[8] = 0x40; // Time to Live
	fake.data[9] = 0x1; // Protocol
	fake.data[10] = 0x0; // Header checksum (b0) - initialized as 0
	fake.data[11] = 0x0; // Header checksum (b1)
	fake.data[12] = 192; // Source IP
	fake.data[13] = 168;
	fake.data[14] = 1;
	fake.data[15] = curr_ip;
	fake.data[16] = 192; // Destination IP
	fake.data[17] = 168;
	fake.data[18] = 1;
	fake.data[19] = 20;
	int sum = checksum(&fake.data[0], 20, 0);
	fake.data[10] = ~sum >> 8; // Header checksum (b0)
	fake.data[11] = ~sum & 0xff; // Header checksum (b1)

  // ICMP Header
	fake.data[20] = 0x8; // ICMP Header - Type - ICMP Request - 8, Reply - 0
	fake.data[21] = 0x0; // ICMP Header - Code - 0
	fake.data[22] = 0x0; // ICMP Header - checksum (b0) - initialized as 0
	fake.data[23] = 0x0; // ICMP Header - checksum (b1)
	fake.data[24] = 0x52; // ICMP Header - ID (b0)
	fake.data[25] = 0x6d; // ICMP Header - ID (b1)
	fake.data[26] = 0x00; // ICMP Header - Sequence (b0)
	fake.data[27] = 0x01; // ICMP Header - Sequence (b1)

  // Data
	fake.data[28] = 0x0; // Data
	fake.data[29] = 0x0;
	fake.data[30] = 0x0;
	fake.data[31] = 0x0;
	fake.data[32] = 0x0;
	fake.data[33] = 0x0;
	fake.data[34] = 0x0;
	fake.data[35] = 0x0;
	for (int i = 0; i < size; i++)
	{
		fake.data[36 + i] = message[i];
	}
  //for (int i = 0; i < 98 - size- 36; i++)
  //{
  //  fake.data[36 + i + size] = 0;
  //}
	sum = checksum(&fake.data[20], 1480, 0);
	fake.data[22] = ~sum >> 8; // Header checksum (b0)
	fake.data[23] = ~sum & 0xff; // Header checksum (b1)
        //memset(&message, 0, message.size());
}

// Waits for input from the user.  Either prints off stored IP-MAC pairs or pings desired IP address.
void *main_protocol_loop(void *arg)
{
  printf("in main_protocol_loop...\n");
  	while(1){
      printf("in the while loop...\n");
      // printf("Entering main_protocol_loop...\n");
    	/*char input;
    	std::string message = "";
    	printf("Send to <other user>: ");
      // std::cin >> message;
      std::getline(std::cin, message);
      int size = message.size();*/

      unsigned int concatd = (192 << 24) + (168 << 16) + (1 << 8) + 20;
	
		// check if target IP is in the lab
      	/*if (userReq[0] == 192 && userReq[1] == 168 && userReq[2] == 1)
      	{
        	printf("\n**************************\n");
		    printf("Target IP is in the lab...\n");
    	}
		else 
		{
        	printf("\n**************************\n");
		    printf("Target IP is NOT in the lab...\n");
		    concatd = (192 << 24) + (168 << 16) + (001 << 8) + 001;
		}*/

      	ether_frame *newfake = new ether_frame();
        ether_frame fake = *newfake;
      	// IP-MAC pair is located in the cache - Form packet and send ARP reply
      	if(cache.find(concatd) != cache.end()){
          // printf("Calling send_packet(IP-MAC pair is in the cache)...\n");
			send_packet(fake);
        	/*printf("Data: ");
          	for(int i = 28; i < 36; i++)
            	printf("%02x ",fake.data[i]);
          	printf("\n**************************\n\n");*/

            // printf("Sending packet...\n");
            // printf("packet: fake\n");
            // for(int i = 0; i < 100; i++)
            //   printf("fake.data[%d] = %02x\n", i, fake.data[i]);
            net.send_frame(&fake, 1514);
            // printf("Packet sent...\n");
      	}

      		// IP-MAC pair is not found in the cache - Form packet and send ARP request to desired IP address to obtain MAC address
      	if(cache.find(concatd) == cache.end()){
          // printf("IP-MAC pair not in cache(create ARP packet)...\n");
			for (int i = 0; i < 6; i++)
			{
				fake.dst_mac[i] = 0xff;
			}

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
			for (int i = 18; i < 24; i++)
			{
				fake.data[i] = 0x00;
			}
        	fake.data[24] = 192;
        	fake.data[25] = 168;
        	fake.data[26] = 1;
        	fake.data[27] = 20;

        	// Send ARP Request
          // printf("Send ARP packet...\n");
        	int n = net.send_frame(&fake, 42);
          printf("After sending the arp frame...\n");
          // printf("ARP packet sent...\n");
      		// Allow a moment for chatter (sometimes in the baseball field, however, preferably would be on the ethernet cables)
      		while(cache.find(concatd) == cache.end()){}
            printf("After the chatter...\n");
            // printf("Calling send_packet...\n");
			send_packet(fake);
      printf("After sending the call to send_packet...\n");
        	/*printf("Data: ");
          	for(int i = 28; i < 36; i++)
            	printf("%02x ",fake.data[i]);
          	printf("\n**************************\n\n");*/
            // printf("Sending packet...\n");
            net.send_frame(&fake, 1514);
            printf("After actually sending the packet...\n");
            // printf("Packet sent...\n");
    	}
      delete newfake;
      printf("End of main_protocol_loop...\n");
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
