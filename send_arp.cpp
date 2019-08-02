#include <pcap.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <linux/if.h>
#include <netdb.h>
#include <netinet/in.h>
#include <unistd.h>

struct ethernet_header{
    uint8_t dst_mac[6];
    uint8_t src_mac[6];
    uint8_t type[2];
};

struct arp_header{
    uint16_t hd_type;
    uint16_t pr_type;
    uint8_t hd_len;
    uint8_t pr_len;
    uint16_t opcode;
    uint8_t smac[6];
    uint8_t sip[4];
    uint8_t tmac[6];
    uint8_t tip[4];
};

bool check_arp(const u_char* packet){
    struct ethernet_header eth;
    int type;

    memcpy(&eth, packet, 14);
    type = (eth.type[0] << 8) + eth.type[1];
    if(type == 0x0806) return true;
    else return false;
}

void get_mac(uint8_t* smac, char* interface) {

    int s;
    struct ifreq ifr;
    unsigned char* test;

    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);

    test = (unsigned char*)ifr.ifr_hwaddr.sa_data;
    printf("%2x:%2x\n", test[0], test[1]);
    close(s);
}

int main(int argc, char* argv[]){

    if(argc != 4){
        printf("usage : ./send_arp [interface] [sender_ip] [target_ip]\n");
        return 1;
    }

    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
      fprintf(stderr, "couldn't open device %s: %s\n", dev, errbuf);
      return -1;
    }

    uint8_t sip[4];
    uint8_t tip[4];

    inet_aton(argv[2], (in_addr*)sip);
    inet_aton(argv[3], (in_addr*)tip);


    struct ethernet_header eth;
    struct arp_header arp;

    // make ethernet
    printf(argv[0]);
    get_mac(&eth.src_mac[0], argv[0]);

    printf("AAA");
    memcpy(eth.dst_mac, "\xff\xff\xff\xff\xff\xff", 6);
    memcpy(eth.type, "\x08\x06", 2);
    // make arp
    memcpy((void*)arp.hd_type, "\x00\x01", 2);
    memcpy((void*)arp.pr_type, "\x08\x00", 2);
    arp.hd_len = (uint8_t)'\x06';
    arp.pr_len = (uint8_t)'\x04';
    memcpy((void*)arp.opcode, "\x00\x01", 2);
    memcpy(arp.smac, eth.src_mac, 6);
    memcpy(arp.sip, sip, 4);
    memcpy((void*)arp.tmac, "\x00\x00\x00\x00\x00\x00", 6);
    memcpy(arp.tip, tip, 4);

    uint8_t buf[42];
    memcpy(buf, &eth, 14);
    memcpy(&buf[14], &arp, 28);

    pcap_sendpacket(handle, buf, 42);
    printf("AAAA");

    while (true) {
      struct pcap_pkthdr* header;
      const u_char* packet;
      int res = pcap_next_ex(handle, &header, &packet);
      if (res == 0) continue;
      if (res == -1 || res == -2) break;
      printf("%u bytes captured\n", header->caplen);

      if(check_arp(packet)) break;
    }


    // extract target mac address
    // make packet
    // pcap_sendpacket(handle, packet, )

    pcap_close(handle);

    return 0;
}
