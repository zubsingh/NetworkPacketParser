// windows network packet parser
#include <iostream>
#include <pcap.h>
#include <string>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <ctype.h>
#include <errno.h>
#include <sys/types.h>
#include <winsock.h>
#include <WinSock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#include <vector>
#include <unordered_map>

#pragma comment(lib, "Ws2_32.lib")

/* Common ethernet types in Hex*/
#define ETHERNET_TYPE_IPv4 0x0800
#define ETHERNET_TYPE_IPv6 0x86DD

/* ethernet headers are always exactly 14 bytes [1] */
#define SIZE_ETHERNET 14

/* Ethernet addresses are 6 bytes */
#define ETHER_ADDR_LEN	6

/* Ethernet header */
struct sniff_ethernet {
    u_char  ether_dhost[ETHER_ADDR_LEN];    /* destination host address */
    u_char  ether_shost[ETHER_ADDR_LEN];    /* source host address */
    u_short ether_type;                     /* IP? ARP? RARP? etc */
};

/* IPv6 header */
struct ipv6_header
{
    unsigned int
            version : 4,
            traffic_class : 8,
            flow_label : 20;
    uint16_t length;
    uint8_t  next_header;
    uint8_t  hop_limit;
    struct in6_addr saddr;
    struct in6_addr daddr;
} ipv6_header;

/* IPv4 header */
struct sniff_ip {
    u_char  ip_vhl;                 /* version << 4 | header length >> 2 */
    u_char  ip_tos;                 /* type of service */
    u_short ip_len;                 /* total length */
    u_short ip_id;                  /* identification */
    u_short ip_off;                 /* fragment offset field */
#define IP_RF 0x8000            /* reserved fragment flag */
#define IP_DF 0x4000            /* don't fragment flag */
#define IP_MF 0x2000            /* more fragments flag */
#define IP_OFFMASK 0x1fff       /* mask for fragmenting bits */
    u_char  ip_ttl;                 /* time to live */
    u_char  ip_p;                   /* protocol */
    u_short ip_sum;                 /* checksum */
    struct  in_addr ip_src, ip_dst;  /* source and dest address */
};
#define IP_HL(ip)               (((ip)->ip_vhl) & 0x0f)
#define IP_V(ip)                (((ip)->ip_vhl) >> 4)


/* TCP header */
typedef u_int tcp_seq;

struct sniff_tcp {
    u_short th_sport;               /* source port */
    u_short th_dport;               /* destination port */
    tcp_seq th_seq;                 /* sequence number */
    tcp_seq th_ack;                 /* acknowledgement number */
    u_char  th_offx2;               /* data offset, rsvd */
#define TH_OFF(th)      (((th)->th_offx2 & 0xf0) >> 4)
    u_char  th_flags;
#define TH_FIN  0x01
#define TH_SYN  0x02
#define TH_RST  0x04
#define TH_PUSH 0x08
#define TH_ACK  0x10
#define TH_URG  0x20
#define TH_ECE  0x40
#define TH_CWR  0x80
#define TH_FLAGS        (TH_FIN|TH_SYN|TH_RST|TH_ACK|TH_URG|TH_ECE|TH_CWR)
    u_short th_win;                 /* window */
    u_short th_sum;                 /* checksum */
    u_short th_urp;                 /* urgent pointer */
};

struct sniff_udp {
    u_short th_sport;
    u_short th_dport;
};

class sessionData {
public:
    std::string src;
    std::string des;
    int src_port;
    int des_port;
    sessionData(std::string srcc,std::string dess,int src_portt,int des_portt): src(srcc),des(dess),src_port(src_portt),des_port(des_portt) {}

    bool operator ==(const sessionData& obj) const
    {
        if ((this->src == obj.src && this->des == obj.des && this->src_port == obj.src_port && this->des_port == obj.des_port)) //&& (this->src ==obj.des && this->des == obj.src && this->src_port == obj.des_port && this->des_port == obj.src_port))
            return true;
        else
            return false;
    }

    /* bool operator ==(const sessionData& obj) const
     {
         if ((this->src == obj.src || this->src == obj.des) && (this->des == obj.des && this->des == obj.src) || this->src_port == obj.src_port && this->src_port == obj.des_port && (this->des_port == obj.des_port && this->des_port == obj.src_port)) {
             return true;
         }
         return false;
     }*/

};


class sessionData1{
public:
    std::string src;
    std::string des;
    int src_port;
    int des_port;
    sessionData1(std::string srcc, std::string dess, int src_portt, int des_portt) : src(srcc), des(dess), src_port(src_portt), des_port(des_portt) {}

    bool operator ==(const sessionData1& obj) const
    {
        if ((this->src == obj.des && this->des == obj.src && this->src_port == obj.des_port && this->des_port == obj.src_port)) //&& (this->src ==obj.des && this->des == obj.src && this->src_port == obj.des_port && this->des_port == obj.src_port))
            return true;
        else
            return false;
    }

};
class MyHashFunction {
public:

    // Use sum of lengths of first and last names
    // as hash function.
    size_t operator()(const sessionData& p) const
    {
        return p.des.length() + p.src.length() + std::to_string(p.src_port).length() + std::to_string(p.des_port).length();
    }
};

class MyHashFunction1 {
public:

    // Use sum of lengths of first and last names
    // as hash function.
    size_t operator()(const sessionData1& p) const
    {
        return p.des.length() + p.src.length() + std::to_string(p.src_port).length() + std::to_string(p.des_port).length();
    }
};

void printVector(std::vector<sessionData>& vec);


// Comparator Class to compare 2 objects
class sessionCompare {
public:
    // Comparator function
    bool operator()(std::vector<sessionData> & a,
                    sessionData & b)
    {
        for (int i = 0; i < a.size(); i++)
        {
            if ((a[i].src == b.src && a[i].des == b.des && a[i].src_port == b.src_port && a[i].des_port == b.des_port) || (a[i].src == b.des && a[i].des == b.src && a[i].src_port == b.des_port && a[i].des_port == b.src_port)) {
                return true;
            }

        }
        return false;
    }
};

//// Comparator Class to compare 2 objects
//class sessionComparebyMap {
//public:
//    // Comparator function
//    bool operator()(std::unordered_map<sessionData,int> & a,
//        sessionData& b)
//    {
//        if (a.find())
//        {
//
//        }
//    }
//};

int main()
{
    int tcpsessions = 0;
    std::vector<sessionData> vec_tcp;
    int udpsessions = 0;
    std::vector<sessionData> vec_udp;
    std::unordered_map<sessionData, int, MyHashFunction> sessionMap;
    std::unordered_map<sessionData1, int, MyHashFunction1> sessionMap1;

    int ipv4_packets = 0;
    int ipv6_packets = 0;

    //std::string file = "C:\\Users\\zubin.singh\\Downloads\\sample.pcap";
    //std::string file = "C:\\Users\\zubin.singh\\Downloads\\smallFlows.pcap";
    std::string file = "C:\\Users\\zubin.singh\\Downloads\\sample7.pcap";
    //std::string file = "C:\\Users\\zubin.singh\\Downloads\\sr-header.pcap";


    // errbuf in pcap_open functions is assumed to be able to hold at least PCAP_ERRBUF_SIZE chars
    //       PCAP_ERRBUF_SIZE is defined as 256.
    char errbuff[PCAP_ERRBUF_SIZE];

    pcap_t* pcap = pcap_open_offline(file.c_str(), errbuff);


    // Create a header object:
    struct pcap_pkthdr* header;

    // Create a character array using a u_char
    // typedef unsigned char   u_char;
    const u_char* data;

    u_int packetCount = 0;
    u_int tcpPacketCount = 0;
    u_int udpPacketCount = 0;

    while (int returnPacket = pcap_next_ex(pcap,&header,&data) >= 0) {

        // Show the packet number
        ++packetCount;
        std::cout << "Packer # " << packetCount << std::endl;

        // Show the size in bytes of the packet
        printf("Packet size: %ld bytes\n", header->len);


        /* declare pointers to packet headers */
        const struct sniff_ethernet* ethernet;  /* The ethernet header [1] */
        const struct sniff_ip* ip;              /* The IPv4 header */
        const struct ipv6_header* ipv6;
        const struct sniff_tcp* tcp;            /* The TCP header */
        const char* payload;                    /* Packet payload */
        const struct sniff_udp* udp;            /* The udp header */

        int size_ip;
        int size_tcp;
        int size_payload;

        u_short eth_type;
        ethernet = (struct sniff_ethernet*)(data);
        eth_type = ntohs(ethernet->ether_type);

        if (eth_type == ETHERNET_TYPE_IPv4) {
            std::cout << "  ipv4 packet\n";

            ip = (struct sniff_ip*)(data + SIZE_ETHERNET);
            size_ip = IP_HL(ip) * 4;
            if (size_ip < 20) {
                printf("   * Invalid IPv4 header length: %u bytes\n", size_ip);
            }

            if (ip->ip_p == IPPROTO_TCP) {

                tcp = (struct sniff_tcp*)(data + SIZE_ETHERNET + size_ip);
                size_tcp = TH_OFF(tcp) * 4;
                if (size_tcp < 20) {
                    printf("   * Invalid TCP header length: %u bytes\n", size_tcp);
                }
                printf("   Protocol: TCP\n");
                ++tcpPacketCount;

                char srcname[16];
                inet_ntop(AF_INET, &(ip->ip_src), srcname, 16);
                printf("   src name %s\n", srcname);

                char desname[16];
                inet_ntop(AF_INET, &(ip->ip_dst), desname, 16);
                printf("   des name %s\n", desname);

                printf("   Src port: %d\n", ntohs(tcp->th_sport));
                printf("   Dst port: %d\n", ntohs(tcp->th_dport));

                sessionData sd(srcname, desname, ntohs(tcp->th_sport), ntohs(tcp->th_dport));
                sessionData1 sd1(srcname, desname, ntohs(tcp->th_sport), ntohs(tcp->th_dport));

                sessionCompare cmp;

                if (sessionMap.find(sd) == sessionMap.end() && sessionMap1.find(sd1) == sessionMap1.end())
                {
                    sessionMap[sd] = 1;
                    sessionMap1[sd1] = 1;
                }

                //if (sessionMap.find(sd) == sessionMap.end())// && sessionMap1.find(sd1) == sessionMap1.end())
                //{
                //    sessionMap[sd] = 1;
                //    //sessionMap1[sd1] = 1;
                //}
                if (vec_tcp.empty() || !cmp(vec_tcp, sd))
                {
                    tcpsessions++;
                    vec_tcp.push_back(sd);
                }

            }
            else if (ip->ip_p == IPPROTO_UDP) {
                printf("   Protocol: UDP\n");
                ++udpPacketCount;

                char srcname[16];
                inet_ntop(AF_INET, &(ip->ip_src), srcname, 16);
                printf("   src name %s\n", srcname);

                char desname[16];
                inet_ntop(AF_INET, &(ip->ip_dst), desname, 16);
                printf("   des name %s\n", desname);


                udp = (struct sniff_udp*)(data + SIZE_ETHERNET + size_ip);

                printf("   Src port: %d\n", ntohs(udp->th_sport));
                printf("   Dst port: %d\n", ntohs(udp->th_dport));

                sessionData sd(srcname, desname, ntohs(udp->th_sport), ntohs(udp->th_dport));

                sessionCompare cmp;

                if (vec_udp.empty() || !cmp(vec_udp, sd))
                {
                    udpsessions++;
                    vec_udp.push_back(sd);
                }
            }

            ipv4_packets++;
        }
        else if (eth_type == ETHERNET_TYPE_IPv6)
        {
            std::cout << "ipv6 packet\n";
            const struct ipv6_header* iph;

            iph = (struct ipv6_header*)(data + SIZE_ETHERNET);
            char desname[48];
            inet_ntop(AF_INET6, &(iph->saddr), desname, 48);
            printf("   saddr %s\n", desname);

            ipv6_packets++;
        }

        std::cout << std::endl;
    }

    std::cout << "Total ipv4 tcp packets " << tcpPacketCount << std::endl;
    std::cout << "Total ipv4 tcp sessions " << tcpsessions << std::endl;
    std::cout << "Total ipv4 tcp sessions map " << sessionMap.size() << std::endl;
    // printVector(vec);
    std::cout << "Total ipv4 udp packets " << udpPacketCount << std::endl;
    std::cout << "Total ipv4 udp sessions " << udpsessions << std::endl;

    std::cout << "Total no of ipv4 " << ipv4_packets << std::endl;
    std::cout << "Total no of ipv6 " << ipv6_packets << std::endl;
    std::cout << "Total number of packets " << packetCount << std::endl;

    std::cout << std::endl;
}




void printVector(std::vector<sessionData>& vec) {
    std::cout << "\n";
    if (vec.empty()) {
        std::cout << "empty\n";
    }
    else {
        for (int i = 0; i < vec.size(); i++)
        {
            std::cout << vec[i].src << " " << vec[i].des << " " << vec[i].src_port << " " << vec[i].des_port << "\n";
        }
    }
    std::cout << "\n";
}
