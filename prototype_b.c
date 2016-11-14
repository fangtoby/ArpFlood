/*********************************************/  
//计算机网络各种协议的结构  
#define ETHER_ADDR_LEN 6 //NIC物理地址占6字节  
#define MAXDATA 10240  
/* 
网络实验程序 
数据包中的TCP包头,IP包头,UDP包头,ARP包,Ethernet包等. 
以及各种表.路由寻址表,地址解析协议表DNS表等 
*/  
#define ETHERTYPE_IP 0x0800   //IP Protocal  
#define ETHERTYPE_ARP 0x0806   //Address Resolution Protocal  
#define ETHERTYPE_REVARP 0x0835   //Reverse Address Resolution Protocal 逆地址解析协议  
/*********************************************/  
//ethernet  
typedef struct ether_header  
{  
    u_char ether_dhost[ETHER_ADDR_LEN];  
    u_char ether_shost[ETHER_ADDR_LEN];  
    u_short ether_type;  
}ETH_HEADER;  
/*********************************************/  
//ether_header eth;  
/*********************************************/  
//arp  
typedef struct arphdr  
{  
    u_short ar_hrd;  
    u_short ar_pro;  
    u_char ar_hln;  
    u_char ar_pln;  
    u_short ar_op;  
}ARP_HEADER;  
/*********************************************/  
/*********************************************/  
//IP报头  
typedef struct ip  
{  
    u_int ip_v:4; //version(版本)  
    u_int ip_hl:4; //header length(报头长度)  
    u_char ip_tos;  
    u_short ip_len;  
    u_short ip_id;  
    u_short ip_off;  
    u_char ip_ttl;  
    u_char ip_p;  
    u_short ip_sum;  
    struct in_addr ip_src;  
    struct in_addr ip_dst;  
}IP_HEADER;  
/*********************************************/  
/*********************************************/  
//TCP报头结构体  
typedef struct tcphdr   
{  
    u_short th_sport;  
    u_short th_dport;  
    u_int th_seq;  
    u_int th_ack;  
    u_int th_off:4;  
    u_int th_x2:4;  
    u_char th_flags;  
    u_short th_win;  
    u_short th_sum;  
    u_short th_urp;  
}TCP_HEADER;  
#define TH_FIN 0x01  
#define TH_SYN 0x02  
#define TH_RST 0x04  
#define TH_PUSH 0x08  
#define TH_ACK 0x10  
#define TH_URG 0x20  
/*********************************************/  
/*********************************************/  
//UDP报头结构体*/  
typedef struct udphdr   
{  
    u_short uh_sport;  
    u_short uh_dport;  
    u_short uh_ulen;  
    u_short uh_sum;  
}UDP_HEADER;  
/*********************************************/  
//=============================================  
/*********************************************/  
/*ARP与ETHERNET生成的报头*/  
typedef struct ether_arp  
{  
    struct arphdr ea_hdr;  
    u_char arp_sha[ETHER_ADDR_LEN];  
    u_char arp_spa[4];  
    u_char arp_tha[ETHER_ADDR_LEN];  
    u_char arp_tpa[4];  
}ETH_ARP;  
#define arp_hrd ea_hdr.ar_hrd  
#define arp_pro ea_hdr.ar_pro  
#define arp_hln ea_hdr.ar_hln  
#define arp_pln ea_hdr.ar_pln  
#define arp_op ea_hdr.ar_op  
#define ARPHRD 1  
/*********************************************/  
/*********************************************/  
//tcp与ip生成的报头  
typedef struct packet_tcp   
{  
    struct ip ip;  
    struct tcphdr tcp;  
    u_char data[MAXDATA];  
}TCP_IP;  
/*********************************************/  
/*********************************************/  
//udp与ip生成的报头  
typedef struct packet_udp   
{  
    struct ip ip;  
    struct udphdr udp;  
}UDP_IP;  
/*********************************************/  
/*********************************************/  
//ICMP的各种形式  
//icmpx,x==icmp_type;  
//icmp报文(能到达目的地,响应-请求包)  
struct icmp8   
{  
    u_char icmp_type; //type of message(报文类型)  
    u_char icmp_code; //type sub code(报文类型子码)  
    u_short icmp_cksum;  
    u_short icmp_id;  
    u_short icmp_seq;  
    char icmp_data[1];  
};  
//icmp报文(能返回目的地,响应-应答包)  
struct icmp0   
{  
    u_char icmp_type; //type of message(报文类型)  
    u_char icmp_code; //type sub code(报文类型子码)  
    u_short icmp_cksum;  
    u_short icmp_id;  
    u_short icmp_seq;  
    char icmp_data[1];  
};  
//icmp报文(不能到达目的地)  
struct icmp3   
{  
    u_char icmp_type; //type of message(报文类型)  
    u_char icmp_code; //type sub code(报文类型子码),例如:0网络原因不能到达,1主机原因不能到达...  
    u_short icmp_cksum;  
    u_short icmp_pmvoid;  
    u_short icmp_nextmtu;  
    char icmp_data[1];  
};  
//icmp报文(重发结构体)  
struct icmp5   
{  
    u_char icmp_type; //type of message(报文类型)  
    u_char icmp_code; //type sub code(报文类型子码)  
    u_short icmp_cksum;  
    struct in_addr icmp_gwaddr;  
    char icmp_data[1];  
};  
struct icmp11   
{  
    u_char icmp_type; //type of message(报文类型)  
    u_char icmp_code; //type sub code(报文类型子码)  
    u_short icmp_cksum;  
    u_int icmp_void;  
    char icmp_data[1];  
};  
