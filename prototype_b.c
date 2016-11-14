// i386 is little_endian.  
#ifndef LITTLE_ENDIAN  
#define LITTLE_ENDIAN   (1)   //BYTE ORDER  
#else  
#error Redefine LITTLE_ORDER  
#endif  
//Mac头部，总长度14字节  
typedef struct _eth_hdr  
{  
    unsigned char dstmac[6]; //目标mac地址  
    unsigned char srcmac[6]; //源mac地址  
    unsigned short eth_type; //以太网类型  
}eth_hdr;  
//IP头部，总长度20字节  
typedef struct _ip_hdr  
{  
    #if LITTLE_ENDIAN  
    unsigned char ihl:4;     //首部长度  
    unsigned char version:4, //版本   
    #else  
    unsigned char version:4, //版本  
    unsigned char ihl:4;     //首部长度  
    #endif  
    unsigned char tos;       //服务类型  
    unsigned short tot_len;  //总长度  
    unsigned short id;       //标志  
    unsigned short frag_off; //分片偏移  
    unsigned char ttl;       //生存时间  
    unsigned char protocol;  //协议  
    unsigned short chk_sum;  //检验和  
    struct in_addr srcaddr;  //源IP地址  
    struct in_addr dstaddr;  //目的IP地址  
}ip_hdr;  
//TCP头部，总长度20字节  
typedef struct _tcp_hdr  
{  
    unsigned short src_port;    //源端口号  
    unsigned short dst_port;    //目的端口号  
    unsigned int seq_no;        //序列号  
    unsigned int ack_no;        //确认号  
    #if LITTLE_ENDIAN  
    unsigned char reserved_1:4; //保留6位中的4位首部长度  
    unsigned char thl:4;        //tcp头部长度  
    unsigned char flag:6;       //6位标志  
    unsigned char reseverd_2:2; //保留6位中的2位  
    #else  
    unsigned char thl:4;        //tcp头部长度  
    unsigned char reserved_1:4; //保留6位中的4位首部长度  
    unsigned char reseverd_2:2; //保留6位中的2位  
    unsigned char flag:6;       //6位标志   
    #endif  
    unsigned short wnd_size;    //16位窗口大小  
    unsigned short chk_sum;     //16位TCP检验和  
    unsigned short urgt_p;      //16为紧急指针  
}tcp_hdr;  
//UDP头部，总长度8字节  
typedef struct _udp_hdr  
{  
    unsigned short src_port; //远端口号  
    unsigned short dst_port; //目的端口号  
    unsigned short uhl;      //udp头部长度  
    unsigned short chk_sum;  //16位udp检验和  
}udp_hdr;  
//ICMP头部，总长度4字节  
typedef struct _icmp_hdr  
{  
    unsigned char icmp_type;   //类型  
    unsigned char code;        //代码  
    unsigned short chk_sum;    //16位检验和  
}icmp_hdr;

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
