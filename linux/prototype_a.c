#ifndef _PROTO_H_
#define _PROTO_H_

/*
* TCP/IP 协议类型
*/
#define IPPROTO_IP        0              // IP
#define IPPROTO_ICMP    1              // ICMP
#define IPPROTO_TCP        6              // TCP
#define IPPROTO_UDP        17             // UDP

/*
* 常见端口
*/
#define PORT_DNS        53                // DNS

/*
* 其它定义
*/
#define ETH_ALEN       6              // 以太网地址大小
#define ETH_HLEN       14             // 以太网头部大小
#define ETH_DATA_LEN   1500           // 最大帧负载数据大小
#define ETH_FRAME_LEN  1514           // 最大帧大小，头部+负载数据

/**
 * 常见协议定义
**/
#pragma pack(push, 1)

/*
*14字节的以太网包头
*/
typedef struct _ETHDR         
{
    UCHAR    eh_dst[ETH_ALEN];            // 目的MAC地址
    UCHAR    eh_src[ETH_ALEN];            // 源MAC地址
    USHORT    eh_type;                    // 下层协议类型，如IP（ETHERTYPE_IP）、ARP（ETHERTYPE_ARP）等
} ETHDR, *PETHDR;

/*
*28字节的ARP头
*/
typedef struct _ARPHDR    
{
    USHORT    ar_hrd;                //    硬件地址类型，以太网中为ARPHRD_ETHER
    USHORT    ar_pro;                //  协议地址类型，ETHERTYPE_IP
    UCHAR    ar_hln;                //    硬件地址长度，MAC地址的长度为6
    UCHAR    ar_pln;                //    协议地址长度，IP地址的长度为4
    USHORT    ar_op;                //    ARP操作代码，ARPOP_REQUEST为请求，ARPOP_REPLY为响应
    UCHAR    ar_sha[ETH_ALEN];    //    源MAC地址
    ULONG    ar_sip;                //    源IP地址
    UCHAR    ar_tha[ETH_ALEN];    //    目的MAC地址
    ULONG    ar_tip;                //    目的IP地址
} ARPHDR, *PARPHDR;

/*
*20字节的IP头
*/
typedef struct _IPHDR        
{
    UCHAR    h_lenver;            // 版本号和头长度（各占4位）
    UCHAR    tos;                // 服务类型 
    USHORT    total_len;            // 封包总长度，即整个IP报的长度
    USHORT    ident;                // 封包标识，惟一标识发送的每一个数据报
    USHORT    frag_and_flags;        // 标志
    UCHAR    ttl;                // 生存时间，就是TTL
    UCHAR    protocol;            // 协议，可能是TCP、UDP、ICMP等
    USHORT    checksum;            // 校验和
    ULONG    saddr;                // 源IP地址
    ULONG    daddr;                // 目标IP地址
} IPHDR, *PIPHDR; 

/*
*20字节的TCP头
*/
typedef struct _TCPHDR    
{
    USHORT    srceport;            // 16位源端口号
    USHORT    dstport;            // 16位目的端口号
    ULONG    seq;                // 32位序列号
    ULONG    ack;                // 32位确认号
    UCHAR    dataoffset;            // 高4位表示数据偏移
    UCHAR    flags;                // 6位标志位
    //FIN - 0x01
    //SYN - 0x02
    //RST - 0x04 
    //PSH - 0x08
    //ACK - 0x10
    //URG - 0x20
    //ACE - 0x40
    //CWR - 0x80

    USHORT    window;                // 16位窗口大小
    USHORT    checksum;            // 16位校验和
    USHORT    urgptr;                // 16位紧急数据偏移量 
} TCPHDR, *PTCPHDR;

/*
*伪TCP头，计算校验和时使用
*/
typedef struct _PSDTCPHDR
{
    ULONG    saddr;
    ULONG    daddr;
    char    mbz;
    char    ptcl;
    USHORT    tcpl;
} PSDTCPHDR, *PPSDTCPHDR;

/*
*8字节的UDP头
*/
typedef struct _UDPHDR
{
    USHORT    srcport;            // 源端口号        
    USHORT    dstport;            // 目的端口号        
    USHORT    len;                // 封包长度
    USHORT    checksum;            // 校验和
} UDPHDR, *PUDPHDR;

/*
*伪UDP头，计算校验和时使用
*/
typedef struct _PSDUDPHDR
{
    ULONG    saddr;
    ULONG    daddr;
    char    mbz;
    char    ptcl;
    USHORT    udpl;
} PSDUDPHDR, *PPSDUDPHDR;

/*
*12字节的ICMP头
*/
typedef struct _ICMPHDR
{
    UCHAR   type;                //类型
    UCHAR   code;                //代码
    USHORT  checksum;            //校验和
    USHORT  id;                    //标识符
    USHORT  sequence;            //序列号
    ULONG   timestamp;            //时间戳
} ICMPHDR, *PICMPHDR;

/*
*6字节的PPPOE头+2字节协议
*/
typedef struct _PPPOEHDR
{
    UCHAR    ver_type;            //版本+类型 一般为0x11
    UCHAR    code;                //编码
    USHORT    sessionid;            //session id
    USHORT    len;                //长度
    USHORT    protocol;            //协议
} PPPOEHDR, *PPPPOEHDR;

/*
* dns包头
*/
typedef struct _DNSHDR 
{
    USHORT id;
    USHORT flags;
    USHORT quests;
    USHORT answers;
    USHORT author;
    USHORT addition;
} DNSHDR, *PDNSHDR;

/* 
* dns查询包,query
*/
typedef struct _DNSQUERY
{
    /*UCHAR　*dname;*/    //查询的域名,这是一个大小在0到63之间的字符串
    /*该域名的获取方法如下：
    * 长度：udp包总长度-sizeof(UDPHDR)-sizeof(DNSHDR)-sizeof(DNSQUERY)
    * 内容在dns头后面
    */
    USHORT    type;            //查询类型，大约有20个不同的类型
    USHORT    classes;        //查询类,通常是A类既查询IP地址
} DNSQUERY, *PDNSQUERY;

/* 
* dns响应包
*/
typedef struct _DNSRESPONSE
{
    USHORT    name;        // 查询的域名
    USHORT    type;        // 查询的类型
    USHORT    classes;    // 类型码
    UINT    ttl;        // 生存时间
    USHORT    length;        // 资源数据长度
    UINT    addr;        // 资源数据
} DNSRESPONSE, *PDNRESPONSE;

#pragma pack(pop)

#endif
