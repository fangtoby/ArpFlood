/////////////////////////////////////////////////////////////////////////////////
// 文件名： arp_func.c
// 作者：   cfjtaishan
// 版本：   1.0
// 日期：   2013-05-14
// 描述：   免费ARP--用于检测IP地址是否冲突.
// 历史记录：
/////////////////////////////////////////////////////////////////////////////////


#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <linux/if_packet.h>
#include <netdb.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/ioctl.h>
#include <net/ethernet.h>
#include <netinet/ether.h>
#include <net/if.h>
#include <netinet/ip.h>

#define    FAILURE   -1
#define    SUCCESS    0

unsigned char src_ip[4] = { 192, 168, 9, 118 };    //要检测的主机IP地址
unsigned char src_mac[6] = {0x00, 0x0c, 0x29, 0x4b, 0x6c, 0x13};    //要检测的主机的MAC地址
unsigned char dst_ip[4] = { 192, 168, 9, 118 };    //目标IP地址
unsigned char dst_mac[6] = { 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };    //ARP广播地址

int send_arp(int sockfd, struct sockaddr_ll *peer_addr);
int recv_arp(int sockfd, struct sockaddr_ll *peer_addr);

//ARP封装包
typedef struct _tagARP_PACKET{  
    struct ether_header  eh;  
    struct ether_arp arp;  
}ARP_PACKET_OBJ, *ARP_PACKET_HANDLE; 

int main(int argc, char *argv[])
{
	int sockfd;
	int rtval = -1;
	struct sockaddr_ll peer_addr;
	//创建socket
	sockfd = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ARP));
	if (sockfd < 0)
	{
		fprintf(stderr, "socket error: %s\n", strerror(errno));
		exit(EXIT_FAILURE);
	}
	
	memset(&peer_addr, 0, sizeof(peer_addr));  
        peer_addr.sll_family = AF_PACKET;  
        struct ifreq req;
	bzero(&req, sizeof(struct ifreq));
        strcpy(req.ifr_name, "eth0");  
        if(ioctl(sockfd, SIOCGIFINDEX, &req) != 0)
		perror("ioctl()");  
        peer_addr.sll_ifindex = req.ifr_ifindex;  
        peer_addr.sll_protocol = htons(ETH_P_ARP);
	//peer_addr.sll_family = AF_PACKET;
	while (1)
	{
		rtval = send_arp(sockfd, &peer_addr);
		if (FAILURE == rtval)
		{
			fprintf(stderr, "Send arp socket failed: %s\n", strerror(errno));
		}
		rtval = recv_arp(sockfd, &peer_addr);
		if (rtval == SUCCESS)
		{
			printf ("Get packet from peer and IP conflicts!\n");
		}
		else if (rtval == FAILURE)
		{
			fprintf(stderr, "Recv arp IP not conflicts: %s\n", strerror(errno));
		}
		else
		{
			fprintf(stderr, "Recv arp socket failed: %s\n", strerror(errno));
		}
		//sleep(1);
	}
	return 0;
}
//////////////////////////////////////////////////////////////////////////
// 函数名: send_arp 
// 描述 : 填充ARP数据包报文并发送出去。
// 参数: 
//    [in] sockfd -- 创建的socket描述符;
//    [in] peer_addr -- 对端的IP信息
// 返回值: 
//    成功: SUCCESS, 失败: FAILURE;
// 说明: 
//////////////////////////////////////////////////////////////////////////
int send_arp(int sockfd, struct sockaddr_ll *peer_addr)
{
	int rtval;
	ARP_PACKET_OBJ frame;
	memset(&frame, 0x00, sizeof(ARP_PACKET_OBJ));
	
	//填充以太网头部
        memcpy(frame.eh.ether_dhost, dst_mac, 6);    //目的MAC地址
        memcpy(frame.eh.ether_shost, src_mac, 6);    //源MAC地址
        frame.eh.ether_type = htons(ETH_P_ARP);      //协议 

	//填充ARP报文头部
        frame.arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);    //硬件类型 
        frame.arp.ea_hdr.ar_pro = htons(ETHERTYPE_IP);    //协议类型 ETHERTYPE_IP | ETH_P_IP
        frame.arp.ea_hdr.ar_hln = 6;                //硬件地址长度
        frame.arp.ea_hdr.ar_pln = 4;                //协议地址长度
        frame.arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);    //ARP请求操作
        memcpy(frame.arp.arp_sha, src_mac, 6);    //源MAC地址
        memcpy(frame.arp.arp_spa, src_ip, 4);     //源IP地址
        memcpy(frame.arp.arp_tha, dst_mac, 6);    //目的MAC地址
        memcpy(frame.arp.arp_tpa, dst_ip, 4);     //目的IP地址
	
        rtval = sendto(sockfd, &frame, sizeof(ARP_PACKET_OBJ), 0, 
		(struct sockaddr*)peer_addr, sizeof(struct sockaddr_ll));  
	if (rtval < 0)
	{
		return FAILURE;
	}
	return SUCCESS;
}
//////////////////////////////////////////////////////////////////////////  
// 函数名: recv_arp   
// 描述 : 接收ARP回复数据报文并判断是不是对免费ARP的回复。  
// 参数:   
//    [in] sockfd -- 创建的socket描述符;  
//    [in] peer_addr -- 对端的IP信息  
// 返回值:   
//    成功: SUCCESS, 失败: FAILURE;  
// 说明:   
//    若是对免费arp请求的回复则返回:SUCCESS.  
//////////////////////////////////////////////////////////////////////////  
int recv_arp(int sockfd, struct sockaddr_ll *peer_addr)  
{  
    int rtval;  
    ARP_PACKET_OBJ frame;  
      
    memset(&frame, 0, sizeof(ARP_PACKET_OBJ));  
    rtval = recvfrom(sockfd, &frame, sizeof(frame), 0,   
        NULL, NULL);  
    //判断是否接收到数据并且是否为回应包  
    if (htons(ARPOP_REPLY) == frame.arp.ea_hdr.ar_op && rtval > 0)  
    {  
        //判断源地址是否为冲突的IP地址  
        if (memcmp(frame.arp.arp_spa, src_ip, 4) == 0)  
        {  
            fprintf(stdout, "IP address is common~\n");  
            return SUCCESS;  
        }  
    }  
    if (rtval < 0)  
    {  
        return FAILURE;  
    }  
    return FAILURE;  
}  
