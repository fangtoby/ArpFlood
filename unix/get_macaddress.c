#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>

#include <errno.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <net/ethernet.h>

#define ETH_ALEN 6  //定义了以太网接口的MAC地址的长度为6个字节
#define ETH_HLAN 14  //定义了以太网帧的头长度为14个字节
#define ETH_ZLEN 60  //定义了以太网帧的最小长度为 ETH_ZLEN + ETH_FCS_LEN = 64个字节
#define ETH_DATA_LEN 1500  //定义了以太网帧的最大负载为1500个字节
#define ETH_FRAME_LEN 1514  //定义了以太网正的最大长度为ETH_DATA_LEN + ETH_FCS_LEN = 1518个字节
#define ETH_FCS_LEN 4   //定义了以太网帧的CRC值占4个字节

#define PF_PACKET   17  /* Packet family.  */
#define AF_PACKET   PF_PACKET

#define ETH_P_ALL       0x0003
#define ETH_P_LOOP      0x0060          /* Ethernet Loopback packet     */
#define ETH_P_PUP       0x0200          /* Xerox PUP packet             */
#define ETH_P_PUPAT     0x0201          /* Xerox PUP Addr Trans packet  */
#define ETH_P_IP        0x0800          /* Internet Protocol packet     */
#define ETH_P_X25       0x0805          /* CCITT X.25                   */
#define ETH_P_ARP       0x0806          /* Address Resolution packet    */
#define ETH_P_BPQ       0x08FF          /* G8BPQ AX.25 Ethernet Packet  */
#define ETH_P_IEEEPUP   0x0a00          /* Xerox IEEE802.3 PUP packet */
#define ETH_P_IEEEPUPAT 0x0a01          /* Xerox IEEE802.3 PUP Addr Trans packet*/

#define SOCK_PACKET 10

#ifndef TRUE
#define TRUE 1
#endif
#ifndef FALSE
#define FALSE 0
#endif

struct sockaddr_ll
{
    u_short sll_family;
    u_short sll_protocol;
    int sll_ifindex;
    u_short sll_hatype;
    u_char sll_pkttype;
    u_char sll_halen;
    u_char sll_addr[8];
};


int main(int argc,char** argv){
    //socket target id
    int sock;
    //sento string
    char buf[42]={0};
    //normal ether header struct
    struct ether_header eth;
    //ether arp packet struct
    struct ether_arp arp;
    //Get local device
    struct ifreq ifr;
    //
    struct sockaddr_ll toaddr;
    
    //source mac address
    unsigned char src_mac[ETHER_ADDR_LEN]={0};
    //destination mac address
    unsigned char dst_mac[ETHER_ADDR_LEN]={0xff,0xff,0xff,0xff,0xff,0xff}; //全网广播ARP请求
    //source ip address ,normal is local ip address
    unsigned char sou_ip_addr[4] = {192,168,8,223};
    //destination ip address
    unsigned char des_ip_addr[4] = {112,65,235,59};
    //ether_header struct length
    int ether_header_len = sizeof(struct ether_header);
    
    int sendto_string_count;
    
    //创建套接字
    sock = socket(AF_INET,SOCK_RAW,0);
    if(0>sock){
        printf("Create Error");
        exit(1);
    }else{
        printf("socket create id = %d \n",sock);
    }
    
    memset(&toaddr, 0, sizeof(struct sockaddr_ll));
    
    memset(&ifr, 0, sizeof(struct ifreq));
    
    strcpy(ifr.ifr_name,"en1");
    
    if(ioctl(sock,SIOCGIFADDR,&ifr) < 0)
    {
        printf("ioctl SIOCGIFADDR error\n");
        close(sock);
        exit(1);
    }
    
    toaddr.sll_ifindex = ifr.ifr_intval;
    
    printf("interface Index:%d\n",ifr.ifr_intval);
    
    printf("IP addr:%s\n",inet_ntoa(((struct sockaddr_in*)&(ifr.ifr_addr))->sin_addr));
    
    memcpy(src_mac,ifr.ifr_addr.sa_data,ETHER_ADDR_LEN);
    
    printf("MAC :%02X-%02X-%02X-%02X-%02X-%02X\n",src_mac[0],src_mac[1],src_mac[2],src_mac[3],src_mac[4],src_mac[5]);
    
    //开始填充，构造以太头部
    
    memset(&eth, 0, ether_header_len);
    
    memcpy(eth.ether_dhost,dst_mac,ETHER_ADDR_LEN);
    
    memcpy(eth.ether_shost,src_mac,ETHER_ADDR_LEN);
    
    eth.ether_type = htons(ETHERTYPE_ARP);

    memset(&arp, 0, sizeof(struct ether_arp));
    
    arp.arp_hrd = htons(ARPHRD_ETHER); //硬件类型为以太
    arp.arp_pro = htons(ETHERTYPE_IP); //协议类型为IP
    
    //硬件地址长度和IPV4地址长度分别是6字节和4字节
    arp.arp_hln = ETHER_ADDR_LEN;
    arp.arp_pln = 4;
    
    //操作码，这里我们发送ARP请求
    arp.arp_op = htons(ARPOP_REQUEST);
    
    //填充发送端的MAC和IP地址
    memcpy(arp.arp_sha,src_mac,ETHER_ADDR_LEN);
//    memcpy(arp.arp_spa,&srcIP,4);
    memcpy((void *) arp.arp_spa,(void *) sou_ip_addr, 4);
//    inet_pton(AF_INET,"192.168.1.105",&targetIP);
//    memcpy(arp.arp_tpa,&targetIP,4);
    memcpy((void *) arp.arp_tpa,(void *) des_ip_addr, 4);
    
    toaddr.sll_family = AF_INET;
    
    
    memcpy(buf, &eth, ether_header_len);
    
    memcpy(&buf[ether_header_len], &arp, sizeof(struct ether_arp));
    
    while (TRUE) {
        sendto_string_count=sendto(sock,buf,42,0,(struct sockaddr *)&toaddr,sizeof(toaddr));
        if(sendto_string_count != -1){
            printf("<success>sendto function return result:%d\n",sendto_string_count);
        }else{
            printf("<failure>sendto function error, return result:%d\n",sendto_string_count);
        }
    }
    close(sock);
    exit(1);
}