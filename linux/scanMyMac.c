#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <time.h>
/*
//header.file /usr/include/linux/if_ether.h

#define ETH_ALEN 6  //定义了以太网接口的MAC地址的长度为6个字节
#define ETH_HLAN 14  //定义了以太网帧的头长度为14个字节
#define ETH_ZLEN 60  //定义了以太网帧的最小长度为 ETH_ZLEN + ETH_FCS_LEN = 64个字节
#define ETH_DATA_LEN 1500  //定义了以太网帧的最大负载为1500个字节
#define ETH_FRAME_LEN 1514  //定义了以太网正的最大长度为ETH_DATA_LEN + ETH_FCS_LEN = 1518个字节 
#define ETH_FCS_LEN 4   //定义了以太网帧的CRC值占4个字节
*/
void ip_packet_callback(char * packet_content);

void ip_tcp_packet_callback(char * packet_content);

void ip_udp_packet_callback(char * packet_content);

int main(int argc, char **argv) {
   int sock, n;
   char buffer[2048];
   struct ethhdr *eth;
   struct iphdr *iph;
   FILE *file;
   time_t timer;

   if (0>(sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) {
     perror("socket");
     exit(1);
   }
   file = fopen("log.txt","w");

   while (1) {
     printf("===========================================================\n");
	 timer = time(NULL);
	 printf("ctime is %s",ctime(&timer));
     //注意：在这之前我没有调用bind函数，原因是什么呢？
     n = recvfrom(sock,buffer,2048,0,NULL,NULL);
     printf("[%d bytes read]\n",n);

     //接收到的数据帧头6字节是目的MAC地址，紧接着6字节是源MAC地址。
     eth=(struct ethhdr*)buffer;
	 printf("Ethernet Header\n");
     printf("   |-Destination Mac Address :%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
     printf("   |-Source MAC Address      :%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);

	 printf("   |-Protocol                :%u\n",(unsigned short)eth->h_proto);
     iph=(struct iphdr*)(buffer+sizeof(struct ethhdr));
     //我们只对IPV4且没有选项字段的IPv4报文感兴趣
     if(iph->version ==4 && iph->ihl == 5){
			 printf("IP Header\n");
			 printf("   |-IP Version        :%d\n",(unsigned int)iph->version);
			 printf("   |-IP Header Length  :%d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)iph->ihl)*4);
			 printf("   |-Type Of Service   :%d\n",(unsigned int)iph->tos);
			 printf("   |-TP Total Length   :%d Bytes(size of packet)\n",ntohs(iph->tot_len));
			 printf("   |-Identification    :%d\n",ntohs(iph->id));
			 printf("   |-TTL               :%d\n",(unsigned int)iph->ttl);
			 printf("   |-Protocol          :%d\n",(unsigned int)iph->protocol);
			 printf("   |-Checksum          :%d\n",ntohs(iph->check));
             printf("   |-Source IP         :%s\n",inet_ntoa(*(struct in_addr *)&iph->saddr));
             printf("   |-Destination IP    :%s\n",inet_ntoa(*(struct in_addr *)&iph->daddr));
     }
	 switch(ntohs(eth->h_proto))
	 {
		case ETH_P_IP:
			printf("IP Packet\n");
			ip_packet_callback(buffer);
		break;
		case ETH_P_ARP:
			printf("ARP Packet\n");
		break;
		case ETH_P_RARP:
			printf("RARP Packet\n");
		break;
	 }
   }
}
void ip_packet_callback(char * packet_content)
{
	struct iphdr *iph;
	iph = (struct iphdr *)(packet_content + sizeof(struct ethhdr));

	switch(iph->protocol)
	{
		case IPPROTO_ICMP:
			printf("ether ip icmp protocol\n");
		break;
		case IPPROTO_TCP:
			printf("ether ip tcp protocol\n");
			ip_tcp_packet_callback(packet_content);
		break;
		case IPPROTO_UDP:
			printf("ether ip udp protocol\n");
			ip_udp_packet_callback(packet_content);
		break;
	}
}
void ip_tcp_packet_callback(char * packet_content)
{
	struct tcphdr *tcpst;
	tcpst = (struct tcphdr *)(packet_content + sizeof(struct ethhdr) + sizeof(struct iphdr));
	printf("TCP Header\n");
	printf("    |-Source Port            :%d\n",ntohs(tcpst->source));
	printf("    |-Destination Port       :%d\n",ntohs(tcpst->dest));
	printf("    |-Sequence Number        :%u\n",ntohl(tcpst->seq));
	printf("    |-Acknowledgement Number :%u\n",ntohl(tcpst->ack_seq));
	printf("    |-Header Length          :%d\n",ntohs(tcpst->doff) * 4);
	printf("    |-Check Sum              :%d\n",ntohs(tcpst->check));
	printf("    |-Window Size            :%d\n",ntohs(tcpst->window));
	printf("    |-Urgent Pointer         :%d\n",ntohs(tcpst->urg_ptr));
}
void ip_udp_packet_callback(char * packet_content)
{
	struct udphdr *udpst;
	udpst = (struct udphdr *)(packet_content + sizeof(struct ethhdr) + sizeof(struct iphdr));
	printf("UDP Header\n");
	printf("    |-Source Port            :%d\n",ntohs(udpst->source));
	printf("    |-Destination Port       :%d\n",ntohs(udpst->dest));
	printf("    |-UDP Length             :%d\n",ntohs(udpst->len));
	printf("    |-UDP Check Sum          :%d\n",ntohs(udpst->check));
}
