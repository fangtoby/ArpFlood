#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <time.h>
//self defined arppacket or use ether_arp (/usr/include/netinet/if_ether.h)
struct arppacket
{
	unsigned short int ar_hrd;
	unsigned short int ar_pro;
	unsigned char ar_hln;
	unsigned char ar_pln;
	unsigned short int ar_op;

	unsigned char ar_sha[ETH_ALEN];
	unsigned char ar_sip[4];
	unsigned char ar_tha[ETH_ALEN];
	unsigned char ar_tip[4];
};
/*
//header.file /usr/include/linux/if_ether.h

#define ETH_ALEN 6  //定义了以太网接口的MAC地址的长度为6个字节
#define ETH_HLAN 14  //定义了以太网帧的头长度为14个字节
#define ETH_ZLEN 60  //定义了以太网帧的最小长度为 ETH_ZLEN + ETH_FCS_LEN = 64个字节
#define ETH_DATA_LEN 1500  //定义了以太网帧的最大负载为1500个字节
#define ETH_FRAME_LEN 1514  //定义了以太网正的最大长度为ETH_DATA_LEN + ETH_FCS_LEN = 1518个字节 
#define ETH_FCS_LEN 4   //定义了以太网帧的CRC值占4个字节
*/
void ip_packet_callback(char * packet_content, int size);

void arp_packet_callback(char * packet_content, int size);

void ip_tcp_packet_callback(char * packet_content, int size);

void ip_udp_packet_callback(char * packet_content, int size);

void ip_icmp_packet_callback(char * packet_content, int size);

void print_data(const char * data, int size);

//FILE *file;

int main(int argc, char **argv) {
	int sock, size;
	char buffer[2048];
	struct ethhdr *eth;
	struct iphdr *iph;
	time_t timer;

	if (0>(sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) {
		perror("socket");
		exit(1);
	}
	//   file = fopen("log.txt","a");
	//   if(file == NULL){
	//	   printf("log.txt file open error!\n");
	//   }
	while (1) {
		size = recvfrom(sock,buffer,2048,0,NULL,NULL);
		printf("===========================================================\n");
		timer = time(NULL);
		printf("ctime is %s",ctime(&timer));
		printf("[%d bytes read]\n",size);

		eth=(struct ethhdr*)buffer;
		printf("Ethernet Header\n"); 
		printf("   |-Destination Mac Address :%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
		printf("   |-Source MAC Address      :%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);

		printf("   |-Protocol                :%u\n",(unsigned short)eth->h_proto);
		//接收到的数据帧头6字节是目的MAC地址，紧接着6字节是源MAC地址。
		iph=(struct iphdr*)(buffer+sizeof(struct ethhdr));
		//我们只对IPV4且没有选项字段的IPv4报文感兴趣
		if(iph->version ==4 && iph->ihl == 5){
			printf("IP Header\n");
			printf("   |-IP Version        :%d\n",(unsigned int)iph->version);
			printf("   |-IP Header Length  :%d DWORDS or %d Bytes\n",(unsigned int)iph->ihl,((unsigned int)iph->ihl)*4);
			printf("   |-Type Of Service   :%d\n",(unsigned int)iph->tos);
			printf("   |-TP Total Length   :%d Bytes(size of packet)\n",ntohs(iph->tot_len));
			printf("   |-Identification    :%d\n",ntohs(iph->id));
			// __be16  frag_off;             
			// frag_off域的低13位 -- 分段偏移(Fragment offset)域指明了该分段在当前
			// 数据报中的什么位置上。除了一个数据报的最后一个分段以外，其他所有的
			// 分段(分片)必须是8字节的倍数。这是8字节是基本分段单位。iphdr->frag_off
			// 的高3位(1) 比特0是保留的，必须为0；(2) 比特1是“更多分片”(MF -- More 
			// Fragment)标志。除了最后一片外，其他每个组成数据报的片都要把该比特置1。 
			// (3) 比特2是“不分片”(DF -- Don't Fragment)标志,如果将这一比特置1，
			// IP将不对数据报进行分片,这时如果有需要进行分片的数据报到来，会丢弃此
			// 数据报并发送一个ICMP差错报文给起始端。  
			printf("   |-Frag Off          :%d\n",ntohs(iph->frag_off));
			printf("   |-TTL               :%d\n",(unsigned int short)iph->ttl);
			printf("   |-Protocol          :%d\n",(unsigned int short)iph->protocol);
			printf("   |-Checksum          :%d\n",ntohs(iph->check));
			printf("   |-Source IP         :%s\n",inet_ntoa(*(struct in_addr *)&iph->saddr));
			printf("   |-Destination IP    :%s\n",inet_ntoa(*(struct in_addr *)&iph->daddr));
		}
		switch(ntohs(eth->h_proto))
		{
			case ETH_P_IP:
				ip_packet_callback(buffer, size);
				break;
			case ETH_P_ARP:
				arp_packet_callback(buffer, size);
				break;
			case ETH_P_RARP:
				arp_packet_callback(buffer, size);
				break;
		}
		//fflush(file);
	}
	//fclose(file);
	return 0;
}
void ip_packet_callback(char * packet_content, int size)
{
	struct iphdr *iph;
	iph = (struct iphdr *)(packet_content + sizeof(struct ethhdr));

	switch(iph->protocol)
	{
		case IPPROTO_ICMP:
			ip_icmp_packet_callback(packet_content, size);
			break;
		case IPPROTO_TCP:
			ip_tcp_packet_callback(packet_content, size);
			break;
		case IPPROTO_UDP:
			ip_udp_packet_callback(packet_content, size);
			break;
	}
}
void ip_tcp_packet_callback(char * packet_content, int size)
{
	struct tcphdr *tcpst;
	int header_size;

	tcpst = (struct tcphdr *)(packet_content + sizeof(struct ethhdr) + sizeof(struct iphdr));
	header_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + tcpst->doff * 4;

	printf("TCP Header\n");
	printf("   |-Source Port            :%d\n",ntohs(tcpst->source));
	printf("   |-Destination Port       :%d\n",ntohs(tcpst->dest));
	printf("   |-Sequence Number        :%u\n",ntohl(tcpst->seq));
	printf("   |-Acknowledgement Number :%u\n",ntohl(tcpst->ack_seq));
	printf("   |-Header Length          :%d DWORDS or %d BYTES\n",(unsigned int)tcpst->doff,(unsigned int)tcpst->doff * 4);
	printf("   |-Check Sum              :%d\n",ntohs(tcpst->check));
	printf("   |-Window Size            :%d\n",ntohs(tcpst->window));
	printf("   |-Urgent Pointer         :%d\n",tcpst->urg_ptr);
	
	printf("[Ethner Header]\n");
	print_data(packet_content , sizeof(struct ethhdr));
	printf("[IP Header]\n");
	print_data(packet_content + sizeof(struct ethhdr) , sizeof(struct iphdr));
	printf("[TCP Header]\n");
	print_data(packet_content + sizeof(struct ethhdr) + sizeof(struct iphdr),tcpst->doff * 4);
	printf("[Data Payload]\n");
	print_data(packet_content + header_size, size - header_size);
}
void ip_udp_packet_callback(char * packet_content, int size)
{
	struct udphdr *udpst;
	int header_size;
	struct iphdr *iph;
	unsigned short iphdrlen;

	iph = (struct iphdr *)(packet_content + sizeof(struct ethhdr));

	iphdrlen = iph->ihl * 4;

	udpst = (struct udphdr *)(packet_content + iphdrlen + sizeof(struct ethhdr));

	header_size = sizeof(struct ethhdr) + iphdrlen + sizeof udpst;

	printf("UDP Header\n");
	printf("   |-Source Port            :%d\n",ntohs(udpst->source));
	printf("   |-Destination Port       :%d\n",ntohs(udpst->dest));
	printf("   |-UDP Length             :%d\n",ntohs(udpst->len));
	printf("   |-UDP Check Sum          :%d\n",ntohs(udpst->check));
	printf("[Ethner Header]\n");
	print_data(packet_content , sizeof(struct ethhdr));
	printf("[IP Header]\n");
	print_data(packet_content + sizeof(struct ethhdr) , sizeof(struct iphdr));
	printf("[UDP Header]\n");
	print_data(packet_content + sizeof(struct ethhdr) + sizeof(struct iphdr),sizeof udpst);
	printf("[Data Payload]\n");

	print_data(packet_content + header_size, size - header_size);
}

void ip_icmp_packet_callback(char * packet_content, int size)
{
	struct icmphdr *icmpst;
	int header_size;
	icmpst = (struct icmphdr *)(packet_content + sizeof(struct ethhdr) + sizeof(struct iphdr));
	header_size = sizeof(struct ethhdr) + sizeof(struct iphdr) + sizeof(struct icmphdr);
	printf("ICMP Header\n");
	printf("   |-Message Type           :%d\n",(unsigned int)icmpst->type);
	printf("   |-Type Sub Code          :%d\n",(unsigned int)icmpst->code);
	printf("   |-Check Sum              :%d\n",ntohs(icmpst->checksum));
	printf("[Ethner Header]\n");
	print_data(packet_content , sizeof(struct ethhdr));
	printf("[IP Header]\n");
	print_data(packet_content + sizeof(struct ethhdr) , sizeof(struct iphdr));
	printf("[Data Payload]\n");
	print_data(packet_content + header_size ,size - header_size);
}

void arp_packet_callback(char * packet_content, int size)
{
	struct arppacket *arpst;
	arpst = (struct arppacket *)(packet_content + sizeof(struct ethhdr));
	printf("ARP/RARP Header\n");
	printf("   |-Hardware Address       :%d\n",ntohs(arpst->ar_hrd));
	printf("   |-Protocol Address       :%d\n",ntohs(arpst->ar_pro));
	printf("   |-Hardware Address Length:%d\n",arpst->ar_hln);
	printf("   |-Protocol Address Length:%d\n",arpst->ar_pln);
	printf("   |-ARP Opcode             :%d\n",ntohs(arpst->ar_op));
	/* ARP protocol opcodes. */  
	//#define     ARPOP_REQUEST    1        /*ARP request*/  
	//#define     ARPOP_REPLY      2        /*ARP reply*/  
	//#define     ARPOP_RREQUEST   3        /*RARP request*/  
	//#define     ARPOP_RREPLY	   4        /*RARP reply*/  
	//#define     ARPOP_InREQUEST  8        /*InARP request*/  
	//#define     ARPOP_InREPLY    9        /*InARP reply*/  
	//#define     ARPOP_NAK        10		/*(ATM)ARP NAK*/  
	printf("   |-Sender IP Address      :%s\n",inet_ntoa(*(struct in_addr *)&arpst->ar_sip));
	printf("   |-Target IP Address      :%s\n",inet_ntoa(*(struct in_addr *)&arpst->ar_tip));
	printf("   |-Sender  Mac Address    :%02x:%02x:%02x:%02x:%02x:%02x\n",arpst->ar_sha[0],arpst->ar_sha[1],arpst->ar_sha[2],arpst->ar_sha[3],arpst->ar_sha[4],arpst->ar_sha[5]);
	printf("   |-Target  Mac Address    :%02x:%02x:%02x:%02x:%02x:%02x\n",arpst->ar_tha[0],arpst->ar_tha[1],arpst->ar_tha[2],arpst->ar_tha[3],arpst->ar_tha[4],arpst->ar_tha[5]);
	printf("[Ethner Header]\n");
	print_data(packet_content , sizeof(struct ethhdr));
	printf("[Arp Header]\n");
	print_data(packet_content + sizeof(struct ethhdr) , sizeof(struct arppacket));
	printf("[Data Payload]\n");
	print_data(packet_content + sizeof(struct ethhdr) + sizeof(struct arppacket),size - sizeof(struct ethhdr) - sizeof(struct arppacket));	
}

void print_data(const char * data, int size)
{
	int i , j;
	if(size > 0)
		printf("\n");
	for(i=0; i<size;i++){
		if(i !=0 && i%16 == 0){
			printf("              ");
			for(j=i-16;j<i;j++){
				if(data[j] >= 32 && data[j] <=128)
					printf("%c",(unsigned char)data[j]);
				else
					printf(".");
			}
			printf("\n");
		}

		if(i%16 ==0) 
			printf("    ");

		printf("%02x",(unsigned int)data[i]);
		//printf("%2x",(unsigned int) data[i]);
		//printf("%x",(unsigned int) data[i]);
		if( i == size - 1){
			for(j=16 - i%16;j>0;j--){
				printf(" ");
			}
			printf("              ");
			for(j=i-i%16;j< i; j++){
				if(data[j] >= 32 && data[j] <=128)
					printf("%c",(unsigned char)data[j]);
				else
					printf(".");
			}
			printf("\n");
		}
	}
}
