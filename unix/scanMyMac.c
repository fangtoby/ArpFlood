#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <net/if_arp.h>
#include <arpa/inet.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>
#include <net/ethernet.h>

int main(int argc, char **argv) {
   int sock, n;
   char buffer[2048];
   struct ether_header *eth;
   struct ip *iph;
   FILE *file;

   if (0>(sock=socket(AF_INET, SOCK_RAW, 0))) {
     perror("socket");
     exit(1);
   }
   file = fopen("log.txt","w");

   while (1) {
     printf("=====================================\n");
     //注意：在这之前我没有调用bind函数，原因是什么呢？
     n = recvfrom(sock,buffer,2048,0,NULL,NULL);
     printf("%d bytes read\n",n);

     //接收到的数据帧头6字节是目的MAC地址，紧接着6字节是源MAC地址。
     eth=(struct ether_header*)buffer;
     printf("Dest MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_dhost[0],eth->ether_dhost[1],eth->ether_dhost[2],eth->ether_dhost[3],eth->ether_dhost[4],eth->ether_dhost[5]);
     printf("Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->ether_shost[0],eth->ether_shost[1],eth->ether_shost[2],eth->ether_shost[3],eth->ether_shost[4],eth->ether_shost[5]);

     iph=(struct ip *)(buffer+sizeof(struct ether_header));
     //我们只对IPV4且没有选项字段的IPv4报文感兴趣
     if(iph->ip_hl ==4){
             printf("Source host:%s\n",inet_ntoa(*(struct in_addr *)&iph->ip_src));
             printf("Dest host:%s\n",inet_ntoa(*(struct in_addr *)&iph->ip_dst));
     }
   }
}
