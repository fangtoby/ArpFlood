#include <stdio.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <arpa/inet.h>

int main(int argc, char **argv) {
   int sock, n;
   char buffer[2048];
   struct ethhdr *eth;
   struct iphdr *iph;
   FILE *file;

   if (0>(sock=socket(PF_PACKET, SOCK_RAW, htons(ETH_P_ALL)))) {
     perror("socket");
     exit(1);
   }
   file = fopen("log.txt","w");

   while (1) {
     fprintf(file,"=====================================\n");
     //注意：在这之前我没有调用bind函数，原因是什么呢？
     n = recvfrom(sock,buffer,2048,0,NULL,NULL);
     fprintf(file,"%d bytes read\n",n);

     //接收到的数据帧头6字节是目的MAC地址，紧接着6字节是源MAC地址。
     eth=(struct ethhdr*)buffer;
     fprintf(file,"Dest MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_dest[0],eth->h_dest[1],eth->h_dest[2],eth->h_dest[3],eth->h_dest[4],eth->h_dest[5]);
     fprintf(file,"Source MAC addr:%02x:%02x:%02x:%02x:%02x:%02x\n",eth->h_source[0],eth->h_source[1],eth->h_source[2],eth->h_source[3],eth->h_source[4],eth->h_source[5]);

     iph=(struct iphdr*)(buffer+sizeof(struct ethhdr));
     //我们只对IPV4且没有选项字段的IPv4报文感兴趣
     if(iph->version ==4 && iph->ihl == 5){
             fprintf(file,"Source host:%s\n",inet_ntoa(*(struct in_addr *)&iph->saddr));
             fprintf(file,"Dest host:%s\n",inet_ntoa(*(struct in_addr *)&iph->daddr));
     }
   }
}
