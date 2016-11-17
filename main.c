#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <stdio.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/types.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/if_ether.h>
#include <net/if_arp.h>
//#include <netpacket/packet.h>
#include <net/if.h>
#include <net/ethernet.h>
#include <arpa/inet.h>

#define BUFLEN 42
/**
 *在每种格式的以太网帧的开始处都有64比特（8字节）的前导字符
 *其中，前7个字节称为前同步码（Preamble），内容是16进制数 0xAA，
 *最后1字节为帧起始标志符0xAB，它标识着以太网帧的开始。前导字符
 *的作用是使接收节点进行同步并做好接收数据帧的准备.
 *
 *[10101010][10101010][10101010][10101010][10101010][10101010][10101010][10101010]
 *
 *在不定长的数据字段后是4个字节的帧校验序列（Frame Check Sequence，FCS），
 *采用32位CRC循环冗余校验对从"目标MAC地址"字段到"数据"字段的数据进行校验。
 *
 *[前同步码Preamble][帧起始标示符0xAB]
 *       7				    1
 *[目标mac地址][源mac地址][类型][数据][数据校验和FCS]
 *     6           6        2  46-1500      4
 *
 *--类型--
 *	1. 0x0800 ip报文
 *	2. 0x0806 arp请求/应答
 *	3. 0x8035 rarp请求/应答
 *
 *--数据--
 *由一个上层协议的协议数据单元PDU构成。可以发送的最大有效负载是1500字节。
 *由于以太网的冲突检测特性，有效负载至少是46个字节。如果上层协议数据单元长
 *度少于46个字节，必须增补到46个字节。帧检验序列：4个字节。验证比特完整性。
 *
 *--类型--
 *接下来的2个字节标识出以太网帧所携带的上层数据类型，如16进制数0x0800
 *代表IP协议数据，16进制数0x809B代表AppleTalk协议数据，16进制数0x8138
 *代表Novell类型协议数据等。
 *
 *--根据类型区分两种帧--
 *根据源地址段后的前两个字节的类型不同.
 *如果值大于1500（0x05DC），说明是以太网类型字段，EthernetII帧格式。值
 *小于等于1500，说明是长度字段，IEEE802.3帧格式。因为类型字段值最小的
 *是0x0600。而长度最大为1500。
 *
 *
 */
// 数据帧最小长度 46 byte
#define MIN_PACK_SIZE 46
// 数据帧最大长度 1500 byte
#define MAX_PACK_SIZE 1500

/* mac 数据帧头部定义，头14个字节，尾4个字节*/
typedef struct _MAC_FRAME_HEADER
{
	unsigned char m_cDstMacAddress[6];	//目的mac地址 a8:15:4d:1f:7d:68
	unsigned char m_cSrcMacAddress[6];	//源mac地址 a8:15:4d:1f:7d:68
	short m_cType;				//上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp,帧类型，2个字节
}__attribute__((packed))MAC_FRAME_HEADER,*PMAC_FRAME_HEADER;

/* mac 数据帧尾部 4 byte */
typedef struct _MAC_FRAME_TAIL
{
	unsigned int m_sCheckSum;	//数据帧尾校验和
}__attribute__((packed))MAC_FRAME_TAIL, *PMAC_FRAME_TAIL;

/* ARP头定义，共28个字节 */
typedef struct _ARPHDR    
{
	short    ar_hrd;                //    硬件地址类型，以太网中为ARPHRD_ETHER
	short    ar_pro;                //  协议地址类型，ETHERTYPE_IP
	char    ar_hln;                //    硬件地址长度，MAC地址的长度为6
	char    ar_pln;                //    协议地址长度，IP地址的长度为4
	short    ar_op;                //    ARP操作代码，ARPOP_REQUEST为请求，ARPOP_REPLY为响应
	char    ar_sha[ETH_ALEN];    //    源MAC地址
	long    ar_sip;                //    源IP地址
	char    ar_tha[ETH_ALEN];    //    目的MAC地址
	long    ar_tip;                //    目的IP地址
}__attribute__((packed)) ARPHDR, *PARPHDR;
/*
 * IP头定义，共20个字节
 *-- 版本 —— 
 *	标识了IP协议的版本，通常这个字段的值为0010，常用的版本号为4，新的版本号为6，
 *	现在IPv6还没有普遍使用，但是中国已经为奥运会建立了一个ipv6的网络。IPv6又被
 *	称为IPng（IP Next Generation）
 *-- 报头长度 ——
 * 	这个字段的长度为4，它表明了IP报头的长度，设计这个字段的原因是报文的选择项字段
 * 	会发生改变，IP报头的最小长度为20个8bit，最大为24个8bit。报文字段描述了以32比
 * 	特为单位程度的报头长度，其中5表示IP报头的最小长度为160比特，6表示最大。
 *-- 服务类型——
 *	字段长度为8位，它用来表示特殊报文的处理方式。服务类型字段实际上被
 *	划分为2个部分，一部分为优先权一部分为TOS。优先权用来设定报文的优先级，就像邮
 *	包分为挂号和平信一样。TOS允许按照吞吐量、时延、可靠性和费用方式选择传输服务，
 *	在早期的时候，TOS还被用来进行路由选择。在QOS中有时也会使用优先权，常见的优先
 *	权队列。
 *-- 总长度—— 
 *	字段长度为16位，通常预标记字段和分片偏移字段一起用于IP报文的分段。如果报文总
 *	长度大于数据链路可传输的最大传输单元（MTU），那么就会对报文进行分片。
 *-- 数据包标记字段 —— 
 *	长度位3位，其中第一位没有被使用第二位是不分片位，当DF位被置1，表示路由器不能
 *	对数据报文进行分片处理，如果报文由于不能被分片而不能被转发，那么路由器将丢弃
 *	这个数据包，并向源地址发送错误报告。这一功能可以用来测试线路的最大传输单元。
 *	第三位MF，当路由器对数据进行分片时，除了最后一个分片的MF位为0外，其他所有的MF
 *	为全部为1，表示其后面还有其他的分片
 *-- 分片偏移――
 * 字段长度为13位，以8个bit为单位，用于指明分片起始点相对于报头的起始点的偏移量，
 * 由于分片到达时间可能错序，所以分片偏移字段可以使得接受者按照顺序重新组织报文。
 *-- 生存时间——  
 *	字段长度为8位，在最初创建报文时，TTL就被设定为某个特定值，当报
 *	文沿路由器传送时，每经过一个路由器TTL的值就会减小1，当TTL为零的时候，就会丢
 *	弃这个报文，同时向源地址发送错误报告，促使重新发送。
 *--协议――
 *	字段长度为8位，它给出了主机到主机或者传输层的地址或者协议号，协议字段
 *	中指定了报文中信息的类型，当前已分配了100多个不同的协议号。
 *-- 校验和――
 *	时针对IP报头的纠错字段，校验和的计算不能用被封装的数据内容，UDP/TCP/
 *	和ICMP都有各自的校验和，此字段包含一个16位的二进制补码和，这是由报文发送者计算得
 *	到的，接收者将联通院士校验和从新进行16位补码和计算，如果在传输中没有发生错误，
 *	那么16位补码值全部为1，由于路由器都会降低TTL值，所以路由器都会重新计算校验和。
 *-- 源地址――
 *	字段长度为32位，分别表示发送报文的路由器的源地址。
 *-- 目的地址――
 *	标识接收数据报文的路由器的地址。
 * */
typedef struct _IP_HEADER
{
	char m_cVersionAndHeaderLen;	//版本信息(前4位)，头长度(后4位)[0000],[0000]
	char m_cTypeOfService;			//服务类型1 [0000][0000]
	short m_sTotalLenOfPacket;		//数据包长度2
	short m_sPacketID;				//数据包标识2
	short m_sSliceinfo;				//分片使用2
	char m_cTTL;					//存活时间1
	char m_cTypeOfProtocol;			//协议类型 ipv4=0800 1
	short m_sCheckSum;				//校验和2
	unsigned int m_uiSourIp;		//源ip 4bt
	unsigned int m_uiDestIp;		//目的ip 4bt
} __attribute__((packed))IP_HEADER, *PIP_HEADER ;

/*
 * TCP头定义，共20个字节
 *
 *-- 序列号（32位) --
 *	用于标识每个报文段，使目的主机可确认已收到指定报文段中的数据。当源主机用于多个
 *	报文段发送一个报文时，即使这些报文到达目的主机的顺序不一样，序列号也可以使目的
 *	主机按顺序排列它们。在建立连接时发送的第一个报文段中，双方都提供一个初始序列号
 *	。TCP标准推荐使用以4ms间隔递增1的计数器值作为这个初始序列号的值。使用计数器可以
 *	防止连接关闭再重新连接时出现相同的序列号。对于那些包含数据的报文段，报文段中第
 *	一个数据字节的数量就是初始序列号，其后数据字节按顺序编号。如果源主机使用同样的
 *	连接发送另一个报文段，那么这个报文段的序列号等于前一个报文段的序列号与前一个报
 *	文段中数据字节的数量之和。例如，假设源主机发送3个报文段，每个报文段有100字节的
 *	数据，且第一个报文段的序列号是1000，那么第二个报文段的序列号就是1100（1000＋100）
 *	，第三个报文段的序列号就是1200（1100＋100）。如果序列号增大至最大值将复位为0。
 * -- 确认号（32位--
 *  目的主机返回确认号，使源主机知道某个或几个报文段已被接收。如果ACK控制位被设置为
 *  1，则该字段有效。确认号等于顺序接收到的最后一个报文段的序号加1，这也是目的主机
 *  希望下次接收的报文段的序号值。返回确认号后，计算机认为已接收到小于该确认号的所有数据.
 *  例如，序列号等于前一个报文段的序列号与前一个报文段中数据字节的数量之和。例如，
 *  假设源主机发送3个报文段，每个报文段有100字节的数据，且第一个报文段的序列号是1000，
 *  那么接收到第一个报文段后，目的主机返回含确认号1100的报头。接收到第二个报文段（其
 *  序号为1100）后，目的主机返回确认号1200。接收到第三个报文段后，目的主机返回确认号
 *  1300。
 *  目的主机不一定在每次接收到报文段后都返回确认号。在上面的例子中，目的主机可能等到
 *  所有3个报文段都收到后，再返回一个含确认号1300的报文段，表示已接收到全部1200字节
 *  的数据。但是如果目的主机再发回确认号之前等待时间过长，源主机会认为数据没有到达目
 *  的主机，并自动重发。
 *  上面的例子中，如果目的主机接收到了报文段号为1000的第一个报文段以及报文段号为1200
 *  的最后一个报文段，则可返回确认号1100，但是再返回确认号1300之前，应该等待报文段号
 *  为1100的中间报文段。
 *-- 报文长度（4位)-- 
 *	由于TCP报头的长度随TCP选项字段内容的不同而变化，因此报头中包含一个指定报头字段的
 *	字段。该字段以32比特为单位，所以报头长度一定是32比特的整数倍，有时需要在报头末尾
 *	补0。如果报头没有TCP选项字段，则报头长度值为5，表示报头一个有160比特，即20字节。
 *-- 保留位（6位) --
 *	 全部为0。
 *-- 控制位（6位）--
 *	 URG:报文段紧急。
 *	 ACK：确认号有效。
 *	 PSH：建议计算机立即将数据交给应用程序。
 *	 RST：复位连接。
 *	 SYN：进程同步。在握手完成后SYN为1，表示TCP建立已连接。此后的所有报文段中，SYN都被置0。
 *	 FIN：源主机不再有待发送的数据。如果源主机数据发送完毕，将把该连接下要发送的最后
 *	 一个报文段的报头中的FIN位置1，或将该报文段后面发送的报头中该位置1。
 *-- 窗口（16位）--
 *	 接收计算机可接收的新数据字节的数量，根据接收缓冲区可用资源的大小，其值随计算机所
 *	 发送的每个报文段而变化。源主机可以利用接收到的窗口值决定下一个报文段的大小。
 *-- 校验和（16位）--
 *	源主机和目的主机根据TCP报文段以及伪报头的内容计算校验和。在伪报头中存放着来自IP报
 *	头以及TCP报文段长度信息。与UDP一样，伪报头并不在网络中传输，并且在校验和中包含伪报
 *	头的目的是为了防止目的主机错误地接收存在路由的错误数据报。
 *-- 紧急指针（16位) --
 *	如果URG为1，则紧急指针标志着紧急数据的结束。其值是紧急数据最后1字节的序号，表示报文
 *	段序号的偏移量。例如，如果报文段的序号是1000，前8个字节都是紧急数据，那么紧急指针就
 *	是8。紧急指针一般用途是使用户可中止进程。
 * */
typedef struct _TCP_HEADER
{
	short m_sSourPort;				// 源端口号16bit
	short m_sDestPort;				// 目的端口号16bit
	unsigned int m_uiSequNum;		// 序列号32bit
	unsigned int m_uiAcknowledgeNum;// 确认号32bit
	short m_sHeaderLenAndFlag;		// 前4位：TCP头长度；中6位：保留；后6位：标志位
	short m_sWindowSize;			// 窗口大小16bit
	short m_sCheckSum;				// 检验和16bit
	short m_surgentPointer;			// 紧急数据偏移量16bit
}__attribute__((packed))TCP_HEADER, *PTCP_HEADER;


/*UDP头定义，共8个字节*/
typedef struct _UDP_HEADER
{
	unsigned short m_usSourPort;	// 源端口号16bit
	unsigned short m_usDestPort;	// 目的端口号16bit
	unsigned short m_usLength;		// 数据包长度16bit
	unsigned short m_usCheckSum;	// 校验和16bit
}__attribute__((packed))UDP_HEADER, *PUDP_HEADER;

/* tcp 内容 */
typedef struct _TCP_OPTIONS
{
	char m_ckind;
	char m_cLength;
	char m_cContext[32];
}__attribute__((packed))TCP_OPTIONS, *PTCP_OPTIONS;

/*
 *Mac地址16进制转换
 *a8:15:4d:1f:7d:68
 */
void mac_to_char(char *mac,unsigned char *str){
	int i;
	int v;
	for(i=0;i<sizeof(str);i++){
		sscanf(mac+3*i,"%2x",&v);
		str[i] = (char) v;
	}
}

// 填充MAC   
void set_hw_addr (char buf[], char *str)
{
              int i;
              char c, val;
              for(i = 0; i < 6; i++)
              {
                      if (!(c = tolower(*str++)))
                              perror("Invalid hardware address"),exit(1);
                     if (isdigit(c))
                             val = c - '0';
                     else if (c >= 'a' && c <= 'f')
                             val = c-'a'+10;
                     else
                             perror("Invalid hardware address"),exit(1);
                     buf[i] = val << 4;
                     if (!(c = tolower(*str++)))
                             perror("Invalid hardware address"),exit(1);
                     if (isdigit(c))
                             val = c - '0';
                     else if (c >= 'a' && c <= 'f')
                             val = c-'a'+10;
                     else
                             perror("Invalid hardware address"),exit(1);
                     buf[i] |= val;
                     if (*str == ':')
                             str++;
             }
}
/* 主函数 */
int main(int argc,char *argv[])
{
	//printf("HelloWorld!\n");

	/* create the ether header 1.0 */

	char dstMacAddress[] = "a8:15:4d:1f:7d:68";

	char srcMacAddress[] = "00:0C:29:46:B3:50";

	/*
	   MAC_FRAME_HEADER header;

	   mac_to_char(dstMacAddress,header.m_cDstMacAddress);

	   mac_to_char(srcMacAddress,header.m_cSrcMacAddress);

	   header.m_cType = 0x0806;


	   printf("header.m_cDstMacAddress = %2x\n",header.m_cDstMacAddress[0]);
	   printf("header.m_cDstMacAddress = %2x\n",header.m_cDstMacAddress[1]);
	   printf("header.m_cDstMacAddress = %2x\n",header.m_cDstMacAddress[2]);
	   printf("header.m_cDstMacAddress = %2x\n",header.m_cDstMacAddress[3]);
	   printf("header.m_cDstMacAddress = %2x\n",header.m_cDstMacAddress[4]);
	   printf("header.m_cDstMacAddress = %2x\n",header.m_cDstMacAddress[5]);

	   MAC_FRAME_TAIL tail;

	   tail.m_sCheckSum = 0;

	   printf("MAC_FRAME_TAIL m_sCheckSum = %u \n",tail.m_sCheckSum);

	   if(argc > 1)
	   {
	   printf("i=%s \n",argv[1]);
	   }
	   */
	/* Create the ether header 2.0 */

	struct ether_header eth_hdr;

	memset(&eth_hdr, 0,sizeof(struct ether_header));
	
	//针对以太网头部源地址进行赋值
	mac_to_char(dstMacAddress,eth_hdr.ether_dhost);

	//针对以太网头部目的地址进行赋值
	mac_to_char(srcMacAddress,eth_hdr.ether_shost);

	eth_hdr.ether_type = htons(ETHERTYPE_ARP);

	printf("ether_type : %02X \n", eth_hdr.ether_type);

	/* Create the arp packet */

	struct ether_arp arp;

	memset(&arp, 0, sizeof(struct ether_arp));

	arp.ea_hdr.ar_hrd = htons(ARPHRD_ETHER);

	arp.ea_hdr.ar_pro = htons(0x0800);

	arp.ea_hdr.ar_hln = 6;

	arp.ea_hdr.ar_pln = 4;

	arp.ea_hdr.ar_op = htons(ARPOP_REQUEST);

	/* create socket */

	int fd;

	fd = socket(AF_INET, SOCK_PACKET, htons(ETH_P_ARP));

	if(fd < 0){
		perror("socket open error!\n");
		exit(EXIT_FAILURE);
	}else{
		printf("socket open success!\n");
	}

	struct sockaddr sa;

	memset(&sa, 0, sizeof(struct sockaddr));

	strcpy(sa.sa_data,"wlan0");

	char buf[60];

	int hdr_len = sizeof(struct ether_header);

	int result;

	/* in address struct */

	char *src_ip_addr = "192.168.0.1";

	char *trc_ip_addr = "192.168.188.1";

	struct in_addr src_addr,trc_addr;

	memset(&src_addr, 0,sizeof(struct in_addr));

	//inet_aton(src_ip_addr, &src_addr);	

	if(inet_pton(AF_INET, src_ip_addr,(void *)&src_addr) < 0){
		perror("fail to convert\n");
		exit(1);
	}

	memset(&trc_addr, 0,sizeof(struct in_addr));

	//inet_aton(trc_ip_addr, &trc_addr);

	if(inet_pton(AF_INET, trc_ip_addr,(void *)&trc_addr) < 0){
		perror("fail to convert\n");
		exit(1);
	}                                                         
	/* set arp packet data */  	
	memcpy((void *) arp.arp_sha,(void *) eth_hdr.ether_shost, 6);

	memcpy((void *) arp.arp_spa,(void *) &src_addr, 4);

	memcpy((void *) arp.arp_tha,(void *) eth_hdr.ether_dhost, 6);

	memcpy((void *) arp.arp_tpa,(void *) &trc_addr, 4);

	memcpy(buf, &eth_hdr, hdr_len);

	memcpy(&buf[hdr_len], &arp, sizeof(struct ether_arp));
	//printf("sizeof buf :%d\n",(int)sizeof(buf));
	/*
	   FILE *logfile;

	   logfile=fopen("log.txt","w");

	   fprintf(logfile , "sdfsdf"); 

	   fclose(logfile);	
	   */

	result = sendto(fd, buf, sizeof(buf), 0, &sa, sizeof(sa));

	printf("attack %s\n!!\n", trc_ip_addr);

	printf("Sendto func result: %d \n",result);

	if(result < 0){
		printf("attack failure: %d \n",errno);
	}else{
		printf("attack success \n");
	}
	/**
	 * in_addr IPv4地址结构体
	 *
	 * inet_ntop();
	 *
	 * inet_pton();
	 *
	 * ip格式转换函数的使用
	 */
	char IPdotdec[20]; //存放点分十进制IP地址
	struct in_addr s; // IPv4地址结构体

	// 输入IP地址
	printf("Please input IP address: ");
	scanf("%s", IPdotdec);
	// 转换
	if( inet_pton(AF_INET, IPdotdec, (void *)&s) < 0){
		perror("fail to convert");
		exit(1);
	}
	printf("inet_pton: 0x%x\n", s.s_addr); // 注意得到的字节序

	// 反转换
	if(inet_ntop(AF_INET, (void *)&s, IPdotdec, 16) == NULL){
		perror("fail to convert");
		exit(0);
	}
	printf("inet_ntop: %s\n", IPdotdec);
	return 0;
}




















