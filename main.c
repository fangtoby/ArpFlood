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
// 数据帧最小长度 46 byte
#define MIN_PACK_SIZE 46
// 数据帧最大长度 1500 byte
#define MAX_PACK_SIZE 1500

/* mac 数据帧头部定义，头14个字节，尾4个字节*/
typedef struct _MAC_FRAME_HEADER
{
	unsigned char m_cDstMacAddress[6];	//目的mac地址 a8:15:4d:1f:7d:68
	unsigned char m_cSrcMacAddress[6];	//源mac地址 a8:15:4d:1f:7d:68
	short m_cType;				//上一层协议类型，如0x0800代表上一层是IP协议，0x0806为arp
}__attribute__((packed))MAC_FRAME_HEADER,*PMAC_FRAME_HEADER;

/* mac 数据帧尾部 */
typedef struct _MAC_FRAME_TAIL
{
	unsigned int m_sCheckSum;	//数据帧尾校验和
}__attribute__((packed))MAC_FRAME_TAIL, *PMAC_FRAME_TAIL;

/*IP头定义，共20个字节*/
typedef struct _IP_HEADER
{
	char m_cVersionAndHeaderLen;	//版本信息(前4位)，头长度(后4位)
	char m_cTypeOfService;			//服务类型8位
	short m_sTotalLenOfPacket;		//数据包长度
	short m_sPacketID;				//数据包标识
	short m_sSliceinfo;				//分片使用
	char m_cTTL;					//存活时间
	char m_cTypeOfProtocol;			//协议类型
	short m_sCheckSum;				//校验和
	unsigned int m_uiSourIp;		//源ip
	unsigned int m_uiDestIp;		//目的ip
} __attribute__((packed))IP_HEADER, *PIP_HEADER ;

/*TCP头定义，共20个字节*/
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

void mac_to_char(char *mac,unsigned char *str){
	int i;
	int v;
	for(i=0;i<sizeof(str);i++){
		sscanf(mac+3*i,"%2x",&v);
		str[i] = (char) v;
	}
}
/* 主函数 */
int main(int argc,char *argv[])
{
	printf("HelloWorld!\n");

	MAC_FRAME_HEADER header;

	char dstMacAddress[] = "a8:15:4d:1f:7d:68";

	char srcMacAddress[] = "c8:bc:c8:92:3e:05";

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
	return 0;
}
