#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <net/if.h>
#include <unistd.h>
#include <netinet/in.h>
#include <string.h>

int main()
{
	struct ifreq ifr;
	struct ifconf ifc;
	char buf[2048];
	int success = 0;

	int sock = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	if (sock == -1) {
		printf("socket error\n");
		return -1;
	}

	ifc.ifc_len = sizeof(buf);
	ifc.ifc_buf = buf;
	if (ioctl(sock, SIOCGIFCONF, &ifc) == -1) {
		printf("ioctl error\n");
		return -1;
	}

	struct ifreq* it = ifc.ifc_req;
	const struct ifreq* const end = it + (ifc.ifc_len / sizeof(struct ifreq));
	char szMac[64];
	int count = 0;
	for (; it != end; ++it) {
		strcpy(ifr.ifr_name, it->ifr_name);
		if (ioctl(sock, SIOCGIFFLAGS, &ifr) == 0) {
			if (! (ifr.ifr_flags & IFF_LOOPBACK)) { // don't count loopback
				if (ioctl(sock, SIOCGIFHWADDR, &ifr) == 0) {
					count ++ ;
					unsigned char * ptr ;
					ptr = (unsigned char  *)&ifr.ifr_ifru.ifru_hwaddr.sa_data[0];
					snprintf(szMac,64,"%02X:%02X:%02X:%02X:%02X:%02X",*ptr,*(ptr+1),*(ptr+2),*(ptr+3),*(ptr+4),*(ptr+5));
					printf("%d,Interface name : %s , Mac address : %s \n",count,ifr.ifr_name,szMac);
				}
			}
		}else{
			printf("get mac info error\n");
			return -1;
		}
	}
}
