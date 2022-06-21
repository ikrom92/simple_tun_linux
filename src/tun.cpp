#include "tun.hpp"

#include <linux/if.h>
#include <linux/if_tun.h>
#include <fcntl.h>
#include <unistd.h>
#include <cstring>
#include <sys/ioctl.h>
#include <netinet/ip.h>
#include <arpa/inet.h>
#include <ifaddrs.h>
#include <sys/epoll.h>

int tun_alloc(std::string& name) {

	int fd = open("/dev/net/tun", O_RDWR);
	if (fd < 0) {
		return fd;
	}

	struct ifreq ifr;
	std::memset(&ifr, 0, sizeof(ifr));
	ifr.ifr_ifru.ifru_flags = IFF_TUN | IFF_NO_PI;

	int err;
	if (err = ioctl(fd, TUNSETIFF, &ifr) < 0) {
		close(fd);
		return err;
	}

	name = ifr.ifr_ifrn.ifrn_name;
	return fd;
}

void tun_destroy(int fd) {
	close(fd);
}

void list_ifaces() {

	struct ifaddrs* ifap;
	if( getifaddrs(&ifap) == -1 ){
		printf("getifaddrs(): %s\n", strerror(errno));
	}
	else{
		struct ifaddrs* iter = ifap;
		char addr_buf[20];
		char mask_buf[20];
		printf("-== Available interfaces ==-\n");
		while( iter ){
			
			if( !iter->ifa_addr ){
				strcpy(addr_buf, "none");
				strcpy(mask_buf, "none");
			}
			else if( iter->ifa_addr->sa_family == AF_INET ){
				sockaddr_in* addr = (sockaddr_in*) iter->ifa_addr;
				inet_ntop(AF_INET, &addr->sin_addr, addr_buf, 20);
				addr = (sockaddr_in*) iter->ifa_netmask;
				inet_ntop(AF_INET, &addr->sin_addr, mask_buf, 20);
			}
			else if( iter->ifa_addr->sa_family == AF_INET6 ){
				sockaddr_in6* addr = (sockaddr_in6*) iter->ifa_addr;
				inet_ntop(AF_INET, &addr->sin6_addr, addr_buf, 20);
				addr = (sockaddr_in6*) iter->ifa_netmask;
				inet_ntop(AF_INET, &addr->sin6_addr, mask_buf, 20);
			}
			else{
				strcpy(addr_buf, "unrecognized");
				strcpy(mask_buf, "");
			}

			printf("%s\t%s\t%s\n", iter->ifa_name, addr_buf, mask_buf);
			iter = iter->ifa_next;
		}
		freeifaddrs(ifap);
		printf("\n");
	}
}

void dump_ipv4(unsigned char* buf, int size) {
	if (size < 20) {
		return;
	}

	// printf("\n");
	// for (int i = 0; i < size; ++i) {
	// 	printf("%02x", buf[i]);
	// }
	// printf("\n");

	unsigned char vihl = buf[0];
	int version = vihl >> 4;

	if (version == 4) {
		int ihl = vihl & 0x0F;
		int total_length = ntohs(reinterpret_cast<unsigned short*>(buf)[1]);
		int ttl = buf[8];
		int protocol = buf[9];

		printf("\nversion: %d\nihl: %d\ntotal length: %d\nttl: %d\nprotocol: %d\nsrc: %d.%d.%d.%d\ndst:%d.%d.%d.%d\n\n",
			version, ihl, total_length, ttl, protocol, (int)buf[12], (int)buf[13], (int)buf[14], (int)buf[15], (int)buf[16], (int)buf[17],(int) buf[18],(int) buf[19]);	
	}
	else if (version == 6) {
		int payload_length = ntohs(reinterpret_cast<unsigned short*>(buf)[2]);
		unsigned char next_header = buf[6];

		printf("\nversion: %d\npayload length: %d\nnext header: %02X (%d)\nsrc: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\ndst: %02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x:%02x%02x\n",
			version, payload_length, next_header, (int)next_header,
			buf[8], buf[9], buf[10], buf[11],
			buf[12], buf[13], buf[14], buf[15],
			buf[16], buf[17], buf[18], buf[19],
			buf[20], buf[21], buf[22], buf[23],
			buf[24], buf[25], buf[26], buf[27],
			buf[28], buf[29], buf[30], buf[31],
			buf[32], buf[33], buf[34], buf[35],
			buf[36], buf[37], buf[38], buf[39]);

		if (next_header == 58) { // icmpv6
			printf("payload: ICMPv6\n");
			printf("\ttype: %d\n", buf[40]);
			printf("\tcode: %d\n", buf[41]);
			printf("\tcheksum: 0x%02X%02X\n", buf[42], buf[43]);
			printf("\tmessage: 0x%02X%02X%02X%02X\n\n", buf[44], buf[45], buf[46], buf[47]);
		}
		else {
			printf("payload: 0x");
			for (int i = 0; i < payload_length; ++i) {
				printf("%02x", buf[40 + i]);
			}
			printf("\n\n");
		}
	}
	else {
		printf("unknown ip version\n");
	}


}

void loop(int fd, bool& running) {

	fcntl(fd, F_SETFL, O_NONBLOCK);

	int efd = epoll_create1(0);
	if (efd < 0) {
		printf("epoll_create() failed\n");
		exit(-1);
	}

	epoll_event e;
	e.events = EPOLLIN | EPOLLERR;
	e.data.fd = fd;
	epoll_ctl(efd, EPOLL_CTL_ADD, fd, &e);

	epoll_event events[10];
	char rdbuf[1500];

	while (running) {

		int nfds = epoll_wait(efd, events, 20, 100);
		if (nfds == -1) {
			int error = errno;
			printf("epoll_wait failed: error = %d, text = %s\n", error, strerror(error));
			break;
		}
		else if (nfds > 0) {
			int bytes_read = read(fd, rdbuf, sizeof(rdbuf));
			printf("read %d bytes\n", bytes_read);
			dump_ipv4((unsigned char*)rdbuf, bytes_read);
		}

	}

	close(efd);
	printf("eof\n");
}

void set_ip_address(int fd, const char* name, const std::string& ip, const std::string& mask) {

	int s = socket(AF_INET, SOCK_DGRAM, IPPROTO_IP);
	
	struct ifreq ifr;
	std::memset(&ifr, 0, sizeof(ifr));
	std::strcpy(ifr.ifr_ifrn.ifrn_name, name);

	struct sockaddr_in* addr = (struct sockaddr_in*)&ifr.ifr_ifru.ifru_addr;
	addr->sin_family = AF_INET;

	inet_pton(AF_INET, ip.c_str(), &addr->sin_addr);
	if (ioctl(s, SIOCSIFADDR, &ifr) < 0) {
		int err = errno;
		printf("cannot set ip address. errno = %d, text = %s\n", err, strerror(err));
		return;
	}

	inet_pton(AF_INET, mask.c_str(), &addr->sin_addr);
	if (ioctl(s, SIOCSIFNETMASK, &ifr) < 0) {
		int err = errno;
		printf("cannot set net mask. errno = %d, text = %s\n", err, strerror(err));
		return;
	}

	if (ioctl(s, SIOCGIFFLAGS, &ifr) < 0) {
		int err = errno;
		printf("cannot ifup interfaces. errno = %d, text = %s\n", err, strerror(err));
		return;
	}

	ifr.ifr_ifru.ifru_flags |= IFF_UP;
	// ifr.ifr_ifru.ifru_flags |= IFF_RUNNING;
	std::strcpy(ifr.ifr_ifrn.ifrn_name, name);
	if (ioctl(s, SIOCSIFFLAGS, &ifr) < 0) {
		int err = errno;
		printf("cannot ifup interfaces. errno = %d, text = %s\n", err, strerror(err));
		return;
	}
	close(s);
}


