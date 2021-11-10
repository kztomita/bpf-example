#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/socket.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <netinet/in.h>
#include <net/ethernet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <net/if_dl.h>
#include <net/if_types.h>
#include <net/bpf.h>
#include "bpf.h"

void usage()
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "bpf_send_garp <if name>\n");
	exit(-1);
}

int get_inaddr(const char *if_name, struct sockaddr_in *saddr)
{
	int fd;
	struct ifreq ifr;

	if ((fd = socket(AF_INET, SOCK_STREAM, 0)) == -1) {
		perror("socket()");
		return -1;
	}

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name) - 1);
	if(ioctl(fd, SIOCGIFADDR, &ifr) < 0){
		perror("ioctl(SIOCGIFADDR)");
		close(fd);
		return -1;
	}

	*saddr = *((struct sockaddr_in *) &ifr.ifr_addr);

	return 0;
}

int get_hwaddr(const char *if_name, struct sockaddr_dl *addr)
{
	unsigned int ifindex;
	struct ifaddrs *ifaddr, *ifa;
	int family;
	struct sockaddr_dl* sdl;

	ifindex = if_nametoindex(if_name);
	if (ifindex == 0) {
		perror("if_nametoindex()");
		return -1;
	}

	if (getifaddrs(&ifaddr) == -1) {
		perror("getifaddrs");
		return -1;
	}

	for (ifa = ifaddr ; ifa != NULL ; ifa = ifa->ifa_next) {
		if (ifa->ifa_addr == NULL) {
			continue;
		}
		family = ifa->ifa_addr->sa_family;

		if (family == AF_LINK) {
			sdl = (struct sockaddr_dl*) ifa->ifa_addr;
			if (sdl->sdl_type == IFT_ETHER &&
			    sdl->sdl_alen == ETHER_ADDR_LEN &&
			    sdl->sdl_index == ifindex) {
				addr->sdl_len = sizeof(struct sockaddr_dl);
				addr->sdl_family = sdl->sdl_family;
				addr->sdl_index = sdl->sdl_index;
				addr->sdl_type = sdl->sdl_type;
				addr->sdl_nlen = 0;
				addr->sdl_alen = sdl->sdl_alen;
				addr->sdl_slen = 0;
				memcpy(addr->sdl_data, LLADDR(sdl), sdl->sdl_alen);

				freeifaddrs(ifaddr);
				return 0;
			}
		}
	}

	freeifaddrs(ifaddr);

	return -1;
}

unsigned char *create_garp_packet(const struct sockaddr_dl *mac, const struct sockaddr_in *saddr, size_t *size)
{
	unsigned char *buff;
	struct ether_header *ether;
	struct arphdr *arp;
	unsigned char *p;

	*size = sizeof(struct ether_header) + sizeof(struct arphdr) +
		ETHER_ADDR_LEN * 2 + sizeof(struct in_addr) * 2;

	buff = malloc(*size);
	if (buff == NULL) {
		fprintf(stderr, "Can't allocate memory.\n");
		return NULL;
	}

	ether = (struct ether_header *) buff;
	arp = (struct arphdr *) (buff + sizeof(struct ether_header));

	memset(ether->ether_dhost, 0xff, ETHER_ADDR_LEN);
        memcpy(ether->ether_shost, LLADDR(mac), ETHER_ADDR_LEN);
        ether->ether_type = htons(ETHERTYPE_ARP);	/* 0x0806 */

	arp->ar_hrd = htons(ARPHRD_ETHER);  /* Ethernet(0x0001) */
	arp->ar_pro = htons(ETHERTYPE_IP);  /* 0x0800 */
	arp->ar_hln = ETHER_ADDR_LEN;
        arp->ar_pln = sizeof(struct in_addr);
        arp->ar_op  = htons(ARPOP_REQUEST);

	p = (unsigned char *) (arp + 1);
	memcpy(p, LLADDR(mac), ETHER_ADDR_LEN);
	p += ETHER_ADDR_LEN;
	memcpy(p, &saddr->sin_addr, sizeof(struct in_addr));
	p += sizeof(struct in_addr);
        memset(p, 0, ETHER_ADDR_LEN);
	p += ETHER_ADDR_LEN;
	memcpy(p, &saddr->sin_addr, sizeof(struct in_addr));

	return buff;
}

int send_packet(int fd, const unsigned char *buff, size_t size)
{
	/*
	 * If you send data smaller than 60 bytes, it will be
	 * padded automatically.
	 *
	 * Ethernet Minimum Frame Size(64 bytes) =
	 *     payload(60bytes) + FCS(4bytes)
	 */
	if (write(fd, buff, size) < 0) {
		perror("write()");
		return -1;
	}

	return 0;
}

int main(int argc, char *argv[])
{
	char *if_name;
	struct sockaddr_in saddr_in;
	struct sockaddr_dl saddr_dl;
	int fd;
	unsigned char *packet;
	size_t packet_size;

	if (argc < 2) {
                usage();
        }

        if_name = argv[1];

	if (get_inaddr(if_name, &saddr_in) == -1) {
		return -1;
	}
	if (get_hwaddr(if_name, &saddr_dl) == -1) {
		return -1;
	}

	fd = open_bpf(if_name);
	if (fd < 0) {
		return -1;
	}

	packet = create_garp_packet(&saddr_dl, &saddr_in, &packet_size);
	if (packet == NULL) {
		close(fd);
		return -1;
	}

	if (send_packet(fd, packet, packet_size) == -1) {
		free(packet);
		close(fd);
		return -1;
	}

	free(packet);
	close(fd);

	return 0;
}
