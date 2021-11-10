#include "bpf.h"
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/bpf.h>

int open_bpf(const char *if_name)
{
	int fd;
	int i = 0;
	char buff[32];
	struct ifreq ifr;
	int immediate = 1;
	int promiscuous = 1;
#if defined(BIOCSDIRECTION)
	u_int direction = BPF_D_INOUT;
#endif
	u_int header_complete = 1;

	while (1) {
		sprintf(buff, "/dev/bpf%d", i);
		fd = open(buff, O_RDWR);
		if (fd != -1) {
			break;
		}
		/* error */
		if (errno == EBUSY) {
			i++;
			continue;
		} else if (errno == ENOENT) {
			fprintf(stderr, "All bpf are busy.\n");
			return -1;
		}

		fprintf(stderr, "Can't open bpf.\n");
		perror("open");
		return -1;
	}

	printf("Opened /dev/bpf%d\n", i);

	memset(&ifr, 0, sizeof(ifr));
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name) - 1);
	if (ioctl(fd, BIOCSETIF, &ifr) == -1) {
		perror("ioctl(BIOCSETIF)");
		close(fd);
		return -1;
	}

	if (ioctl(fd, BIOCIMMEDIATE, &immediate) < 0) {
		perror("ioctl(BIOCIMMEDIATE)");
		close(fd);
		return -1;
	}

	if (ioctl(fd, BIOCPROMISC, &promiscuous) == -1) {
		perror("ioctl(BIOCPROMISC)");
		close(fd);
		return -1;
	}

#if defined(BIOCSDIRECTION)
	if (ioctl(fd, BIOCSDIRECTION, &direction) == -1) {
		perror("ioctl(BIOCSDIRECTION)");
		close(fd);
		return -1;
	}
#endif

	/*
	 * header_complete
	 * 0: SMAC in L2 header are filled in automatically (default).
	 * 1: SMAC in L2 header is sent with the specified value.
	 */
	if (ioctl(fd, BIOCSHDRCMPLT, &header_complete) == -1) {
		perror("ioctl(BIOCSHDRCMPLT)");
		close(fd);
		return -1;
	}

	return fd;
}



