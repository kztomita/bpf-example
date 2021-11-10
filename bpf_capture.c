#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <stdlib.h>
#include <sys/errno.h>
#include <sys/ioctl.h>
#include <fcntl.h>
#include <net/if.h>
#include <net/bpf.h>
#include "bpf.h"

#define MAX_DUMP_SIZE  200

void usage()
{
	fprintf(stderr, "Usage:\n");
	fprintf(stderr, "bpf_capture <if name>\n");
	exit(-1);
}

void dump_buffer(const u_char *buff, size_t n, size_t limit)
{
	int i;

	for (i = 0 ; i < n ; i++) {
		if (i == limit) {
			printf("snipped...");
			break;
		}
		if (i % 16 == 0) {
			printf("%08x  ", i);
		}
		printf("%02x ", buff[i]);
		if (i % 16 == 15) {
			printf("\n");
		}
	}
	printf("\n");
}

int main(int argc, char *argv[])
{
	char *if_name;
	int fd;
	u_char *buff, *end;
	ssize_t received;
	u_int blen;
	struct bpf_hdr *bpfhdrp;
	u_char *packet;

	if (argc < 2) {
                usage();
        }

        if_name = argv[1];

	fd = open_bpf(if_name);
	if (fd == -1) {
		return -1;
	}

	/*
	 * Read buffer size must be equal to which returned by
	 * the BIOCGBLEN ioctl.
	 */
	if (ioctl(fd, BIOCGBLEN, &blen) == -1) {
		perror("ioctl()");
		close(fd);
		return -1;
	}

	buff = malloc(blen);
	if (buff == NULL) {
		fprintf(stderr, "Can't allocate memory.\n");
		close(fd);
		return -1;
	}

	while (1) {
		received = read(fd, (void *) buff, blen);
		if (received == -1) {
			perror("read");
			break;
		}
		end = buff + received;

		bpfhdrp = (struct bpf_hdr *) buff;

		while ((u_char *) bpfhdrp < end) {
			if ((u_char *) bpfhdrp + sizeof(struct bpf_hdr) > end) {
				fprintf(stderr, "Insufficient buffer size.\n");
				break;
			}

			printf("Captured Length: %d, Packet Length: %d\n",
			       bpfhdrp->bh_caplen, bpfhdrp->bh_datalen);

			packet = (u_char *) bpfhdrp + bpfhdrp->bh_hdrlen;

			if (packet + bpfhdrp->bh_caplen > end) {
				fprintf(stderr, "Insufficient buffer size.\n");
				break;
			}

			dump_buffer(packet, bpfhdrp->bh_caplen, MAX_DUMP_SIZE);

			/* next bpf_hdr */
			bpfhdrp = (struct bpf_hdr *)
				((char *) bpfhdrp +
				 BPF_WORDALIGN(bpfhdrp->bh_hdrlen + bpfhdrp->bh_caplen));
		}
	}

	free(buff);
	close(fd);

	return 0;
}

