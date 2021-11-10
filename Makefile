CC = gcc
CFLAGS = -Wall -O2
ALL = bpf_capture bpf_send_garp

all: $(ALL)

bpf_capture: bpf_capture.o bpf.o

bpf_send_garp: bpf_send_garp.o bpf.o

clean:
	rm -f *.o
	rm -f $(ALL)
