
# Summary

Examples of sending and receiving packets by using BPF(Berkeley Packet Filter).

# Platforms

- Mac OS X (Tested on Big Sur)
- FreeBSD (Tested on FreeBSD13)

# How to build

Use GNU Make.

Mac OS X

    # make

FreeBSD

    # gmake

The following two files will be created.

bpf_send_garp

Example of sending packets.
This binary sends a Gratuitous ARP from specified interface.

bpf_capture

Example of receiving packets.
This binary captures packets from specified interface, like tcpdump.
It just outputs hexadecimal dump. No parsing packet data.

# Usage Example

    # sudo ./bpf_send_garp en1
    # sudo ./bpf_capture en1

