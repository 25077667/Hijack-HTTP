#!/usr/bin/python
from bcc import BPF

from sys import argv
import socket
import os

# Nodified from https://github.com/iovisor/bcc/blob/e83019bdf6c400b589e69c7d18092e38088f89a8/examples/networking/http_filter/http-parse-simple.py


def usage():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("Try '%s -h' for more options." % argv[0])
    exit()


def help():
    print("USAGE: %s [-i <if_name>]" % argv[0])
    print("")
    print("optional arguments:")
    print("   -h                       print this help")
    print("   -i if_name               select interface if_name. Default is eth0")
    print("")
    exit()


def do_bpf(ifname: str):
    print("binding socket to {ifname}")
    b = BPF(src_file="http_filter.c", debug=0)

    # load eBPF program http_filter of type SOCKET_FILTER into the kernel eBPF vm
    # more info about eBPF program types
    # http://man7.org/linux/man-pages/man2/bpf.2.html
    function_http_filter = b.load_func("http_filter", BPF.SOCKET_FILTER)

    # create raw socket, bind it to interface
    # attach bpf program to socket created
    BPF.attach_raw_socket(function_http_filter, ifname)

    # get file descriptor of the socket previously created inside BPF.attach_raw_socket
    socket_fd = function_http_filter.sock

    # create python socket object, from the file descriptor
    sock = socket.fromfd(socket_fd, socket.PF_PACKET,
                         socket.SOCK_RAW, socket.IPPROTO_IP)
    # set it as blocking socket
    sock.setblocking(True)

    while 1:
        # retrieve raw packet from socket
        os.read(socket_fd, 2048)


def main():
    interface = "eth0"
    if len(argv) == 2:
        if str(argv[1]) == '-h':
            help()
        else:
            usage()

    if len(argv) == 3:
        if str(argv[1]) == '-i':
            interface = argv[2]
        else:
            usage()

    if len(argv) > 3:
        usage()

    do_bpf(interface)


if __name__ == '__main__':
    main()
