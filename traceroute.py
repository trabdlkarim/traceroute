#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Created on Tue Jul  7 22:38:24 2020

@author: trabdlkarim
"""



import os
import sys
import time
import socket
import struct

ICMP_ECHO_REQUEST = 8
PAYLOAD = "bbHHh"
MAX_HOPS = 30

class Traceroute(object):
    def __init__(self,hostname):
        self.hostname = hostname
        self.ttl = 1
        self.rtt = [0.0, 0.0, 0.0]
        self.dest = ["","",""]
        self.sock_dgram= socket.socket(socket.AF_INET,socket.SOCK_DGRAM,socket.IPPROTO_ICMP)
        self.sock_raw = socket.socket(socket.AF_INET,socket.SOCK_RAW,socket.IPPROTO_ICMP)
        self.sock_raw.bind(('', 0))
        self.sock_raw.settimeout(1.5)

    def __checksum(self,string):
        string = bytearray(string)
        chksum = 0
        limit = (len(string) // 2) * 2
        for i in range(limit,2):
            val = string[i] + (string[i+1]*256)
            chksum += val
            chksum = chksum & 0xffffffff

        if limit < len(string):
            chksum += string[-1]
            chksum = chksum & 0xffffffff

        chksum = (chksum >> 16) + (chksum & 0xffff)
        chksum = chksum + (chksum >> 16)

        chksum = ~chksum
        chksum = chksum & 0xffff
        chksum = chksum >> 8 | (chksum << 8 & 0xff00)

        return chksum

    def __build_pack(self):
        checksum = 0
        id_ = os.getpid() & 0xFFFF
        header = struct.pack(PAYLOAD, ICMP_ECHO_REQUEST, 0, checksum, id_, 1)
        data = struct.pack("d", time.time())
        packet = header + data
        checksum = self.__checksum(packet)
        checksum = socket.htons(checksum)

        header = struct.pack(PAYLOAD, ICMP_ECHO_REQUEST, 0, checksum, id_, 1)
        packet = header + data

        return packet

    def get_route_packets_trace(self):
        try:
            host_addr = socket.gethostbyname(self.hostname)
            print("traceroute to {} ({}), {} hops max, {} byte packets".format(self.hostname,host_addr,MAX_HOPS,len(PAYLOAD)))
            stop = False
            with self.sock_dgram, self.sock_raw:
                while not stop:
                    packet = self.__build_pack()
                    self.sock_dgram.setsockopt(socket.IPPROTO_IP, socket.IP_TTL, struct.pack('I', self.ttl))
                    try:
                        for i in range(3):
                            t1 = time.time()
                            self.sock_dgram.sendto(packet, (host_addr,0))
                            icmp_msg, addr = self.sock_raw.recvfrom(1024)
                            t2 = time.time()
                            self.rtt[i]= "%.4f" % ((t2-t1)*1000)
                            self.dest[i]= addr[0]
                        if self.dest[0] == self.dest[1] and self.dest[1] == self.dest[2]:
                            trace = "TTL = {:<3} {} ({}) {} ms  {} ms  {} ms".format(self.ttl,socket.gethostbyaddr(self.dest[0])[0],self.dest[0],self.rtt[0],self.rtt[1],self.rtt[2])
                        elif  self.dest[0] != self.dest[1] and self.dest[1] != self.dest[2]:
                             trace = "TTL = {:<3} {} ({}) {} ms  {} ({}) {} ms  {} ({}){} ms".format(self.ttl,socket.gethostbyaddr(self.dest[0])[0],
                                                                                                     self.dest[0],self.rtt[0],socket.gethostbyaddr(self.dest[1])[0],
                                                                                                     self.dest[1],self.rtt[1],socket.gethostbyaddr(self.dest[2])[0],
                                                                                                     self.dest[2],self.rtt[2])
                        elif self.dest[0] == self.dest[1] and self.dest[1] != self.dest[2]:
                            trace = "TTL = {:<3} {} ({}) {} ms  {} ms  {} ({}){} ms".format(self.ttl,socket.gethostbyaddr(self.dest[0])[0],
                                                                                                     self.dest[0],self.rtt[0],self.rtt[1],socket.gethostbyaddr(self.dest[2])[0],
                                                                                                     self.dest[2],self.rtt[2])
                        elif self.dest[0] != self.dest[1] and self.dest[1] == self.dest[2]:
                            trace = "TTL = {:<3} {} ({}) {} ms  {} ({}){} ms {} ms".format(self.ttl,socket.gethostbyaddr(self.dest[0])[0],
                                                                                                     self.dest[0],self.rtt[0],self.rtt[1],socket.gethostbyaddr(self.dest[1])[0],
                                                                                                     self.dest[1],self.rtt[2])

                    except socket.timeout:
                        trace = "TTL = {:<3} ***".format(self.ttl)
                    except socket.herror:
                        trace = "TTL = {:<3} {} ({}) {} ms  {} ms  {} ms".format(self.ttl,self.dest[0],self.dest[0],self.rtt[0],self.rtt[1],self.rtt[2])
                    print(trace)
                    self.ttl += 1
                    if self.dest[0] == host_addr or self.ttl > MAX_HOPS:
                        stop = True
        except Exception as ex:
            #print(str(ex))
            raise ex

def main(argv):
    tracker = Traceroute(argv[0])
    tracker.get_route_packets_trace()

if __name__ == "__main__":
    if len(sys.argv) > 1:
        main(sys.argv[1:])
    else:
        print("Hostname required but none given.")
        print("Usage: traceroute HOSTNAME")