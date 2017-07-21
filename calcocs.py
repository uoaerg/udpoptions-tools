#!/usr/bin/env python

import struct
import sys

def internetchecksum(pkt):
    if len(pkt) % 2 != 0:
        a = bytearray(pkt)
        a.append(0)
        pkt = bytes(a) # python is such a cluster fuck

    databytes = struct.unpack("!{}H".format(int(len(pkt)/2)), pkt)
    total = 0
    for b in databytes:
        total = total + b

    while total > 0xFFFF:
        high = 0xFFFF0000 & total
        low = 0x0000FFFF & total

        high = high >> 16

        total = low + high
    return total ^ 0xFFFF

def calculateocs(pkt):
    res = internetchecksum(pkt)
    print("computed in ck: {:04x}".format(res))
    res = res ^ 0xFFFF
    print("computed in ck: {:04x}".format(res))

    while res > 0x00FF:
        high = 0xFF00 & res
        low =  0x00FF & res

        high = high >> 8

        res = low + high
    return res ^ 0xFF

def calculate8bit(pkt):
    res = 0
    for b in pkt:
        res = res + b

    while res > 0x00FF:
        high = 0xFF00 & res
        low =  0x00FF & res

        high = high >> 8

        res = low + high
    return res ^ 0xFF

if __name__ == "__main__":
    if len(sys.argv) == 1:
        exit()

    symbols = sys.argv[1:] 

    values = []    

    for s in symbols:
        values.append(int(s, 16))
    values = bytearray(values)

    print("OCS: 0x{:02x}".format(calculate8bit(values)))
