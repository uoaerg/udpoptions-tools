#!/usr/bin/env python

import struct

def hexdump(databytes):
    total = 0
    count = 0
    for b in databytes:
        print("{:02x} ".format(b), end='')
        count = count + 1
        if count % 8 == 0:
            print(" ", end='')
        if count % 16 == 0:
            print("")

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
    data = bytes("Hello World\x01\x01\x01\x01\x01\x01\x00", 'ascii')
    sourceaddr = bytearray([139, 133, 204, 55])
    destaddr = bytearray([139, 133, 204, 4])
    proto = 17
    udplen = 8 + len(data)
    sport = 2600
    dport = 2500
    cksum = 0

    pkt = struct.pack("!4s4sBBHHHHH{}s".format(len(data)),
        sourceaddr, destaddr,
        0, proto, udplen,
        sport, dport,
        udplen, cksum,
        data)

    result = internetchecksum(pkt)
    print("checksum: {}".format(hex(result)))

    options = bytearray([0x02,0x00,0x01,0x01,0x01,0x01,0x00])
    options[1] = 0x00

    result = calculateocs(options)
    print("checksum: 0x{:02x}".format(result))

    options[1] = result
    result = calculateocs(options)
    print("inverse:  0x{:02x}".format(result))
