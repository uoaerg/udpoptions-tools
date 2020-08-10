#!/usr/bin/env python3

import struct
import socket

UDPOPT_EOL = 0
UDPOPT_NOP = 1
UDPOPT_OCS = 2
UDPOPT_ACS = 3
UDPOPT_LITE = 4
UDPOPT_MSS = 5
UDPOPT_TIME = 6
UDPOPT_FRAG = 7
UDPOPT_AE = 8
UDPOPT_ECHOREQ = 9
UDPOPT_ECHORES = 10

UDPOLEN_EOL = 0
UDPOLEN_NOP = 0
UDPOLEN_OCS = 2
UDPOLEN_ACS = 4
UDPOLEN_LITE = 4
UDPOLEN_MSS = 4
UDPOLEN_TIME = 10
UDPOLEN_FRAG = 12
UDPOLEN_ECHOREQ = 6
UDPOLEN_ECHORES = 6

def calculateocs(pkt):     
    res = 0                 
    for b in pkt:           
        res = res + b       
                            
    while res > 0x00FF:     
        high = 0xFF00 & res 
        low =  0x00FF & res 
                            
        high = high >> 8    
                            
        res = low + high    
    return res ^ 0xFF       

# parse udp options tlv into a dictionary
def udp_dooptions(buf):
        ocs = calculateocs(buf)
        if ocs != 0:
                print("OCS failed {} but should be 0".format(hex(ocs)))

        opts = {}
        cnt = len(buf)
        optlen = 0
        cp = 0

        while (cnt > 0):
                cnt = cnt - optlen
                cp = cp + optlen

                # 
                # Parse the required options that define the packet
                #
                opt = buf[cp]
                if opt == UDPOPT_EOL:
                        optlen = 1
                        return opts
                if opt == UDPOPT_NOP:
                        optlen = 1
                        continue

                if opt == UDPOPT_OCS:
                        opts['UDPOPT_OCS'] = buf[cp+1]
                        optlen = 2
                        continue

                optlen = buf[cp+1]

                # 
                # Parse useful options
                #
                if opt == UDPOPT_MSS:      
                    mss = struct.unpack("!h", buf[optlen:optlen+2])[0]
                    opts['UDPOPT_MSS'] = mss

                if opt == UDPOPT_TIME:     
                    tsval, tsecr = struct.unpack("!ii", buf[optlen:optlen+8])
                    opts['UDPOPT_TIME'] = (tsval, tsecr)

                if opt == UDPOPT_ECHOREQ:
                    token = struct.unpack("!h", buf[optlen:optlen+2])[0]
                    opts['UDPOPT_ECHOREQ'] = token

                if opt == UDPOPT_ECHORES:
                    token = struct.unpack("!h", buf[optlen:optlen+2])[0]
                    opts['UDPOPT_ECHORES'] = token

def udp_addoptions(opts):

        optbuf = bytearray(100)

        # place the ocs
        optbuf[0] = UDPOPT_OCS
        optbuf[1] = 0

        optlen = 2
        
        if 'UDPOPT_TIME' in opts:
            optbuf[optlen] = UDPOPT_TIME
            optbuf[optlen+1] = UDPOLEN_TIME

            tsval, tsecr = opts['UDPOPT_TIME']


            struct.pack_into("!I", optbuf, optlen+2, tsval)
            struct.pack_into("!I", optbuf, optlen+6, tsecr)
            optlen = optlen + UDPOLEN_TIME

        if 'UDPOPT_MSS' in opts:
            optbuf[optlen] = UDPOPT_MSS
            optbuf[optlen+1] = UDPOLEN_MSS

            mss = opts['UDPOPT_MSS']
            struct.pack_into("!I", optbuf, optlen+2, mss)
            optlen = optlen + UDPOLEN_MSS

        if 'UDPOPT_ECHOREQ' in opts:
            optbuf[optlen] = UDPOPT_ECHOREQ
            optbuf[optlen+1] = UDPOLEN_ECHOREQ

            token = opts['UDPOPT_ECHOREQ']
            struct.pack_into("!I", optbuf, optlen+2, token)
            optlen = optlen + UDPOLEN_ECHOREQ

        if 'UDPOPT_ECHORES' in opts:
            optbuf[optlen] = UDPOPT_ECHORES
            optbuf[optlen+1] = UDPOLEN_ECHORES

            token = opts['UDPOPT_ECHORES']
            struct.pack_into("!I", optbuf, optlen+2, token)
            optlen = optlen + UDPOLEN_ECHORES

        #add a nop
        optbuf[optlen] = UDPOPT_NOP
        optlen = optlen + 1

        optbuf[optlen] = UDPOPT_EOL
        optlen = optlen + 1

        optbuf = optbuf[:optlen]
        optbuf[1] = calculateocs(optbuf)

        return optbuf

if __name__ == "__main__":
        options = udp_dooptions(
                bytearray(
                    [0x02,0x7f,0x06,0x0A,0x40,0x30,0x20,0x10,0x40,0x30,0x20,0x10,0x05,0x04,0x0F,0x0F,0x09,0x04,0x0F,0x0F,0x0A,0x04,0x0F,0x0F,0x01,0x01,0x01,0x01,0x01,0x01,0x00]))

        optbuf = udp_addoptions(options)

        print(options)
        print(optbuf)
