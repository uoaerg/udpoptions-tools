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
        opts['optionspacelength'] = len(buf)
        opts['optionsdata'] = [hex(x) for x in buf]
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
                    mss = struct.unpack("!H", buf[cp+2:cp+UDPOLEN_MSS])[0]
                    opts['UDPOPT_MSS'] = mss

                if opt == UDPOPT_TIME:     
                    tsval, tsecr = struct.unpack("!II", buf[cp+2:cp+UDPOLEN_TIME])
                    opts['UDPOPT_TIME'] = (tsval, tsecr)

                if opt == UDPOPT_ECHOREQ:
                    token = struct.unpack("!I", buf[cp+2:cp+UDPOLEN_ECHOREQ])[0]
                    opts['UDPOPT_ECHOREQ'] = token

                if opt == UDPOPT_ECHORES:
                    token = struct.unpack("!I", buf[cp+2:cp+UDPOLEN_ECHORES])[0]
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
            struct.pack_into("!H", optbuf, optlen+2, mss)
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

def checkocsfromstr(options):
    data = bytearray(int(x, 16) for x in options.split(" "))
    res = calculateocs(data)
    print(res)
    

if __name__ == "__main__":
        import sys

        if len(sys.argv) > 1:
            data = bytearray(int(x, 16) for x in sys.argv[1:])
            print(udp_dooptions(data))
        else:
            print("Stand alone enter option data as args i.e, python3 udp_options.py  02 fe 06 0a 11 22 33 44 55 66 77 88 0a 06 00 00 33 44 01 00")
