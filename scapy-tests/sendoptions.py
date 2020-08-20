import udp_options
import udp_usrreq
import time
import argparse
import sys

EXPECTEDRESULTS = [
    'anything',
    'silence', 
    'nooptions',
    'options',
    'validecho',
    'validtime',
]

packets = []

def callback(pcb, data=None, options=None, error=None):
    global packets
    global send_count
    # gather up all the packets we recieve
    packets.append((pcb, data, options, error))

    if args.VERBOSE:
        print((pcb, data, options, error))

    # respond to any udp packets
    if args.MODE == "pingpong":
        if not data and not options:
            return

        opts = {}
        if 'UDPOPT_ECHOREQ' in options:
            opts['UDPOPT_ECHORES'] = options['UDPOPT_ECHOREQ']

        if args.VERBOSE:
            print(opts)
        udp_usrreq.udp_output(b"pingpong mode reply to packet",
            {"src": BINDADDR, "dst": DESTADDR, "sport": SPORT, "dport": DPORT},
            options=opts)

    return

if __name__ == "__main__":

    parser = argparse.ArgumentParser(description='Send udp options and expect responses')

    parser.add_argument('OPTIONDATA', metavar='N', type=str, nargs='*',
                        help='option data as hexidecimal bytes seperated with spaces, i.e. in 8 bit striges 02 33 05 04 00 24 00')

    parser.add_argument('--expect', '-e', dest='EXPECT', action='append', nargs='+', 
                        help='response to expect')

    parser.add_argument('-f', dest='FIREWALL', action='store_true',
                        help='configure firewall to icmp for our bound port (NOT IMPLEMENTED)')

    parser.add_argument('-H', dest='HEXDUMP', action='store_true',
                        help='read in data from hexdump output, i.e. in 16 bit strides 0233 0504 0024 00 (NOT IMPLEMENTED)')

    parser.add_argument('-i', dest='INTERFACE', action='store', default=None, type=str,
                        help='interface to listen for responses on, defaults to all, but this does not always work')

    parser.add_argument('--mode', '-m', dest='MODE', action='store', type=str,
                        help='mode to run in, defaults to sending 1 packet and gathering up replies')

    parser.add_argument('-p', dest='PAYLOAD', action='store', default="hello udp options\n", type=str,
                        help='UDP payload to send with packet')

    parser.add_argument('-s', dest='SENDPACKET', metavar='DSTADDR', type=str, nargs=4,
                        help='send packet [SOURCEADDRESS SOURCEPORT DESTINATIONADDRESS DESTINATIONPORT]')

    parser.add_argument('--verbose', '-v', dest="VERBOSE", action='count', default=0)

    parser.add_argument('-w', dest='WAITTIME', action='store', default=1, type=int,
                        help='time in seconds to wait for responses, wait time of 0 disables listening')

    args = parser.parse_args()

    options = {}
    if args.OPTIONDATA:
        if args.HEXDUMP:
            print('hexdump output is NOT IMPLEMENTED')
            sys.exit(1)
        else:
            data = bytearray(int(x, 16) for x in args.OPTIONDATA)
            options = udp_options.udp_dooptions(data)
            if args.VERBOSE:
                print(options)

    if not args.SENDPACKET:
        sys.exit(0)
    else:
        BINDADDR = args.SENDPACKET[0]
        SPORT = int(args.SENDPACKET[1])
        DESTADDR = args.SENDPACKET[2]
        DPORT = int(args.SENDPACKET[3])

    if args.VERBOSE:
        print("sending to:\t", (BINDADDR, SPORT), (DESTADDR, DPORT))
        print("via interface:\t", args.INTERFACE)
        print("UDP Data:\t", args.PAYLOAD)
        print("UDP Options:\t", options)

        if args.WAITTIME:
            print("waiting {} seconds for response".format(args.WAITTIME))
        else:
            print("not listening for any response") 

        if args.EXPECT:
            print("expecting response of: ", args.EXPECT)

    if args.FIREWALL:
        print("firewall configuration is NOT IMPLEMENTED")
        sys.exit(1)

    pcb_hdr = udp_usrreq.bindaddr(
        {
            "address": BINDADDR,
            "port": SPORT,
            "cb": callback
        })
    if not pcb_hdr:
        print("failed to bind")
        sys.exit(1)

#    opts = { 'UDPOPT_TIME': (0x11223344, 0x55667788), 
#             'UDPOPT_MSS': 0x1122,
#             'UDPOPT_ECHOREQ':0xabcd,
#             'UDPOPT_ECHORES':0xabcd
#    }

    sniffer = udp_usrreq.start_run_loop(args.INTERFACE)

    udp_usrreq.udp_output(b"Hello Options Space on a packet\n",
        {"src": BINDADDR, "dst": DESTADDR, "sport": SPORT, "dport": DPORT},
        options=options)

    # wait for any response
    time.sleep(args.WAITTIME)
    udp_usrreq.stop_run_loop(sniffer)

    if args.VERBOSE:
        print("recived {} packets in {} seconds listening".format(len(packets), args.WAITTIME))

    if not args.EXPECT:
        sys.exit(0)

    for expectation in args.EXPECT:
        if expectation[0] == "silence":
            if len(packets) == 0:
                sys.exit(0)
            else: 
                sys.exit(1)

        # if we are not expecting silence then 0 packets received is always an
        # error
        if len(packets) == 0:
            sys.exit(1)

        # only expect icmp packets, udp or udp + options is an error
        if expectation[0] == "icmponly":
            for p in packets:
                if (p[1] or p[2]) and not p[3]:
                    if args.VERBOSE:
                        print(p)
                    sys.exit(1)
            sys.exit(0)

        # expect that we receive UDP, but none of received packets have UDP
        # options. This probably doesn't work if we only get 0 len UDP in
        # response
        if expectation[0] == "nooptions":
            udp = False
            for p in packets:
                if p[1]:
                    udp = True
                if p[2]:
                    if args.VERBOSE:
                        print(p)
                    sys.exit(1)

            if not udp:
                sys.exit(1)
            else:
                sys.exit(0)

        # expect at least one packet with UDP options
        if expectation[0] == "options":
            for p in packets:
                if p[2]:
                    if args.VERBOSE:
                        print(p)
                    sys.exit(0)
            sys.exit(1)

        # expect at least one packet with UDP options
        # expect one probe packet (no payload, udp options and udp options length >= 1000)
        if expectation[0] == "dplpmtudsearch":
            optionspresent = False
            probepresent = False
            for p in packets:
                if p[2]:
                    if args.VERBOSE:
                        print(p)
                    optionspresent = True
                if not p[1] and (p[2] and p[2]['optionspacelength'] >= 1000):
                    if args.VERBOSE:
                        print(p)
                    probepresent = True
            if optionspresent and probepresent:
                sys.exit(0)
            else:
                sys.exit(1)
