import udp_options
import udp_usrreq
import time
import argparse

EXPECTEDRESULTS = [
    'anything',
    'silence', 
    'nooptions',
    'options',
    'validecho',
    'validtime',
]

def callback(pcb, data=None, options=None, error=None):
    print(pcb)
    print(options)
    return
    if data or options:
        print("got a packet back")
        print(pcb)
        print(data)
        print(options)
    else:
        print("got not a packet back")
        print(pcb)
        print(error)

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

    parser.add_argument('-p', dest='PAYLOAD', action='store', default="hello udp options\n", type=str,
                        help='UDP payload to send with packet')

    parser.add_argument('-s', dest='SENDPACKET', metavar='DSTADDR', type=str, nargs=4,
                        help='send packet [SOURCEADDRESS SOURCEPORT DESTINATIONADDRESS DESTINATIONPORT]')

    parser.add_argument('--verbose', '-v', dest="VERBOSE", action='count', default=0)

    parser.add_argument('-w', dest='WAITTIME', action='store', default=10, type=int,
                        help='time in seconds to wait for responses, wait time of 0 disables listening')

    args = parser.parse_args()

    if args.OPTIONDATA:
        if args.HEXDUMP:
            print('hexdump output is NOT IMPLEMENTED')
            exit(1)
        else:
            data = bytearray(int(x, 16) for x in args.OPTIONDATA)
            options = udp_options.udp_dooptions(data)

    if not args.SENDPACKET:
        exit(0)
    else:
        BINDADDR = args.SENDPACKET[0]
        SPORT = args.SENDPACKET[1]
        DESTADDR = args.SENDPACKET[2]
        DPORT = args.SENDPACKET[3]

    if args.VERBOSE:
        print("sending to:\t", (BINDADDR, SPORT), (DESTADDR, DPORT))
        print("via interface:\t", args.INTERFACE)
        print("UDP Data:\t", args.PAYLOAD)
        print("UDP Options:\t", options)

        if args.WAITTIME:
            print("waiting {} seconds for response".format(args.WAITTIME))
        else:
            print("not listening for any response") 

        print("expecting response of: ", args.EXPECT)

    if args.FIREWALL:
        print("firewall configuration is NOT IMPLEMENTED")
        exit(1)

    exit(1)

    # old talker program from here
    pcb_hdr = udp_usrreq.bindaddr(
        {
            "address": BINDADDR,
            "port": SPORT,
            "cb": callback
        })
    if not pcb_hdr:
        print("failed to bind")
        exit(1)
    opts = { 'UDPOPT_TIME': (0x11223344, 0x55667788), 
             'UDPOPT_MSS': 0x1122,
             'UDPOPT_ECHOREQ':0xabcd,
             'UDPOPT_ECHORES':0xabcd
    }

    sniffer = udp_usrreq.start_run_loop(args.INTERFACE)

    udp_usrreq.udp_output(b"Hello Options Space on a packet\n",
        {"src": BINDADDR, "dst": DESTADDR, "sport": SPORT, "dport": DPORT},
        options=opts)

    # wait for any response
    time.sleep(WAITTIME)
    udp_usrreq.stop_run_loop(sniffer)
