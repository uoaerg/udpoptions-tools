from scapy.all import IP
from scapy.all import UDP 
from scapy.all import *

import udp_options

listening = {}

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

def udpchksum(src, dst, sprt, dprt, data):
    sourceaddr = bytearray([ int(x) for x in src.split(".")])
    destaddr = bytearray([ int(x) for x in dst.split(".")])
    proto = 17
    udplen = 8 + len(data)
    sport = sprt
    dport = dprt
    cksum = 0

    pkt = struct.pack("!4s4sBBHHHHH{}s".format(len(data)),
	sourceaddr, destaddr,
	0, proto, udplen,
	sport, dport,
	udplen, cksum,
	data)

    return internetchecksum(pkt)

def udp_output(data, pcb, options=None):
    if not type(data) is bytes:
        raise TypeError("udp_output data must be bytes object")
    ip = IP(src=pcb['src'], dst=pcb['dst'])
    udp = UDP(sport=pcb['sport'], dport=pcb['dport'])
    optpkt = ip/udp/data

    optpkt.getlayer(1).len = len(optpkt.getlayer(1)) #force UDP len

    chksum = optpkt[UDP].chksum #capture correct checksum
    udplen = optpkt[UDP].len    #capture correct length
    #udplen = len(data) + 8

    if options:
        optbuf = udp_options.udp_addoptions(options)
        optpkt = (optpkt/bytes(optbuf))

    optpkt.getlayer(1).chksum = udpchksum(pcb['src'],pcb['dst'], pcb['sport'],
	pcb['dport'], data)
    optpkt.getlayer(1).len = udplen
    send(optpkt, verbose=False)

def udp_input(pkt):
    doechores = False
    ip = pkt[IP]
    udp = pkt[UDP]
    options = None

    if ip.len != udp.len+20:
        try:
            pay = pkt[Raw].load
        except IndexError:
            pay = b""
        opt = pkt[Padding].load
        options = udp_options.udp_dooptions(bytearray(opt)) 

        if 'UDPOPT_ECHORES' in options:
            reqtoken = options['UDPOPT_ECHORES']

            resopt = {
                'UDPOPT_TIME': (0x11223344, 0x55667788),
                'UDPOPT_ECHORES':reqtoken
            }
            doechores = True

    pcb_hdr = (ip.dst, udp.dport)
    if pcb_hdr in listening:
        proc = listening[pcb_hdr]
        proc['peerinfo'] = (ip.src, udp.sport)
        # only do an echo request if there is a process listening               
        # on this address. This has the side effect of not responding           
        # to packets that we generate                                           
        if doechores:                                                           
            udp_output(b"I love Options Space on a packet",
                {'src':ip.dst,'dst':ip.src, 'sport':udp.dport, 'dport':udp.sport}, 
                options=resopt)
        proc['cb'](proc, pay, options, None)

def icmp_input(pkt):
    icmp = pkt[ICMP]
    if icmp.type == 3:
        ip = pkt['IP in ICMP']
        udp = pkt['UDP in ICMP']

        pcb_hdr = (ip.src, udp.sport)
        if pcb_hdr in listening:
            proc = listening[pcb_hdr]
            proc['cb'](proc, b"", None,
                {'type':icmp.type, 'code':icmp.code})
        print("ICMP Packet type {} code {}".format(icmp.type, icmp.code))
    else:
        print("ICMP Packet type {} code {}".format(icmp.type, icmp.code))

def pkt_input(pkt=None):
    if ICMP in pkt:
        icmp_input(pkt)
    if UDP in pkt:
        udp_input(pkt)

def run_loop():
    sniff(prn= lambda x: pkt_input(x), filter="icmp or (udp and port 2500)")

def bindaddr(pcb):
    pcb_hdr = (pcb['address'], pcb['port'])
    if not pcb_hdr in listening:
        listening[pcb_hdr] = pcb
        return pcb_hdr
    else:
        return None

if __name__ == "__main__":
    run_loop()
    print("All done!")
