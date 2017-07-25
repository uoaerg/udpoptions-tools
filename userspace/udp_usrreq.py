from scapy.all import IP
from scapy.all import UDP 
from scapy.all import *

import udpoptions

listening = {}

def udp_output(data, pcb, options=None):

    ip = IP(src=pcb['src'], dst=pcb['dst'])
    udp = UDP(sport=pcb['sport'], dport=pcb['dport'])

    optpkt = ip/udp/data

    chksum = optpkt[UDP].chksum #capture correct checksum
    udplen = optpkt[UDP].len    #capture correct length
    udplen = len(data) + 8

    optpkt.getlayer(1).len = len(optpkt.getlayer(1)) #force UDP len

    if options:
        optbuf = udpoptions.udp_addoptions(options)
        optpkt = (optpkt/str(optbuf))

    optpkt.getlayer(1).chksum = chksum
    optpkt.getlayer(1).len = udplen

    print("output: data {} udplen {} optlen {}".format(len(data), udplen, len(optbuf)))
    send(optpkt)

def udp_input(pkt):
    ip = pkt[IP]
    udp = pkt[UDP]
    options = None

    if ip.len != udp.len+20:
        print(pkt.show())
        pay = pkt[Raw].load
        opt = pkt[Padding].load
        options = udpoptions.udp_dooptions(bytearray(opt)) 

        print("udp len {}, options len {}".format(len(pay), len(opt)))
        print(options)

    pcb_hdr = (ip.dst, udp.dport)

    if pcb_hdr in listening:
        proc = listening[pcb_hdr]
        proc['callback'](proc, data, options)

def icmp_input(pkt):
    icmp = pkt[ICMP]
    if icmp.type == 3:
        ip = pkt['IP in ICMP']
        udp = pkt['UDP in ICMP']

        pcb_hdr = (ip.src, udp.sport)
        if pcb_hdr in listening:
            proc = listening[pcb_hdr]
            proc['callback'](proc, data, options, 
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

def bindaddr(addr, port, cb):
    pcb_hdr = (addr, port)
    if not pcb_hdr in listening:
        listening[pcb_hdr] = cb
        return pcb_hdr
    else:
        return None

if __name__ == "__main__":
    run_loop()
    print("All done!")
