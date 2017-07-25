from scapy.all import IP
from scapy.all import UDP 
from scapy.all import *

import udpoptions

def udp_output(data, pcb, options=None):

    ip = IP(src=pcb['src'], dst=pcb['dst'])
    udp = UDP(sport=pcb['sport'], dport=pcb['dport'])

    optpkt = ip/udp/data

    chksum = optpkt[UDP].chksum #capture correct checksum
    udplen = optpkt[UDP].len    #capture correct length

    optpkt.getlayer(1).len = len(optpkt.getlayer(1)) #force UDP len

    if options:
        optbuf = udpoptions.udp_addoptions(options)
        print(optbuf)
        optpkt = (optpkt/str(optbuf))

    optpkt.getlayer(1).chksum = chksum
    optpkt.getlayer(1).len = udplen

    send(optpkt)

if __name__ == "__main__":
    opts = { 'UDPOPT_TIME': (0x11223344, 0x55667788), 'UDPOPT_MSS': 0x1122}
    udp_output("hell world\n", options=opts, src="139.133.204.4", dst="139.133.204.54")
