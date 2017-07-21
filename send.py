from scapy.all import IP
from scapy.all import UDP 
from scapy.all import *

if __name__ == "__main__":

    ip = IP(src="139.133.204.4", dst="139.133.204.55")
    udp = UDP(sport=2600, dport=2500)

    optpkt = ip/udp/"Hello Options\n"
    #optpkt = optpkt.__class__(str(optpkt))

    chksum = optpkt[UDP].chksum #capture correct checksum
    udplen = optpkt[UDP].len    #capture correct length

    #print("UDP Checksum: {}, UDP Length: {}".format(hex(chksum), udplen))

    optpkt.getlayer(1).len = len(optpkt.getlayer(1)) #force UDP len
    optpkt = (optpkt/"\x02\x01\x01\x01\x01\x01\x01\x00")

    #optpkt.getlayer(1).chksum = chksum
    #optpkt.getlayer(1).len = udplen

    optpkt.getlayer(1).chksum = 0x724a

    send(optpkt)
