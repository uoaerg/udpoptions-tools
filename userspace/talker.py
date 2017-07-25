import udpoptions
import udp_usrreq

if __name__ == "__main__":
    opts = { 'UDPOPT_TIME': (0x11223344, 0x55667788), 'UDPOPT_MSS': 0x1122}
    udp_usrreq.udp_output("Hello Options Space on a packet\n", 
        {"src":"139.133.204.4", "dst":"139.133.204.54", "sport":2500, "dport":2600}, 
        options=opts)
