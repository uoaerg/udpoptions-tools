import udp_options
import udp_usrreq
import time

BINDADDR = '10.0.4.1'
DESTADDR = '10.0.4.4'
SPORT = 2500
DPORT = 7
INTERFACE = None

def callback(pcb, data=None, options=None, error=None):
    if data:
        print("got a packet back")
        print(pcb)
        print(data)
        print(options)
    else:
        print("got not a packet back")
        print(pcb)
        print(data)
        print(error)

if __name__ == "__main__":
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

    sniffer = udp_usrreq.start_run_loop(INTERFACE)

    udp_usrreq.udp_output(b"Hello Options Space on a packet\n",
        {"src": BINDADDR, "dst": DESTADDR, "sport": SPORT, "dport": DPORT},
        options=opts)

    # wait for any response
    time.sleep(10)
    udp_usrreq.stop_run_loop(sniffer)
