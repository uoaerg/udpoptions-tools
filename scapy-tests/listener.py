import udp_options
import udp_usrreq

BINDADDR = '10.0.4.1'
SPORT = 7
INTERFACE = None

def callback(pcb, data=None, options=None, error=None):
    if error:
        print("error from:")
    else:
        print("packet from:")
    print("\t", pcb)

    if data:
        print("UDP Data:\t", data)
    if options:
        print("UDP Options:\t", options)
    if error:
        print("ICMP:\t", error)

    # be an echo server
    if data and not error:
        udp_usrreq.udp_output(data, 
            {"src": pcb['address'], "dst": pcb['peerinfo'][0], "sport": SPORT, "dport": 2500})

if __name__ == "__main__":
    print("startings")
    pcb_hdr = udp_usrreq.bindaddr(
        {
            "address": BINDADDR,
            "port": SPORT,
            "cb": callback
        })
    if not pcb_hdr:
        print("error binding")
        exit(1)
    else:
        print("bound and listening on ", pcb_hdr)
    udp_usrreq.run_loop(INTERFACE)
