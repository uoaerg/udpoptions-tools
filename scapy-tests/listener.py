import udp_options
import udp_usrreq

def callback(pcb, data=None, options=None, error=None):
    print(pcb)
    if data:
        print("UDP Data:\t", data)
    if options:
        print("UDP Options:\t", options)
    if error:
        print("ICMP:\t", error)

if __name__ == "__main__":
    print("startings")
    pcb_hdr = udp_usrreq.bindaddr(
        {
            "address": '10.0.4.4', 
            "port": 2600, 
            "cb": callback
        })
    if not pcb_hdr:
        print("error binding")
        exit(1)
    else:
        print("bound and listening on ", pcb_hdr)
    udp_usrreq.run_loop()
