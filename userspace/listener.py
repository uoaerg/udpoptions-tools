import udpoptions
import udp_usrreq

def callback(pcb, data=None, options=None, error=None):
    print(pcb)

if __name__ == "__main__":
    print("startings")
    udp_usrreq.bindaddr('139.133.204.4', 2600, callback)        
    udp_usrreq.run_loop()
