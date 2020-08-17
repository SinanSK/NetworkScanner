import scapy.all as scapy
import optparse


def get_inp():

    parse = optparse.OptionParser()
    
    parse.add_option("-r", "--range", dest="rangeip",
                     help="Ip Range | Example : 192.168.0.1/24")
    
    (user_input, args) = parse.parse_args()
    
    if not user_input.rangeip:
    
        print("Please enter IP address.")
   
    return user_input.rangeip


def scan(ip):
    
    arp = scapy.ARP(pdst=ip)
    
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    
    combine_packet = broadcast/arp
    
    answer = scapy.srp(combine_packet, timeout=3, verbose=0)[0]
   
    print("Result : ")
   
    print("\nIP", " "*18+"MAC")
   
    print("="*38)

    for i, j in answer:
    
        print(j.psrc.ljust(20), j.hwsrc)


addr = get_inp()
scan(addr)
