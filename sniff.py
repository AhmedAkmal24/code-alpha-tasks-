import scapy.all as scapy
#it is the library used to monitor the network 

def start_sniffer(interface):
    scapy.sniff(iface=interface, filter="icmp", prn=process_packet, store=False)
#it is a function used to start sniff

start_sniffer('\\Device\\NPF_{53ED0B3E-E091-4332-B341-7EC1B0426335}')

def sniffing(interface):
    scapy.sniff(iface=interface,store=False,prn=process_packet)
#it is a function used to define the sniffing 

def process_packet(packet):
    print(packet)
#it is a function used to captured data 

sniffing('\\Device\\NPF_{53ED0B3E-E091-4332-B341-7EC1B0426335}')


