# SCAPY

from scapy.all import sniff

def process_packet(packet):
    print(packet.summary())

sniff(iface= "eth0", prn=process_packet, count=50) # tenho q descobrir isso ainda

sniff(filter="tcp port 80", prn=process_packet) #HTTP
#####
def process_packet(packet):
    if packet.haslayer('IP'):
        src_ip = packet['IP'].src
        dst_ip = packet['IP'].dst
        print(f"Oirgem: {src_ip} -> Destino: {dst_ip}")

##### identificando dispositivos conectados #### 

from scapy.all import ARP, Ether, srp

def scan_network(ip_range):
    arp_request = ARP(pdst=ip_range)
    broadcast = Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast / arp_request
    answered = srp(arp_request_broadcast, timeout=2, verbose=False)[0]

    devices = []
    for sent, received in answered:
        devices.append({'ip': received.psrc, 'mac': received.hwsrc})

    return devices

devices = scan_network("192.168.15.0/24")
print("Dispositivos conectados:")
for device in devices:
    print(f"IP: {device['ip']}, MAC: {device['mac']}")
