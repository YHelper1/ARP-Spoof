import socket

from scapy.all import *


def get_own_ip_address():
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    s.connect(("8.8.8.8", 80))
    ip_addr = s.getsockname()[0]
    s.close()
    return ip_addr

def get_router_ip_addr(own_ip):
    router_ip = own_ip[:own_ip.rfind(".")] + ".1"
    return router_ip

router_addr = get_router_ip_addr(get_own_ip_address())



def get_os(ip, port):
    ip_p = IP(dst=ip)
    tcp_p= TCP(dport=port, flags="S")
    packet = ip_p / tcp_p
    response = sr1(packet, timeout=0.01, verbose=False)
    if not response:
        return None
    if response.haslayer(TCP):
        tcp_layer = response.getlayer(TCP)
        if "R" in tcp_layer.flags:
            return None
        ip_layer = response.getlayer(IP)
        window = tcp_layer.window
        ttl = ip_layer.ttl
        if ttl <= 64 and window in [32120, 5840]:
            print("Likely OS: Linux/FreeBSD")
        elif ttl <= 128:
            print("Likely OS: Windows")
        elif ttl >= 200:
            print("Likely OS: Cisco/Network Device")
        else:
            print("OS detection uncertain.")

        return window



my_macs = get_if_hwaddr([i for i in get_if_list() if "wlan" in i][0]) 
print(my_macs)
print(get_router_ip_addr(get_own_ip_address()))


target_ip = "192.168.3.0/24"

def get_devices(ips):
    arp_request = Ether(dst="ff:ff:ff:ff:ff:ff")/ARP(pdst=ips)
    answered, unanswered = srp(arp_request, timeout=1, verbose=False)
    devices = []
    for sent, received in answered:
        device = {}
        device["ip"] = received.psrc
        print(received.psrc)
        info = None
        for port in [80, 49152]:
            info = get_os(received.psrc, port)
            print(port)
            if info:
                break
        print(info)
        device["mac"] = received.hwsrc
        devices.append(device)
    return devices


devices = get_devices(target_ip)

print(devices)

#class SpoofApp(app):
#    def compose(self) -> ComposeResult:
#        yield(Input(placeholder="Limit ip"))
