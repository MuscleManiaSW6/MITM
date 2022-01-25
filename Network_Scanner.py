import scapy.all as scapy
from termcolor import colored


class NetworkScanner:
    def __init__(self, ip=None, interface=None):
        self.ip = ip
        self.interface = interface
        self.arp_request = scapy.ARP()
        self.broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
        self.response = None
        self.connected_device_data = {}

    def scan(self, ip=None, interface=None):
        if ip is None:
            ip = self.ip
        if interface is None:
            interface = self.interface
        self.arp_request.pdst = ip
        arp_broadcast_packet = self.broadcast / self.arp_request
        self.response = scapy.srp(arp_broadcast_packet, iface=interface, timeout=20, verbose=False)[0]
        return self.response

    def get_scan_result(self):
        for data in self.response:
            self.connected_device_data[data[1].psrc] = data[1].hwsrc
        print(len(self.connected_device_data))
        if len(self.connected_device_data) == 0:
            print(colored("No Device Found", "red"))
            return -1
        print(colored("[+] Device discovered :" + str(len(self.connected_device_data)), "green"))
        count = 1
        print(colored("----------------------------------------------------------------", "green"))
        print("S.No         IP                      MAC ADDRESS")
        print(colored("----------------------------------------------------------------", "green"))
        for data in self.connected_device_data.items():
            print(str(count) + ".           " + data[0] + "         " + data[1])
            count += 1
        return self.connected_device_data

    def get_mac(self, ip=None, interface=None):
        if ip is None:
            ip = self.ip
        if interface is None:
            interface = self.interface
        response = self.scan(ip, interface)
        if len(response) == 0:
            return -1
        return response[0][1].hwsrc
