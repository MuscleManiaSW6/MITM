import scapy.all as scapy
from scapy.utils import hexdump


class Sniffer:
    def __init__(self, interface, store=False, print_sniff_data=True, save_raw_data=False,raw_data_file_name = "raw_data.txt", sniff_data_file_name = "data.txt"):
        self.interface = interface
        self.store = store
        self.print_sniff_data = print_sniff_data
        self.save_raw_data = save_raw_data
        if save_raw_data is True:
            self.raw_data = open(raw_data_file_name, "a")
        if store is True:
            self.file = open(sniff_data_file_name, "a")

    def sniff(self):
        sniff_packet = scapy.sniff(iface=self.interface, prn=self.analyze_packet, store=False)

    def analyze_packet(self, packet):
        source_mac = destination_mac = source_ip = destination_ip = sport = dport = load = ""
        if not(packet.haslayer("ARP")):
            if packet.haslayer("Ethernet"):
                source_mac = packet["Ethernet"].src
                destination_mac = packet["Ethernet"].dst
            if packet.haslayer("IP"):
                source_ip = packet["IP"].src
                destination_ip = packet["IP"].dst
            elif packet.haslayer("IPv6"):
                source_ip = packet["IPv6"].src
                destination_ip = packet["IPv6"].dst
            if packet.haslayer("TCP"):
                sport = packet["TCP"].sport
                dport = packet["TCP"].dport
            if packet.haslayer("Raw"):
                load = packet["Raw"].load
            sniff_data = {"source_mac": source_mac, "destination_mac": destination_mac, "source_ip": source_ip,
                          "destination_ip": destination_ip, "sport": sport, "dport": dport, "load": load}
            if self.print_sniff_data is True:
                self.print_data(sniff_data)
            if self.store is True:
                self.save_data(sniff_data)
            if self.save_raw_data is True:
                raw_data = str(packet.show(dump=True, lvl='', label_lvl=''))
                self.raw_data.write(raw_data)

    def print_data(self, data):
        print("Source MAC: " + data["source_mac"])
        print("Destination MAC: " + data["destination_mac"])
        print("Source IP: " + data["source_ip"])
        print("Destination IP: " + data["destination_ip"])
        print("SPORT: " + str(data["sport"]))
        print("DPORT: " + str(data["dport"]))
        print("PACKET DATA\n\n")
        print(hexdump(data["load"]))
        print("*" * 100)

    def save_data(self, data):
        load_data = str(hexdump(data["load"], dump=True))
        save_data = "\nSource MAC: " + str(data["source_mac"]) + "\nDestination MAC: " + str(
            data["destination_mac"]) + "\nSource IP: " + str(data["source_ip"]) + "\nDestination IP: " + str(
            data["destination_ip"]) + "\nSPORT: " + str(data["sport"]) + "\nDPORT: " + str(
            data["dport"]) + "\nPACKET DATA\n\n" + load_data + "\n\n" + str("*" * 100)
        self.file.write(save_data)
