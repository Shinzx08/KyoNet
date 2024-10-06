import argparse
import requests
from scapy.all import *
from colorama import Fore, Style
from tkinter import Tk, Canvas, Entry, Text, Button, PhotoImage
from pathlib import Path
from scapy.layers.dns import DNS, DNSQR, DNSRR
from scapy.layers.inet import UDP, IP, TCP
from datetime import datetime
from source.dnsfiglet import dnsfiglet
from source.dnsfirewall import DNSSpoofingDetector
from source.version import __version__

OUTPUT_PATH = Path(__file__).parent
ASSETS_PATH = OUTPUT_PATH / Path(r"C:\Users\USER\Documents\Kyonet\master\KyoNet\assets\frame0")
def relative_to_assets(path: str) -> Path:
    return ASSETS_PATH / Path(path)


class DNSListener:
    
    def __init__(self, interface=None, verbose=False, target_ip=None, analyze_dns_type=False, doh=False, target_domains=None,
                 filter_port=None, filter_src_ip=None, filter_dst_ip=None, dns_type=None, pcap_file=None, firewall=False,
                 threshold=50, window_size=60):
        self.interface = interface
        self.verbose = verbose
        self.target_ip = target_ip
        self.analyze_dns_type = analyze_dns_type
        self.doh = doh
        self.target_domains = target_domains
        self.filter_port = filter_port
        self.filter_src_ip = filter_src_ip
        self.filter_dst_ip = filter_dst_ip
        self.dns_type = dns_type
        self.pcap_file = pcap_file
        self.firewall = firewall  
        self.threshold = threshold
        self.window_size = window_size
        self.total_dns_requests = 0
        self.unique_domains = set()
        self.most_requested_domains = {}
        self.dns_types = {}
        self.source_ips = {}
        self.destination_ips = {}
        self.dns_detector = None
        self.create_dns_detector()

    def create_dns_detector(self):
        if self.firewall:
            self.dns_detector = DNSSpoofingDetector(threshold=self.threshold, window_size=self.window_size)

    def process_packet(self, pkt):
        self.total_dns_requests += 1

        if DNS in pkt:
            if self.firewall and self.dns_detector:
                self.dns_detector.process_packet(pkt)

            if self.filter_port and UDP in pkt and pkt[UDP].sport != self.filter_port and pkt[
                UDP].dport != self.filter_port:
                return

            if self.filter_src_ip and IP in pkt and pkt[IP].src != self.filter_src_ip:
                return

            if self.filter_dst_ip and IP in pkt and pkt[IP].dst != self.filter_dst_ip:
                return

            if self.dns_type and pkt[IP].proto != self.dns_type:
                return

            source_ip = pkt[IP].src
            self.source_ips[source_ip] = self.source_ips.get(source_ip, 0) + 1

            destination_ip = pkt[IP].dst
            self.destination_ips[destination_ip] = self.destination_ips.get(destination_ip, 0) + 1

            if pkt.haslayer(TCP) and pkt[TCP].dport == 53:  
                if pkt.haslayer(DNSQR):
                    qname = pkt[DNSQR].qname.decode()
                    self.unique_domains.add(qname)
                    self.most_requested_domains[qname] = self.most_requested_domains.get(qname, 0) + 1
                    if self.target_domains and qname not in self.target_domains:
                        return
                    self.print_info(pkt, "DNS Request", qname)
                    if self.doh and qname in self.target_domains:
                        self.resolve_and_print_doh_result(qname)

            elif pkt.haslayer(UDP) and pkt[UDP].dport == 53:  
                if pkt[DNS].qr == 0: 
                    qname = pkt[DNSQR].qname.decode()
                    self.unique_domains.add(qname)
                    self.most_requested_domains[qname] = self.most_requested_domains.get(qname, 0) + 1
                    if self.target_domains and qname not in self.target_domains:
                        return
                    self.print_info(pkt, "DNS Request", qname)
                    if self.doh and qname in self.target_domains:
                        self.resolve_and_print_doh_result(qname)

                elif pkt[DNS].qr == 1:  
                    if DNSRR in pkt:
                        qname = pkt[DNSQR].qname.decode()
                        resp_ip = pkt[DNSRR].rdata
                        if self.target_ip and resp_ip != self.target_ip:
                            return
                        self.print_info(pkt, "DNS Response", qname, resp_ip)

                        dns_type = pkt[IP].proto
                        self.dns_types[dns_type] = self.dns_types.get(dns_type, 0) + 1

        if self.pcap_file:
            wrpcap(self.pcap_file, pkt, append=True)  
    def resolve_and_print_doh_result(self, qname):
        resolved_ips = self.resolve_dns_doh(qname)
        if resolved_ips:
            print(f"Resolved IPs for {qname} using DoH: {resolved_ips}")

    def print_info(self, pkt, packet_type, qname, resp_ip=None, doh_result=None):
        dns_type_names = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 41: "OPT", 28: "AAAA", 17: "RP"}

        dns_type = pkt[IP].proto
        dns_type_name = dns_type_names.get(dns_type, str(dns_type))

        if pkt.haslayer(TCP):
            protocol = "TCP"
        elif pkt.haslayer(UDP):
            protocol = "UDP"
        else:
            protocol = "Unknown"

        timestamp = datetime.fromtimestamp(pkt.time).strftime('%Y-%m-%d %H:%M:%S.%f')

        print(f"{Fore.CYAN}Timestamp      :{Style.RESET_ALL}", timestamp)
        print(f"{Fore.GREEN}Source IP      :{Style.RESET_ALL}", pkt[IP].src)
        print(f"{Fore.GREEN}Destination IP :{Style.RESET_ALL}", pkt[IP].dst)
        print(f"{Fore.GREEN}Source MAC     :{Style.RESET_ALL}", pkt.src)
        print(f"{Fore.GREEN}Destination MAC:{Style.RESET_ALL}", pkt.dst)
        print(f"{Fore.GREEN}Packet Size    :{Style.RESET_ALL}", len(pkt))
        print(f"{Fore.GREEN}TTL            :{Style.RESET_ALL}", pkt.ttl)
        print(f"{Fore.GREEN}Type           :{Style.RESET_ALL}", dns_type_name)
        print(f"{Fore.GREEN}IP Checksum    :{Style.RESET_ALL}", pkt[IP].chksum)
        print(f"{Fore.GREEN}Protocol       :{Style.RESET_ALL}", protocol)
        if protocol == "UDP" and UDP in pkt:
            print(f"{Fore.GREEN}UDP Checksum   :{Style.RESET_ALL}", pkt[UDP].chksum)
        print(f"{Fore.YELLOW}{packet_type}   :{Style.RESET_ALL}", qname)
        if resp_ip:
            print(f"{Fore.YELLOW}Response IP    :{Style.RESET_ALL}", resp_ip)
        if doh_result:
            print(f"{Fore.YELLOW}DoH Result     :{Style.RESET_ALL}", doh_result)
        print("-" * 50)

    def resolve_dns_doh(self, dns_request):
        url = f"https://cloudflare-dns.com/dns-query?name={dns_request}&type=A"
        headers = {"Accept": "application/dns-json"}
        try:
            response = requests.get(url, headers=headers)
            response.raise_for_status()  
            result = response.json()
            if "Answer" in result:
                answers = result["Answer"]
                return [answer["data"] for answer in answers]
            else:
                print(f"{Fore.RED}[!] Error: No 'Answer' field in DoH response.{Style.RESET_ALL}")
        except requests.RequestException as e:
            print(f"{Fore.RED}[!] Error resolving DNS over HTTPS: {e}{Style.RESET_ALL}")
        except Exception as e:
            print(f"{Fore.RED}[!] An unexpected error occurred: {e}{Style.RESET_ALL}")
        return None

    def listen(self):
        if self.interface:
            sniff(filter="udp or tcp port 53", prn=self.process_packet, store=0, iface=self.interface)
        else:
            sniff(filter="udp or tcp port 53", prn=self.process_packet, store=0)

    def print_summary(self):
        dns_type_names = {1: "A", 2: "NS", 5: "CNAME", 12: "PTR", 41: "OPT", 28: "AAAA", 17: "RP"}
        print("\n")
        print(f"{Fore.BLUE}Total DNS Requests    :{Style.RESET_ALL}", self.total_dns_requests)
        print(f"{Fore.BLUE}Unique Domains        :{Style.RESET_ALL}", len(self.unique_domains))
        print(f"{Fore.BLUE}Most Requested Domains:{Style.RESET_ALL}")
        for domain, count in sorted(self.most_requested_domains.items(), key=lambda x: x[1], reverse=True):
            if count > 5: 
                print(f"\t{Fore.YELLOW}{domain}:{Style.RESET_ALL} {count} requests")
            else:
                break  
        print(f"{Fore.BLUE}DNS Types:{Style.RESET_ALL}")
        for dns_type, count in sorted(self.dns_types.items()):
            dns_type_name = dns_type_names.get(dns_type, str(dns_type))
            print(f"\t{Fore.YELLOW}{dns_type_name}:{Style.RESET_ALL} {count}")

        print(f"{Fore.BLUE}Source IPs:{Style.RESET_ALL}")
        for source_ip, count in sorted(self.source_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"\t{Fore.YELLOW}{source_ip}:{Style.RESET_ALL} {count}")

        print(f"{Fore.BLUE}Destination IPs:{Style.RESET_ALL}")
        for destination_ip, count in sorted(self.destination_ips.items(), key=lambda x: x[1], reverse=True):
            print(f"\t{Fore.YELLOW}{destination_ip}:{Style.RESET_ALL} {count}")

class DNSsniffer:
    def __init__(self, root):
        self.root = root
        self.root.geometry("745x505")
        self.root.configure(bg="#FFFFFF")

        self.canvas = Canvas(root, bg="#FFFFFF", height=505, width=745, bd=0, highlightthickness=0, relief="ridge")
        self.canvas.place(x=0, y=0)
        
        self.canvas.place(x=0, y=0)
        self.canvas.create_rectangle(0.0, 0.0, 745.0, 87.0, fill="#0077BC", outline="")
        
        image_image_1 = PhotoImage(file=relative_to_assets("image_1.png"))
        self.canvas.create_image(109.0, 132.0, image=image_image_1)

        image_image_2 = PhotoImage(file=relative_to_assets("image_2.png"))
        self.canvas.create_image(109.0, 206.0, image=image_image_2)

        image_image_3 = PhotoImage(file=relative_to_assets("image_3.png"))
        self.canvas.create_image(109.0, 354.0, image=image_image_3)

        image_image_4 = PhotoImage(file=relative_to_assets("image_4.png"))
        self.canvas.create_image(109.0, 280.0, image=image_image_4)
        
        self.canvas.create_text(68.0, 120.0, anchor="nw", text="Interface", fill="#FFFFFF", font=("Dangrek Regular", 20 * -1))
        self.canvas.create_text(18.0, 18.0, anchor="nw", text="KYONET", fill="#FFFFFF", font=("Dangrek Regular", 35 * -1))
        self.canvas.create_text(70.0, 192.0, anchor="nw", text="Target IP", fill="#FFFFFF", font=("Dangrek Regular", 20 * -1))
        self.canvas.create_text(57.0, 265.0, anchor="nw", text="Filter Src IP", fill="#FFFFFF", font=("Dangrek Regular", 20 * -1))
        self.canvas.create_text(58.0, 341.0, anchor="nw", text="Filter Dis IP", fill="#FFFFFF", font=("Dangrek Regular", 20 * -1))

        entry_image_1 = PhotoImage(
            file=relative_to_assets("entry_1.png"))
        entry_bg_1 = self.canvas.create_image(
            568.0,
            124.0,
            image=entry_image_1
        )
        self.entry_1 = Entry(
            bd=0,
            bg="#D9D9D9",
            fg="#000716",
            highlightthickness=0
        )
        self.entry_1.place(
            x=456.0,
            y=104.0,
            width=224.0,
            height=38.0
        )

        entry_image_2 = PhotoImage(
            file=relative_to_assets("entry_2.png"))
        entry_bg_2 = self.canvas.create_image(
            568.0,
            350.0,
            image=entry_image_2
        )
        self.entry_2 = Entry(
            bd=0,
            bg="#D9D9D9",
            fg="#000716",
            highlightthickness=0
        )
        self.entry_2.place(
            x=456.0,
            y=330.0,
            width=224.0,
            height=38.0
        )

        entry_image_3 = PhotoImage(
            file=relative_to_assets("entry_3.png"))
        entry_bg_3 = self.canvas.create_image(
            568.0,
            285.0,
            image=entry_image_3
        )
        self.entry_3 = Entry(
            bd=0,
            bg="#D9D9D9",
            fg="#000716",
            highlightthickness=0
        )
        self.entry_3.place(
            x=456.0,
            y=265.0,
            width=224.0,
            height=38.0
        )

        entry_image_4 = PhotoImage(
            file=relative_to_assets("entry_4.png"))
        entry_bg_4 = self.canvas.create_image(
            568.0,
            212.0,
            image=entry_image_4
        )
        self.entry_4 = Entry(
            bd=0,
            bg="#D9D9D9",
            fg="#000716",
            highlightthickness=0
        )
        self.entry_4.place(
            x=456.0,
            y=192.0,
            width=224.0,
            height=38.0
        )
        button_image_1 = PhotoImage(file=relative_to_assets("button_1.png"))
        button_1 = Button(
            image=button_image_1,
            borderwidth=0,
            highlightthickness=0,
            command=lambda: self.start_sniffing,
            relief="flat"
        )
        button_1.place(x=202.0, y=404.0, width=322.0, height=82.0)

    def start_sniffing(self):
        # Get the user input from the entries
        interface = self.entry_1.get()
        target_ip = self.entry_2.get()
        filter_src_ip = self.entry_3.get()
        filter_dst_ip = self.entry_4.get()

        # Create DNSListener instance with the user inputs
        dns_listener = DNSListener(
            interface=interface,
            target_ip=target_ip,
            filter_src_ip=filter_src_ip,
            filter_dst_ip=filter_dst_ip
            # Add other arguments as needed, using defaults or hardcoded values
        )
        dns_listener.listen()
        dns_listener.print_summary()


def main():
    parser = argparse.ArgumentParser(description="DNSWatch packet sniffer")
    parser.add_argument("-i", "--interface", help="Interface to listen on")
    parser.add_argument("-v", "--verbose", action="store_true", help="Enable verbose output")
    parser.add_argument("-t", "--target-ip", help="Target IP to analyze DNS responses for")
    parser.add_argument("-d", "--analyze-dns-type", action="store_true", help="Analyze DNS type")
    parser.add_argument("--doh", action="store_true", help="Resolve DNS using DNS over HTTPS (DoH)")
    parser.add_argument("-D", "--target-domains", nargs="+", default=[], help="List of target domains to monitor")
    parser.add_argument("-p", "--filter-port", type=int, help="Filter by source or destination port")
    parser.add_argument("-s", "--filter-src-ip", help="Filter by source IP address")
    parser.add_argument("-r", "--filter-dst-ip", help="Filter by destination IP address")
    parser.add_argument("--dns-type", type=int, help="Filter by DNS type")
    parser.add_argument("--pcap-file", help="Save captured packets to a pcap file")
    parser.add_argument("--firewall", action="store_true", help="Enable DNS firewall mode")
    parser.add_argument("--threshold", type=int, default=50, help="Threshold for DNS query count (default: 50)")
    parser.add_argument("--window-size", type=int, default=60, help="Window size in seconds (default: 60)")
    parser.add_argument("--version", action="version", version=f"%(prog)s {__version__}")
    return parser.parse_args()


if __name__ == "__main__":
    root = Tk()
    app = DNSsniffer(root)
    root.mainloop()