import scapy.all as scapy
import argparse

def scan():
    parser = argparse.ArgumentParser()
    parser.add_argument("-t", "--target", dest="target", help="The target IP range")
    (options) = parser.parse_args()
    if not options.target:
        parser.error("[-] Please specify a target, use --help for more info")
    arp_request = scapy.ARP(pdst=options.target)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]

    clients_list = []
    for val in answered_list:
        client_dict = {"ip": val[1].psrc, "mac": val[1].hwsrc}
        clients_list.append(client_dict)
    return clients_list

def print_result(result_list):
    print("IP\t\t\tMAC Address\n------------------------------------------")
    for client in result_list:
        print(client["ip"] + "\t\t" + client["mac"])


scan_result = scan()
print_result(scan_result)
