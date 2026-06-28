
import time
from scapy.all import ARP, Ether, sendp

INTERFACE = None  

# An unknown MAC (50:d4:f7 is a real TP-Link OUI, so vendor lookup will resolve it)
FAKE_MAC  = "50:d4:f7:00:00:01"
FAKE_IP   = "192.168.1.200"
BROADCAST = "ff:ff:ff:ff:ff:ff"


def make_arp_request(src_mac, src_ip, target_ip="192.168.1.1"):
    return Ether(src=src_mac, dst=BROADCAST) / ARP(
        op=1, hwsrc=src_mac, psrc=src_ip, pdst=target_ip
    )


def make_arp_reply(src_mac, src_ip, target_ip="192.168.1.1"):
    return Ether(src=src_mac, dst=BROADCAST) / ARP(
        op=2, hwsrc=src_mac, psrc=src_ip, pdst=target_ip
    )


def test_unknown_device():
    print(f"[TEST] Unknown device — {FAKE_IP} ({FAKE_MAC})")
    sendp(make_arp_request(FAKE_MAC, FAKE_IP), iface=INTERFACE, verbose=False)


def test_cooldown(times=3, delay=2.0):
    print(f"[TEST] {times} ARPs from same MAC, {delay}s apart (expect 1 alert)")
    for i in range(times):
        print(f"  → {i + 1}/{times}")
        sendp(make_arp_request(FAKE_MAC, FAKE_IP), iface=INTERFACE, verbose=False)
        if i < times - 1:
            time.sleep(delay)


def test_whitelisted_device(mac, ip="192.168.1.201"):
    print(f"[TEST] Whitelisted device — {ip} ({mac}) (expect NO alert)")
    sendp(make_arp_request(mac, ip), iface=INTERFACE, verbose=False)


def test_spoof(ip="192.168.1.35"):
    """Two replies for the same IP from different MACs — should flag a spoof."""
    print(f"[TEST] ARP spoof on {ip} (expect a SPOOF incident)")
    sendp(make_arp_reply("aa:aa:aa:aa:aa:aa", ip), iface=INTERFACE, verbose=False)
    time.sleep(1)
    sendp(make_arp_reply("de:ad:be:ef:00:01", ip), iface=INTERFACE, verbose=False)


if __name__ == "__main__":
    test_unknown_device()
    time.sleep(1)
    test_cooldown()
    time.sleep(1)
    # Replace with a real MAC from your whitelist.json to confirm it's ignored:
    test_whitelisted_device(mac="d8:31:34:ee:d4:8a")
    time.sleep(1)
    test_spoof()
    print("[DONE] All test packets sent.")
