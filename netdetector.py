
import json
import os
import smtplib
import time
import urllib.error
import urllib.request
from datetime import datetime
from email.message import EmailMessage

from scapy.all import sniff, conf, ARP, IP, TCP, DHCP, Ether

from database import init_db, log_alert, log_event


# load config

BASE_DIR = os.path.dirname(os.path.abspath(__file__))


def _path(name: str) -> str:
    return os.path.join(BASE_DIR, name)


def load_whitelist(path: str = "whitelist.json") -> set:
    with open(_path(path), encoding="utf-8") as f:
        return set(m.lower() for m in json.load(f)["whitelist"])


def load_config(path: str = "config.json") -> dict:
    with open(_path(path), encoding="utf-8") as f:
        return json.load(f)


WHITELIST = load_whitelist()

config = load_config()
EMAIL_USER  = config["email"]["username"]               # sending account
EMAIL_PASS  = config["email"]["password"]               # Gmail App Password
ALERT_EMAIL = config.get("email", {}).get("alert_email", "")  # recipient (set via web UI)
EMAIL_ALERTS_ENABLED = config.get("email_alerts_enabled", True)
OFF_HOURS_START = config.get("off_hours_start", 1)
OFF_HOURS_END = config.get("off_hours_end", 6)
SCAN_WINDOW_SECONDS = config.get("scan_window_seconds", 10)
SCAN_PORT_THRESHOLD = config.get("scan_port_threshold", 15)
SCAN_COOLDOWN_SECONDS = config.get("scan_cooldown_seconds", 60)

LOG_FILE = _path("traffic.log")


# autologger

def log(message: str):
    timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    line = f"[{timestamp}] {message}"
    print(line)
    with open(LOG_FILE, "a", encoding="utf-8") as f:
        f.write(line + "\n")


# vendor lookup handling, utilizes MACvendors API

vendor_cache = {}

def get_vendor(mac: str) -> str:
    if mac in vendor_cache:
        return vendor_cache[mac]

    try:
        url = f"https://api.macvendors.com/{mac}"
        with urllib.request.urlopen(url, timeout=3) as response:
            result = response.read().decode("utf-8")
    except urllib.error.HTTPError as e:
        if e.code == 404:
            result = "Unknown Vendor"
        elif e.code == 429:
            result = "Rate Limited"
        else:
            result = f"API Error ({e.code})" 
    except Exception:
        result = "Vendor Lookup Failed"

    vendor_cache[mac] = result # caches result to prevent ratelimiting
    return result


# Alert Cooldown (prevents alerts being spammed)

alert_cooldowns = {}
COOLDOWN_SECONDS = config.get("cooldown_seconds", 60)

def is_on_cooldown(mac: str) -> bool:
    now = time.time()

    # Clean up expired entries so the dict doesn't grow forever
    expired = [m for m, t in alert_cooldowns.items() if now - t > COOLDOWN_SECONDS]
    for m in expired:
        del alert_cooldowns[m]

    if mac in alert_cooldowns:
        return True

    alert_cooldowns[mac] = now
    return False


# DHCP hostname capture

hostname_cache = {}  # mac -> hostname

def handle_dhcp(packet):
    if not packet.haslayer(DHCP):
        return

    mac = packet[Ether].src.lower()
    hostname = None
    for opt in packet[DHCP].options:
        if isinstance(opt, tuple) and opt[0] == "hostname":
            value = opt[1]
            hostname = value.decode(errors="ignore") if isinstance(value, bytes) else value
            break

    if hostname:
        hostname_cache[mac] = hostname
        log(f"[DHCP] {mac} identifies as '{hostname}'")


# ARP poisoning detection

ip_mac_map = {}          # ip -> the MAC that FIRST claimed it (baseline)
spoof_cooldowns = {}
SPOOF_COOLDOWN_SECONDS = 30


def get_gateway_ip():
    """Best-effort auto-detect of the default gateway (your router)."""
    try:
        return conf.route.route("0.0.0.0")[2]
    except Exception:
        return None


GATEWAY_IP = config.get("gateway_ip") or get_gateway_ip()


def is_spoof_on_cooldown(ip: str) -> bool:
    now = time.time()
    last = spoof_cooldowns.get(ip)
    if last and (now - last) < SPOOF_COOLDOWN_SECONDS:
        return True
    spoof_cooldowns[ip] = now
    return False

def is_off_hours(now=None) -> bool:
    """True if the current local hour falls inside the off-hours window."""
    hour = (now or datetime.now()).hour
    start, end = OFF_HOURS_START, OFF_HOURS_END
    if start == end:
        return False
    if start < end:
        return start <= hour < end          # normal activity window
    return hour >= start or hour < end   

def detect_arp_spoof(packet):
    """Flag when an IP is suddenly claimed by a different MAC — the poisoning signature."""
    src_ip  = packet[ARP].psrc
    src_mac = packet[ARP].hwsrc.lower()

    if src_ip in ("0.0.0.0", "") or src_mac in ("00:00:00:00:00:00", ""):
        return

    known_mac = ip_mac_map.get(src_ip)

    if known_mac is None:
        ip_mac_map[src_ip] = src_mac   # sets a MAC's assigned IP to it's first sighting 
        return

    if known_mac != src_mac:
        # Keep the original baseline so an ongoing attack keeps re-alerting.
        if is_spoof_on_cooldown(src_ip):
            return

        is_gateway = (src_ip == GATEWAY_IP)
        severity = "CRITICAL" if is_gateway else "WARNING"
        label    = " (DEFAULT GATEWAY)" if is_gateway else ""
        vendor   = get_vendor(src_mac)

        details = (f"{src_ip}{label} now claims {src_mac} "
                   f"(was {known_mac}). Vendor: {vendor}")
        log(f"[SPOOF/{severity}] {details}")
        log_event("arp_spoof", severity, ip=src_ip, mac=src_mac, details=details)
        send_spoof_email(src_ip, known_mac, src_mac, is_gateway)

# detect port scanning

scan_tracker = {}    # src_ip -> list of (timestamp, dst_port)
scan_cooldowns = {}  # src_ip -> last alert time


def detect_port_scan(src_ip: str, dst_ip: str, dport: int):
    """Flag a source that hits many distinct ports in a short window."""
    now = time.time()

    history = scan_tracker.setdefault(src_ip, [])
    history.append((now, dport))

    # Drop anything outside the rolling window
    cutoff = now - SCAN_WINDOW_SECONDS
    history[:] = [(t, p) for (t, p) in history if t >= cutoff]

    distinct_ports = {p for (t, p) in history}
    if len(distinct_ports) < SCAN_PORT_THRESHOLD:
        return

    # One alert per source per cooldown, so an ongoing scan doesn't flood
    last = scan_cooldowns.get(src_ip)
    if last and (now - last) < SCAN_COOLDOWN_SECONDS:
        return
    scan_cooldowns[src_ip] = now

    count = len(distinct_ports)
    mac = ip_mac_map.get(src_ip)  # reuse the MAC we learned from ARP, if we have it
    sample = ", ".join(str(p) for p in sorted(distinct_ports)[:10])
    details = (f"Possible port scan from {src_ip}"
               + (f" ({mac})" if mac else "")
               + f" → {dst_ip}: {count} ports in {SCAN_WINDOW_SECONDS}s "
                 f"(e.g. {sample})")
    log(f"[SCAN] {details}")
    log_event("port_scan", "WARNING", ip=src_ip, mac=mac, details=details)
    send_scan_email(src_ip, dst_ip, count)

# email alert handling

def _send(msg: EmailMessage, kind: str):
    if not EMAIL_ALERTS_ENABLED:
        log(f"[EMAIL] Alerts disabled in settings — skipping {kind}")
        return
    if not ALERT_EMAIL:
        log(f"[EMAIL] No alert_email set — skipping {kind}")
        return
    try:
        with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
            server.login(EMAIL_USER, EMAIL_PASS)
            server.send_message(msg)
        log(f"[EMAIL] {kind} sent to {ALERT_EMAIL}")
    except Exception as e:
        log(f"[EMAIL] Failed to send {kind}: {e}")


def send_alert_email(mac: str, ip: str, vendor: str, hostname: str = None):
    msg = EmailMessage()
    msg["Subject"] = f"⚠ Unknown device on your network: {mac}"
    msg["From"]    = EMAIL_USER
    msg["To"]      = ALERT_EMAIL
    msg.set_content(
        f"An unrecognised device joined your network.\n\n"
        f"MAC:      {mac}\n"
        f"IP:       {ip}\n"
        f"Vendor:   {vendor}\n"
        f"Hostname: {hostname or 'unknown'}\n"
    )
    _send(msg, "device alert")


def send_spoof_email(ip, old_mac, new_mac, is_gateway):
    urgency = "CRITICAL — GATEWAY" if is_gateway else "Warning"
    msg = EmailMessage()
    msg["Subject"] = f"⚠ [{urgency}] Possible ARP spoofing on {ip}"
    msg["From"]    = EMAIL_USER
    msg["To"]      = ALERT_EMAIL
    msg.set_content(
        f"A possible ARP poisoning attack was detected.\n\n"
        f"IP address:   {ip}\n"
        f"Was owned by: {old_mac}\n"
        f"Now claims:   {new_mac}\n\n"
        + ("This is your DEFAULT GATEWAY — treat as serious. All your traffic "
           "could be routed through an attacker.\n" if is_gateway else "")
    )
    _send(msg, "spoof alert")

def send_scan_email(src_ip, dst_ip, count):
    msg = EmailMessage()
    msg["Subject"] = f"⚠ [Warning] Possible port scan from {src_ip}"
    msg["From"]    = EMAIL_USER
    msg["To"]      = ALERT_EMAIL
    msg.set_content(
        f"A possible port scan was detected on your network.\n\n"
        f"Source:      {src_ip}\n"
        f"Target:      {dst_ip}\n"
        f"Ports hit:   {count} in {SCAN_WINDOW_SECONDS} seconds\n"
    )
    _send(msg, "port scan alert")

# packet handling

def handle_arp(packet):
    # checks for spoofing, then checks for unrecognized MACs
    detect_arp_spoof(packet)

    src_mac = packet[ARP].hwsrc.lower()
    src_ip  = packet[ARP].psrc

    if src_mac not in WHITELIST and not is_on_cooldown(src_mac):
        vendor   = get_vendor(src_mac)
        hostname = hostname_cache.get(src_mac)
        log_alert(mac=src_mac, ip=src_ip, vendor=vendor, hostname=hostname)
        send_alert_email(src_mac, src_ip, vendor, hostname)
        host = f" [{hostname}]" if hostname else ""
        log(f"[ALERT] Unknown device — {src_ip} ({src_mac}){host} | Vendor: {vendor}")
        if is_off_hours():
            details = (f"Unknown device active during off-hours "
                       f"({OFF_HOURS_START:02d}:00-{OFF_HOURS_END:02d}:00): "
                       f"{src_ip} ({src_mac}){host}. Vendor: {vendor}")
            log(f"[OFF-HOURS] {details}")
            log_event("off_hours", "WARNING", ip=src_ip, mac=src_mac, details=details)

def handle_tcp(packet):
    if not (packet.haslayer(IP) and packet.haslayer(TCP)):
        return
    detect_port_scan(packet[IP].src, packet[IP].dst, packet[TCP].dport)

def handle_packet(packet):
    try:
        if packet.haslayer(ARP):
            handle_arp(packet)
        elif packet.haslayer(DHCP):
            handle_dhcp(packet)
        elif packet.haslayer(TCP):
            handle_tcp(packet)
    except Exception as e:
        log(f"[ERROR] Could not parse packet: {e}")



# main program loop
if __name__ == "__main__":
    init_db()
    log(f"NetDetector starting — {len(WHITELIST)} whitelisted devices")
    log(f"Gateway: {GATEWAY_IP or 'unknown'} | Alerts to: {ALERT_EMAIL or '(none set)'}")
    log("-" * 60)
# init sniffer
    sniff(
        prn=handle_packet,
        store=False,
        filter="arp or (tcp[tcpflags] & (tcp-syn|tcp-ack) == tcp-syn) or (udp and (port 67 or port 68))",
    )
