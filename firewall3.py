import os
import sys
import time
import json
import ssl
import shutil
import platform
import urllib.request
import smtplib
from collections import defaultdict
from datetime import datetime
from scapy.all import sniff, IP, TCP

THRESHOLD = 40
ALERT_CONFIG_FILE = "alert_config.json"
DEFAULT_ALERT_CONFIG = {
    "cooldown": 60,
    "email": {
        "enabled": False,
        "server": "smtp.example.com",
        "port": 465,
        "use_ssl": True,
        "use_tls": False,
        "username": "user@example.com",
        "password": "changeme",
        "from": "fw@example.com",
        "to": ["admin@example.com"]
    },
    "webhook": {
        "enabled": False,
        "url": "https://example.com/webhook"
    }
}

print(f"THRESHOLD: {THRESHOLD}")

# Globals set in __main__
alert_config = {}
last_alert_times = {}


def read_ip_file(filename):
    try:
        with open(filename, "r") as file:
            ips = [line.strip() for line in file if line.strip()]
        return set(ips)
    except FileNotFoundError:
        log_event(f"IP file not found: {filename}")
        return set()


def load_alert_config():
    global alert_config
    if os.path.exists(ALERT_CONFIG_FILE):
        try:
            with open(ALERT_CONFIG_FILE, "r") as f:
                cfg = json.load(f)
            alert_config = {**DEFAULT_ALERT_CONFIG, **cfg}
            # Merge nested dicts
            alert_config['email'] = {**DEFAULT_ALERT_CONFIG['email'], **cfg.get('email', {})}
            alert_config['webhook'] = {**DEFAULT_ALERT_CONFIG['webhook'], **cfg.get('webhook', {})}
        except Exception as e:
            log_event(f"Failed to load alert config: {e}")
            alert_config = DEFAULT_ALERT_CONFIG.copy()
    else:
        alert_config = DEFAULT_ALERT_CONFIG.copy()
        # Create sample config for user to edit
        try:
            with open(ALERT_CONFIG_FILE, "w") as f:
                json.dump(DEFAULT_ALERT_CONFIG, f, indent=4)
            log_event(f"Created sample alert config: {ALERT_CONFIG_FILE}")
        except Exception:
            pass


def is_nimda_worm(packet):
    if packet.haslayer(TCP) and packet[TCP].dport == 80:
        payload = packet[TCP].payload
        return "GET /scripts/root.exe" in str(payload)
    return False


def log_event(message):
    try:
        log_folder = "logs"
        os.makedirs(log_folder, exist_ok=True)
        timestamp = datetime.now().strftime("%Y-%m-%d_%H-%M-%S")
        log_file = os.path.join(log_folder, f"log_{timestamp}.txt")
        with open(log_file, "a") as file:
            file.write(f"{message}\n")
    except Exception:
        # Fallback to printing if logging fails
        print(f"LOG ERROR: {message}")


def send_email_alert(subject, body):
    if not alert_config.get('email', {}).get('enabled'):
        return False
    conf = alert_config['email']
    try:
        msg = f"From: {conf['from']}\r\nTo: {', '.join(conf['to'])}\r\nSubject: {subject}\r\n\r\n{body}"
        if conf.get('use_ssl', True):
            context = ssl.create_default_context()
            with smtplib.SMTP_SSL(conf['server'], conf['port'], context=context) as server:
                if conf.get('username'):
                    server.login(conf['username'], conf['password'])
                server.sendmail(conf['from'], conf['to'], msg)
        else:
            with smtplib.SMTP(conf['server'], conf['port']) as server:
                if conf.get('use_tls'):
                    server.starttls(context=ssl.create_default_context())
                if conf.get('username'):
                    server.login(conf['username'], conf['password'])
                server.sendmail(conf['from'], conf['to'], msg)
        log_event(f"Email alert sent: {subject}")
        return True
    except Exception as e:
        log_event(f"Failed to send email alert: {e}")
        return False


def send_webhook_alert(payload):
    if not alert_config.get('webhook', {}).get('enabled'):
        return False
    try:
        url = alert_config['webhook']['url']
        data = json.dumps(payload).encode('utf-8')
        req = urllib.request.Request(url, data=data, headers={'Content-Type': 'application/json'})
        with urllib.request.urlopen(req, timeout=10) as resp:
            log_event(f"Webhook posted, status: {getattr(resp, 'status', 'unknown')}")
        return True
    except Exception as e:
        log_event(f"Failed to post webhook: {e}")
        return False


def alert(title, message, ip=None, level='warning'):
    now = time.time()
    cooldown = alert_config.get('cooldown', 60)
    key = ip if ip else title
    last = last_alert_times.get(key, 0)
    if now - last < cooldown:
        log_event(f"Suppressed alert due to cooldown: {title}")
        return
    last_alert_times[key] = now

    full = f"{datetime.now().isoformat()} [{level.upper()}] {title}: {message}"
    log_event(full)

    # Send alerts based on config
    send_email_alert(title, full)
    send_webhook_alert({"title": title, "message": full, "ip": ip, "level": level})


def safe_block_ip(ip):
    # On non-Linux or when iptables not available, just log the action
    if platform.system() != 'Linux' or shutil.which('iptables') is None:
        log_event(f"Would block IP (platform unsupported or iptables missing): {ip}")
        return False
    cmd = f"iptables -A INPUT -s {ip} -j DROP"
    os.system(cmd)
    return True


def packet_callback(packet):
    try:
        src_ip = packet[IP].src
    except Exception:
        return

    if src_ip in whitelist_ips:
        return

    if src_ip in blacklist_ips:
        safe_block_ip(src_ip)
        log_event(f"Blocking blacklisted IP: {src_ip}")
        alert("Blacklisted IP blocked", f"Blocking blacklisted IP: {src_ip}", ip=src_ip, level='critical')
        return
    
    if is_nimda_worm(packet):
        print(f"Blocking Nimda source IP: {src_ip}")
        safe_block_ip(src_ip)
        payload = str(packet[TCP].payload) if packet.haslayer(TCP) else ""
        log_event(f"Blocking Nimda source IP: {src_ip}")
        alert("Nimda worm detected", f"Detected Nimda-style GET payload from {src_ip}: {payload}", ip=src_ip, level='critical')
        return

    packet_count[src_ip] += 1

    current_time = time.time()
    time_interval = current_time - start_time[0]

    if time_interval >= 1:
        for ip, count in packet_count.items():
            packet_rate = count / time_interval

            if packet_rate > THRESHOLD and ip not in blocked_ips:
                print(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                safe_block_ip(ip)
                log_event(f"Blocking IP: {ip}, packet rate: {packet_rate}")
                alert("IP rate limited and blocked", f"Blocking IP: {ip}, packet rate: {packet_rate}", ip=ip, level='warning')
                blocked_ips.add(ip)

        packet_count.clear()
        start_time[0] = current_time


if __name__ == "__main__":
    # Check for root only on POSIX systems
    if os.name != 'nt':
        try:
            if os.geteuid() != 0:
                print("This script requires root privileges.")
                sys.exit(1)
        except AttributeError:
            pass

    load_alert_config()

    whitelist_ips = read_ip_file("whitelist.txt")
    blacklist_ips = read_ip_file("blacklist.txt")

    packet_count = defaultdict(int)
    start_time = [time.time()]
    blocked_ips = set()

    print("Monitoring network traffic...")
    sniff(filter="ip", prn=packet_callback)