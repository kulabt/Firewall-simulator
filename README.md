# Firewall Monitor with Alerting System

A Python-based network firewall monitor that detects and blocks malicious traffic, including Nimda worm attacks and DDoS-style rate-based attacks. Features real-time alerting via email and webhooks.

## Features

✅ **Packet Sniffing** – Real-time IP packet monitoring using Scapy  
✅ **Nimda Worm Detection** – Identifies and blocks Nimda-style `GET /scripts/root.exe` payloads  
✅ **Rate-Based Blocking** – Blocks IPs exceeding configurable packet rate threshold (default: 40 pps)  
✅ **Whitelist/Blacklist** – Skip or immediately block known IPs  
✅ **Email Alerts** – SMTP notifications on security events  
✅ **Webhook Alerts** – JSON POST to external services (Slack, Discord, custom endpoints)  
✅ **Alert Cooldown** – Prevents alert spam with configurable suppression window  
✅ **Comprehensive Logging** – Timestamped event logs in `logs/` folder  
✅ **Cross-Platform** – Graceful handling on Windows (logs-only) and Linux (full iptables blocking)  

## Requirements

- **Python 3.7+**
- **Scapy** – packet manipulation library
- **Linux/WSL** (recommended for actual iptables blocking)
- **Root/Administrator privileges** – required for packet sniffing and firewall rules

## Installation

### On Linux / WSL Ubuntu

```bash
# Update package manager
sudo apt update && sudo apt upgrade -y

# Install Python and pip
sudo apt install python3 python3-pip -y

# Install Scapy
sudo pip3 install scapy
```

### On Windows (no actual blocking)

```powershell
pip install scapy
# Note: Install Npcap (https://nmap.org/npcap/) for packet capture support
```

## Quick Start

### 1. Clone or download the repository
```bash
git clone https://github.com/yourusername/firewall-monitor.git
cd firewall-monitor
```

### 2. Create IP lists
```bash
touch whitelist.txt blacklist.txt
```

Optionally add IPs (one per line):
```
# whitelist.txt – allowed IPs
192.168.1.100
10.0.0.50

# blacklist.txt – always block
203.0.113.1
198.51.100.5
```

### 3. Configure alerts (optional)
Edit `alert_config.json`:

```json
{
    "cooldown": 60,
    "email": {
        "enabled": true,
        "server": "smtp.gmail.com",
        "port": 465,
        "use_ssl": true,
        "username": "your-email@gmail.com",
        "password": "your-app-password",
        "from": "your-email@gmail.com",
        "to": ["admin@example.com"]
    },
    "webhook": {
        "enabled": true,
        "url": "https://hooks.slack.com/services/YOUR/WEBHOOK/URL"
    }
}
```

### 4. Run the firewall monitor (as root/admin)

**Linux/WSL:**
```bash
sudo python3 firewall3.py
```

**Windows (PowerShell as Administrator):**
```powershell
python firewall3.py
```

### 5. Test with packet sender (in another terminal)

Edit `nimda_packet.py` and set the target IP, then:

```bash
# Single Nimda packet
sudo python3 nimda_packet.py

# Multiple packets to trigger rate-based block
python3 -c "
from nimda_packet import send_nimda_packet
for i in range(100):
    send_nimda_packet('TARGET_IP')
"
```

## Configuration

### `alert_config.json`

| Key | Type | Description |
|-----|------|-------------|
| `cooldown` | int | Alert suppression window in seconds (default: 60) |
| `email.enabled` | bool | Enable email alerts |
| `email.server` | str | SMTP server address |
| `email.port` | int | SMTP port (465 = SSL, 587 = TLS) |
| `email.use_ssl` | bool | Use SSL for connection |
| `email.use_tls` | bool | Use STARTTLS for connection |
| `email.username` | str | SMTP username |
| `email.password` | str | SMTP password or app-specific token |
| `email.from` | str | Sender email address |
| `email.to` | list | Recipient email addresses |
| `webhook.enabled` | bool | Enable webhook alerts |
| `webhook.url` | str | Webhook endpoint URL (Slack, Discord, custom) |

### Firewall Threshold

Edit `THRESHOLD` in `firewall3.py` (default: 40 packets/second):

```python
THRESHOLD = 40  # Block IPs sending >40 packets/sec
```

## Alert Types

The system sends three types of alerts:

1. **Blacklisted IP Blocked** (CRITICAL)
   - Triggered when IP matches `blacklist.txt`

2. **Nimda Worm Detected** (CRITICAL)
   - Triggered by `GET /scripts/root.exe` payload on port 80

3. **IP Rate Limited and Blocked** (WARNING)
   - Triggered when packet rate exceeds `THRESHOLD`

## Logging

All events logged to `logs/log_YYYY-MM-DD_HH-MM-SS.txt`:

```
2025-12-30T14:35:22.123456 [CRITICAL] Nimda worm detected: Detected Nimda-style GET payload from 192.168.1.50: ...
2025-12-30T14:35:25.456789 [WARNING] IP rate limited and blocked: Blocking IP: 203.0.113.1, packet rate: 125.5
```

## Verify Blocked IPs (Linux/WSL)

```bash
sudo iptables -L -n | grep DROP
```

## Example Use Cases

### Monitor home network for attacks
```bash
sudo python3 firewall3.py
# Runs continuously, logs suspicious activity
```

### Alert team on Slack/Discord
1. Get webhook URL from Slack/Discord integration
2. Set `webhook.enabled = true` and paste URL in `alert_config.json`
3. All alerts will POST to your channel

### Test firewall detection
```bash
# In Terminal A:
sudo python3 firewall3.py

# In Terminal B:
sudo python3 nimda_packet.py

# In Terminal C (watch logs):
tail -f logs/log_*.txt
```

## Troubleshooting

### Permission Denied
```bash
# Always use sudo on Linux/WSL
sudo python3 firewall3.py
```

### Scapy Import Error
```bash
sudo pip3 install scapy
```

### No Packets Captured
- Ensure you're running with root privileges
- On Windows, verify Npcap is installed
- Check network interface name with `ip link show` (Linux)

### Alerts Not Sending
- Verify SMTP/webhook URL credentials in `alert_config.json`
- Check logs: `tail -f logs/log_*.txt`
- Test SMTP with: `python3 -c "import smtplib; ..."`

## Files

| File | Purpose |
|------|---------|
| `firewall3.py` | Main firewall monitor script |
| `nimda_packet.py` | Test packet sender (for demo/testing) |
| `alert_config.json` | Alert configuration (email, webhook) |
| `whitelist.txt` | Trusted IPs (one per line) |
| `blacklist.txt` | Always-block IPs (one per line) |
| `logs/` | Event log files (created at runtime) |

## Security Notes ⚠️

- **Root Access**: This script requires root to modify firewall rules. Use with caution.
- **Email Credentials**: Store SMTP passwords securely (consider environment variables or secrets manager).
- **Testing Only**: Test on your own networks. Do not use to attack others.
- **Nimda Detection**: Detection is simple payload matching. Real-world filtering requires deeper DPI.

## Future Enhancements

- [ ] GeoIP-based blocking
- [ ] Machine learning-based anomaly detection
- [ ] Dashboard UI for real-time monitoring
- [ ] Syslog integration
- [ ] Multiple firewall rule targets (UFW, firewalld)

## License

MIT License – feel free to use and modify

## Contributing

Found a bug or have a feature request? Open an issue or submit a PR!

## Contact

For questions or issues, open a GitHub issue or reach out.

---

**Happy monitoring! 🔒**

