# NetDetector

A home-network monitor: detects unrecognised devices and suspicious activity, logs them
to SQLite, sends email alerts, and shows everything on a live web dashboard.

## Files

| File             | Role                                                                 |
|------------------|----------------------------------------------------------------------|
| `netdetector.py` | The sniffer. Captures ARP + DHCP, detects unknown devices & spoofing. |
| `database.py`    | SQLite storage: `alerts` (devices) and `events` (incidents) tables.   |
| `web_server.py`  | FastAPI app: serves the dashboard, streams updates, controls sniffer. |
| `dashboard.html` | The live dashboard UI (devices + incidents + controls).              |
| `config.json`    | Email credentials + alert recipient + cooldown.                      |
| `whitelist.json` | MAC addresses to treat as known/safe.                               |
| `arp_test.py`    | Test tool — crafts packets to exercise detection without a real device. |
| `traffic.log`    | Created at runtime — a flat text log of everything.                  |
| `network_log.db` | Created at runtime — the SQLite database.                            |


## Setup

1. Install dependencies:
   ```
   pip install scapy fastapi "uvicorn[standard]"
   ```
   On Windows, also install Npcap (https://npcap.com/) for packet capture.

2. Edit `config.json`:
   - `email.username` / `email.password` — the Gmail account that SENDS alerts
     (use a Gmail App Password, not your normal password).
   - `email.alert_email` — where alerts go (can also be set from the dashboard).

3. Add your known devices to `whitelist.json`.

## Running

Two processes. On Windows the sniffer needs an **Administrator** PowerShell;
the web server does not.

- Sniffer (elevated):
  ```
  python netdetector.py
  ```
- Web server (normal — or elevated if you want the dashboard's Start button to work):
  ```
  python -m uvicorn web_server:app --host 127.0.0.1 --port 8000
  ```

Then open http://localhost:8000
