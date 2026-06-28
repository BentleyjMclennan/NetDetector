"""
Web interface for the network logger — serves a live dashboard.
Run with: uvicorn web_server:app --host 0.0.0.0 --port 8000

Requires: pip install fastapi uvicorn

The sniffer (netdetector.py) keeps writing alerts to network_log.db.
This server reads that DB and pushes updates to the browser over a WebSocket,
so the dashboard updates in near real time without the page polling itself.
"""

import asyncio
import json
import os
import subprocess
import sys

from fastapi import FastAPI, WebSocket, WebSocketDisconnect
from fastapi.responses import FileResponse

from database import get_recent_alerts, get_recent_events

app = FastAPI()

BASE_DIR = os.path.dirname(os.path.abspath(__file__))
DASHBOARD_PATH = os.path.join(BASE_DIR, "dashboard.html")
CONFIG_PATH = os.path.join(BASE_DIR, "config.json")
SNIFFER_SCRIPT = os.path.join(BASE_DIR, "netdetector.py")

# How often the server checks the DB for changes (seconds).
POLL_INTERVAL = 0.5


# ── Routes ─────────────────────────────────────────────────────────────────────

@app.get("/")
async def dashboard():
    """Serve the dashboard page."""
    return FileResponse(DASHBOARD_PATH, media_type="text/html")


@app.get("/api/alerts")
async def api_alerts():
    """REST endpoint — handy for testing and the dashboard's initial load."""
    return await asyncio.to_thread(get_recent_alerts)


@app.get("/api/events")
async def api_events():
    """Incident history (ARP spoofing, etc.) — the second dashboard feed."""
    return await asyncio.to_thread(get_recent_events)


@app.get("/api/state")
async def api_state():
    """Both feeds in one call — used by the dashboard's fallback refresh."""
    alerts = await asyncio.to_thread(get_recent_alerts)
    events = await asyncio.to_thread(get_recent_events)
    return {"alerts": alerts, "events": events}


@app.websocket("/ws")
async def state_socket(websocket: WebSocket):
    """
    Push the current device list AND incident list to the browser, then keep
    pushing whenever either changes. We compare a lightweight 'signature' each
    tick and only send when it actually differs, to avoid spamming the client.
    """
    await websocket.accept()
    last_signature = None

    try:
        while True:
            # Run the (blocking) DB queries in threads so we don't stall the loop
            alerts = await asyncio.to_thread(get_recent_alerts)
            events = await asyncio.to_thread(get_recent_events)

            # Signature changes when a device is added/updated OR a new incident
            # lands (events are append-only, so their count + newest id is enough).
            alert_sig = [(a["mac"], a["last_seen"], a["alert_count"]) for a in alerts]
            event_sig = (len(events), events[0]["id"] if events else None)
            signature = (alert_sig, event_sig)

            if signature != last_signature:
                await websocket.send_text(json.dumps({
                    "alerts": alerts,
                    "events": events,
                }))
                last_signature = signature

            await asyncio.sleep(POLL_INTERVAL)

    except WebSocketDisconnect:
        # Browser tab closed — nothing to clean up, just exit quietly
        pass


# ── Config: the alert recipient email ───────────────────────────────────────────
# ⚠ The Start button below only works if THIS server runs elevated (Run as
#   Administrator), because the sniffer it launches inherits these privileges and
#   Scapy needs admin to capture. When control features are enabled, bind to
#   localhost so they aren't reachable from the LAN:
#       python -m uvicorn web_server:app --host 127.0.0.1 --port 8000

def _read_config() -> dict:
    with open(CONFIG_PATH, encoding="utf-8") as f:
        return json.load(f)


def _write_config(cfg: dict) -> None:
    with open(CONFIG_PATH, "w", encoding="utf-8") as f:
        json.dump(cfg, f, indent=2)


def _looks_like_ip(value: str) -> bool:
    parts = value.split(".")
    return len(parts) == 4 and all(p.isdigit() and 0 <= int(p) <= 255 for p in parts)


def _config_view(cfg: dict) -> dict:
    """The safe, browser-facing shape of the config (never the SMTP password)."""
    return {
        "alert_email": cfg.get("email", {}).get("alert_email", ""),
        "gateway_ip": cfg.get("gateway_ip", ""),
        "email_alerts_enabled": cfg.get("email_alerts_enabled", True),
    }


@app.get("/config")
async def config_page():
    """Serve the settings page."""
    return FileResponse(os.path.join(BASE_DIR, "config.html"), media_type="text/html")


@app.get("/api/config")
async def get_config():
    cfg = await asyncio.to_thread(_read_config)
    return _config_view(cfg)


@app.post("/api/config")
async def update_config(payload: dict):
    cfg = await asyncio.to_thread(_read_config)

    if "alert_email" in payload:
        email = (payload.get("alert_email") or "").strip()
        if email and "@" not in email:
            return {"error": "That doesn't look like an email address."}
        cfg.setdefault("email", {})["alert_email"] = email

    if "gateway_ip" in payload:
        gw = (payload.get("gateway_ip") or "").strip()
        if gw and not _looks_like_ip(gw):
            return {"error": "Gateway must be an IP like 192.168.1.1 (or blank to auto-detect)."}
        cfg["gateway_ip"] = gw

    if "email_alerts_enabled" in payload:
        cfg["email_alerts_enabled"] = bool(payload.get("email_alerts_enabled"))

    await asyncio.to_thread(_write_config, cfg)
    return _config_view(cfg)


# ── Sniffer process control ─────────────────────────────────────────────────────

class SnifferManager:
    """Starts and stops netdetector.py as a child process."""

    def __init__(self):
        self.process = None

    def is_running(self) -> bool:
        # poll() returns None while the process is still alive
        return self.process is not None and self.process.poll() is None

    def start(self) -> bool:
        if self.is_running():
            return False
        self.process = subprocess.Popen(
            [sys.executable, SNIFFER_SCRIPT],
            cwd=BASE_DIR,
        )
        return True

    def stop(self) -> bool:
        if not self.is_running():
            return False
        self.process.terminate()
        try:
            self.process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            self.process.kill()   # force it if it won't exit gracefully
        self.process = None
        return True


sniffer = SnifferManager()


@app.get("/api/sniffer/status")
async def sniffer_status():
    return {"running": sniffer.is_running()}


@app.post("/api/sniffer/start")
async def sniffer_start():
    sniffer.start()
    return {"running": sniffer.is_running()}


@app.post("/api/sniffer/stop")
async def sniffer_stop():
    sniffer.stop()
    return {"running": sniffer.is_running()}


@app.on_event("shutdown")
async def _cleanup():
    # Don't leave an orphan capture process running if the server stops
    sniffer.stop()
