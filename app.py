"""Flask dashboard and real-time capture service for the Linux Security Monitor."""

import os
from threading import Lock, Thread

from flask import Flask, jsonify, render_template

from database import get_recent_alerts, get_recent_packets, get_summary, init_db
from monitor import start_capture

app = Flask(__name__)
init_db()
capture_state = {"running": False, "error": None}
capture_lock = Lock()


def rows_to_dict(rows):
    return [dict(row) for row in rows]


@app.get("/")
def dashboard():
    return render_template(
        "dashboard.html",
        summary=get_summary(),
        alerts=get_recent_alerts(),
        packets=get_recent_packets(),
    )


def run_capture(interface: str | None) -> None:
    with capture_lock:
        capture_state["running"] = True
        capture_state["error"] = None
    try:
        start_capture(interface)
    except Exception as error:
        with capture_lock:
            capture_state["error"] = str(error)
    finally:
        with capture_lock:
            capture_state["running"] = False


def start_background_capture() -> None:
    interface = os.getenv("MONITOR_INTERFACE") or None
    Thread(target=run_capture, args=(interface,), daemon=True, name="scapy-capture").start()


@app.get("/api/dashboard")
def dashboard_data():
    with capture_lock:
        status = dict(capture_state)
    return jsonify({
        "summary": get_summary(),
        "alerts": rows_to_dict(get_recent_alerts()),
        "packets": rows_to_dict(get_recent_packets()),
        "capture": status,
    })


@app.get("/api/summary")
def summary():
    return jsonify(get_summary())


if __name__ == "__main__":
    start_background_capture()
    app.run(host="0.0.0.0", port=5000, debug=False)
