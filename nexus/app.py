"""Nexus — central progression tracker for VulnLab."""

import requests
from flask import Flask, render_template, jsonify

app = Flask(__name__)

MODES = [
    {"id": "easy",   "name": "Easy Mode",   "endpoint": "http://easy:5000",
     "port": 8080,
     "desc": "Four basic web vulns in one Flask + Nginx setup"},
    {"id": "medium", "name": "Medium Mode", "endpoint": "http://medium:5000",
     "port": 9090,
     "desc": "Harder find, tripwires, honeypots, no map"},
    {"id": "hard",   "name": "Hard Mode",   "endpoint": "http://hard-api:5001",
     "port": 9191,
     "desc": "Three microservices, SSRF, JWT bypass, internal RCE chain"},
]


def fetch_status(base_url):
    try:
        r = requests.get(f"{base_url}/progress/status", timeout=5)
        if r.status_code == 200:
            return r.json()
    except Exception:
        pass
    return None


@app.route("/")
def index():
    cards = []
    for m in MODES:
        url = m['endpoint']
        status = fetch_status(url)
        token = None
        if status and status.get("all_done"):
            try:
                tr = requests.get(f"{url}/progress/token", timeout=5)
                if tr.status_code == 200:
                    token = tr.json().get("token", "")
            except Exception:
                pass
        cards.append({
            **m,
            "status": status or {"error": "unreachable"},
            "token": token,
        })
    return render_template("index.html", cards=cards)


@app.route("/api/status")
def api_status():
    results = {}
    for m in MODES:
        url = m['endpoint']
        results[m['id']] = fetch_status(url)
    return jsonify(results)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=7070, debug=True)
