"""Orbit API Service -- external-facing, port 5001.
Vulnerabilities: JWT none, SSRF, cache poisoning, internal proxy RCE.
"""

import re
import time
from functools import wraps

import jwt as pyjwt
import requests
from flask import Flask, request, Response, render_template_string, jsonify

app = Flask(__name__)

BAN_SECONDS = 240
_BANS = {}

_HONEYPOT_PATHS = {
    "/debug", "/shell", "/exec", "/cmd",
    "/wp-admin", "/wp-login", "/.env", "/config",
    "/backup", "/db", "/sql", "/phpmyadmin", "/manager",
    "/console", "/vuln", "/.git",
    "/server-status", "/actuator", "/swagger",
    "/setup", "/install", "/phpinfo",
}

_TRIP_PATTERNS = {
    re.compile(r"<\s*script", re.I): "script tag",
    re.compile(r"alert\s*\(", re.I): "alert()",
    re.compile(r"confirm\s*\(", re.I): "confirm()",
    re.compile(r"prompt\s*\(", re.I): "prompt()",
    re.compile(r"document\.cookie", re.I): "cookie access",
    re.compile(r"\b1\s*=\s*1\b"): "tautology",
    re.compile(r"UNION\s+SELECT", re.I): "UNION SELECT",
}


def _real_ip():
    f = request.headers.get("X-Forwarded-For", "")
    return f.split(",")[0].strip() if f else (request.remote_addr or "unknown")


def _is_banned(ip):
    ex = _BANS.get(ip, 0)
    if time.time() < ex:
        return True
    if ex:
        del _BANS[ip]
    return False


def _ban(ip):
    _BANS[ip] = time.time() + BAN_SECONDS


def _scan_tripwires(ip):
    for vals in request.args.values():
        for v in vals if isinstance(vals, list) else [vals]:
            for pat, label in _TRIP_PATTERNS.items():
                if pat.search(v):
                    _ban(ip)
                    return True
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        for v in data.values() if isinstance(data, dict) else []:
            if isinstance(v, str):
                for pat, label in _TRIP_PATTERNS.items():
                    if pat.search(v):
                        _ban(ip)
                        return True
    return False


def guard(f):
    @wraps(f)
    def wrapper(*a, **kw):
        ip = _real_ip()
        if _is_banned(ip):
            r = int(_BANS[ip] - time.time())
            return Response(f"Rate limit. Try again in {r}s.", 429)
        if _scan_tripwires(ip):
            return Response("Request blocked.", 429)
        return f(*a, **kw)
    return wrapper


@app.before_request
def _path_trip():
    ip = _real_ip()
    if _is_banned(ip):
        return None
    path = request.path.lower().rstrip("/")
    for hp in _HONEYPOT_PATHS:
        n = hp.lower()
        if path == n or path.startswith(n + "/"):
            _ban(ip)
            r = int(_BANS[ip] - time.time())
            return Response(f"Rate limit. Try again in {r}s.", 429)
    return None


_JWT_SECRET = "orbit-dev-secret-2024"
_JWT_ALGO = "HS256"
_INTERNAL_SECRET = "trusted"


def _mk_token(payload):
    return pyjwt.encode(payload, _JWT_SECRET, algorithm=_JWT_ALGO)


def _verify_token(token):
    """Accepts 'none' algorithm."""
    if not token:
        return None
    try:
        return pyjwt.decode(token, _JWT_SECRET, algorithms=["HS256"])
    except (pyjwt.InvalidSignatureError, Exception):
        pass
    try:
        return pyjwt.decode(token, options={"verify_signature": False})
    except Exception:
        return None


@app.route("/")
@guard
def index():
    return jsonify({"service": "orbit-api", "version": "1.2.0"})


@app.route("/auth/login", methods=["POST"])
@guard
def login():
    data = request.get_json(silent=True) or {}
    username = data.get("username", "guest")
    role = "user"
    if username == "admin":
        role = "admin"
    token = _mk_token({"sub": username, "role": role})
    return jsonify({"token": token, "type": "Bearer"})


@app.route("/auth/verify")
@guard
def verify():
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    payload = _verify_token(token)
    if payload:
        return jsonify({"valid": True, "claims": payload})
    return jsonify({"valid": False}), 401


@app.route("/profile")
@guard
def profile():
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    payload = _verify_token(token)
    if not payload:
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({
        "user": payload.get("sub"),
        "role": payload.get("role"),
    })


@app.route("/api/avatar")
@guard
def avatar():
    """SSRF -- fetches arbitrary URLs."""
    url = request.args.get("url", "")
    if not url:
        return jsonify({"error": "missing url"}), 400
    try:
        resp = requests.get(url, timeout=5, allow_redirects=False)
        return Response(
            resp.content,
            resp.status_code,
            content_type=resp.headers.get("Content-Type", "text/plain"),
        )
    except requests.exceptions.ConnectionError:
        return jsonify({"error": "connection failed"}), 502
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/page")
@guard
def page():
    """Cache-poisonable."""
    host = request.headers.get("X-Forwarded-Host", request.host)
    return render_template_string(
        "<!DOCTYPE html><html><head><title>Orbit</title>"
        '<script src="http://{{ host }}/sdk.js"></script></head>'
        "<body><h1>Orbit Dashboard</h1></body></html>",
        host=host,
    )


@app.route("/api/admin/exec")
@guard
def admin_exec():
    """Requires admin JWT -- proxies to internal service RCE."""
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    payload = _verify_token(token)
    if not payload or payload.get("role") != "admin":
        return jsonify({"error": "admin required"}), 403
    cmd = request.args.get("cmd", "")
    if not cmd:
        return jsonify({"error": "missing cmd"}), 400
    try:
        resp = requests.get(
            f"http://internal:5002/admin/exec?cmd={cmd}",
            headers={"x-internal-auth": _INTERNAL_SECRET},
            timeout=10,
        )
        return Response(resp.content, resp.status_code, content_type="text/plain")
    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/admin/flag")
@guard
def admin_flag():
    """Requires admin JWT -- proxies to internal flag."""
    auth = request.headers.get("Authorization", "")
    token = auth.removeprefix("Bearer ").strip()
    payload = _verify_token(token)
    if not payload or payload.get("role") != "admin":
        return jsonify({"error": "admin required"}), 403
    try:
        resp = requests.get(
            "http://internal:5002/admin/flag",
            headers={"x-internal-auth": _INTERNAL_SECRET},
            timeout=5,
        )
        return Response(resp.content, resp.status_code, content_type="text/plain")
    except Exception as e:
        return jsonify({"error": str(e)}), 500

# ── Progression tracking ────────────────────────────────────────────────

PROGRESS = {"jwt": False, "ssrf": False, "rce": False, "flag": False}
PROGRESS_TOKEN_HARD = "nexus-complete-all-modes"


@app.route("/progress/complete/<vuln>", methods=["POST"])
def hard_progress_complete(vuln):
    if vuln in PROGRESS:
        PROGRESS[vuln] = True
        return {"status": "ok", "vuln": vuln}
    return {"error": "unknown vuln"}, 400


@app.route("/progress/status")
def hard_progress_status():
    return {**PROGRESS, "all_done": all(PROGRESS.values())}


@app.route("/progress/token")
def hard_progress_token():
    if all(PROGRESS.values()):
        return {"token": PROGRESS_TOKEN_HARD}
    return {"error": "not all completed", "remaining": [
        k for k, v in PROGRESS.items() if not v
    ]}, 400
