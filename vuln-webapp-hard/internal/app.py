"""Orbit Internal Service — internal only, port 5002.
Not proxied through the gateway. Only reachable via:
  1. SSRF from the API service (/api/avatar)
  2. API proxy endpoints (/api/admin/*)

Trusts X-Internal-Auth header for authorization.
"""

import os
import re
import subprocess
import time
from functools import wraps

from flask import Flask, request, Response

app = Flask(__name__)

FLAG = "flag{ssrf_jwt_none_internal_rce}"

# Internal auth header name
_INTERNAL_AUTH = "X-Internal-Auth"
_INTERNAL_SECRET = "trusted"


def require_internal(f):
    """Only accept requests with the correct internal auth header."""
    @wraps(f)
    def wrapper(*a, **kw):
        val = request.headers.get(_INTERNAL_AUTH, "")
        val = request.headers.get("x-internal-auth", "")
        if val != _INTERNAL_SECRET:
            return Response("{\"error\":\"forbidden\"}", 403, content_type="application/json")
        return f(*a, **kw)
    return wrapper


# ── Endpoints ──────────────────────────────────────────────────────────

@app.route("/admin/health")
def health():
    """Health check — intentionally open (no auth),
    so SSRF discovery can find this service.
    """
    return Response(
        "{\"service\":\"orbit-internal\",\"status\":\"running\"}",
        200, content_type="application/json",
    )


@app.route("/admin/flag")
@require_internal
def flag():
    """Returns the flag — requires X-Internal-Auth header."""
    return Response(FLAG, 200, content_type="text/plain")


@app.route("/admin/exec")
@require_internal
def exec_cmd():
    """RCE — passes `cmd` directly to subprocess shell=True.

    Only reachable with the correct internal auth header.
    """
    cmd = request.args.get("cmd", "")
    if not cmd:
        return Response("{\"error\":\"missing cmd\"}", 400, content_type="application/json")
    try:
        result = subprocess.check_output(
            cmd, shell=True, timeout=10, stderr=subprocess.STDOUT
        )
        return Response(result.decode(), 200, content_type="text/plain")
    except subprocess.TimeoutExpired:
        return Response("timeout", 500)
    except subprocess.CalledProcessError as e:
        return Response(e.output.decode(), 500, content_type="text/plain")


@app.route("/admin/ping")
@require_internal
def ping():
    """Command injection — `host` param is interpolated into a shell command."""
    host = request.args.get("host", "")
    if not host:
        return Response("{\"error\":\"missing host\"}", 400, content_type="application/json")
    try:
        result = subprocess.check_output(
            f"ping -c 1 {host} 2>&1 || true",
            shell=True, timeout=10, stderr=subprocess.STDOUT,
        )
        return Response(result.decode(), 200, content_type="text/plain")
    except subprocess.TimeoutExpired:
        return Response("timeout", 500)
    except subprocess.CalledProcessError as e:
        return Response(e.output.decode(), 500, content_type="text/plain")


@app.route("/admin/env")
@require_internal
def env():
    """Exposes environment variables."""
    import json
    safe = {k: v for k, v in os.environ.items()
            if not k.startswith("SECRET")}
    return Response(json.dumps(safe, indent=2), 200, content_type="application/json")


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5002, debug=True)
