"""Vulnerable Flask app — local security practice only.

Endpoints:
  /search?q=    — reflected XSS
  /store        — stored XSS
  /display      — shows stored content
  /run?cmd=     — RCE via subprocess shell=True
  /             — uses X-Forwarded-Host (cache-poisonable)
"""

import subprocess

from flask import Flask, request, Response, render_template_string

app = Flask(__name__)

# In-memory "database" for stored XSS
storage = []


@app.route("/")
def index():
    """Home page. Reads X-Forwarded-Host to build a script src.

    Since Nginx's cache key does NOT include $http_x_forwarded_host,
    an attacker can poison the cache here. Every user who hits the
    cached response will load JS from attacker-hostile origin.
    """
    forwarded_host = request.headers.get("X-Forwarded-Host", request.host)
    return render_template_string(
        """<!DOCTYPE html>
<html>
<head><title>VulnLab</title></head>
<body>
<h1>VulnLab Security Lab</h1>
<p>Welcome. This environment is for authorized testing only.</p>

<!-- NOTE: forwarded host is interpolated into the page to enable cache poisoning -->
<script src="http://{{ host }}/analytics.js"></script>
<p>Loaded analytics from: {{ host }}</p>

<hr>
<h2>Test endpoints</h2>
<ul>
  <li><a href="/search?q=hello">/search?q= — reflected XSS</a></li>
  <li><a href="/store">/store — stored XSS</a></li>
  <li><a href="/run?cmd=id">/run?cmd= — RCE</a></li>
</ul>
</body>
</html>""",
        host=forwarded_host,
    )


@app.route("/search")
def search():
    """Reflected XSS — the `q` param is injected directly into HTML."""
    q = request.args.get("q", "")
    return Response(
        f"""<!DOCTYPE html>
<html>
<head><title>Search — VulnLab</title></head>
<body>
<h1>Search results for: {q}</h1>
<a href="/">Back</a>
</body>
</html>""",
        content_type="text/html",
    )


@app.route("/store", methods=["POST"])
def store():
    """Stored XSS — accepts JSON {"content":"..."} and saves it.

    curl -X POST http://localhost:8080/store \\
      -H 'Content-Type: application/json' \\
      -d '{"content": "<script>alert(1)</script>"}'
    """
    data = request.get_json(force=True)
    content = data.get("content", "")
    storage.append(content)
    return {"stored": True, "id": len(storage) - 1}, 201


@app.route("/display")
def display():
    """Renders all stored items WITHOUT sanitization."""
    items = "".join(f"<li>{item}</li>" for item in storage)
    return Response(
        f"""<!DOCTYPE html>
<html>
<head><title>Stored — VulnLab</title></head>
<body>
<h1>Stored content</h1>
<ul>{items}</ul>
<a href="/">Back</a>
</body>
</html>""",
        content_type="text/html",
    )


@app.route("/run")
def run():
    """RCE — passes `cmd` directly to subprocess with shell=True.

    curl 'http://localhost:8080/run?cmd=id'
    """
    cmd = request.args.get("cmd", "")
    if not cmd:
        return {"error": "missing cmd"}, 400
    try:
        result = subprocess.check_output(
            cmd, shell=True, stderr=subprocess.STDOUT, timeout=5
        )
        return Response(result.decode(), content_type="text/plain")
    except subprocess.TimeoutExpired:
        return {"error": "command timed out"}, 500
    except subprocess.CalledProcessError as e:
        return {"error": e.output.decode()}, 500


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

# ── Progression tracking ────────────────────────────────────────────────

PROGRESS = {"cache": False, "xss": False, "stored": False, "rce": False}
PROGRESS_TOKEN_EASY = "nexus-unlock-easy-mode"


@app.route("/progress/complete/<vuln>", methods=["POST"])
def progress_complete(vuln):
    if vuln in PROGRESS:
        PROGRESS[vuln] = True
        return {"status": "ok", "vuln": vuln}
    return {"error": "unknown vuln"}, 400


@app.route("/progress/status")
def progress_status():
    return {**PROGRESS, "all_done": all(PROGRESS.values())}


@app.route("/progress/token")
def progress_token():
    if all(PROGRESS.values()):
        return {"token": PROGRESS_TOKEN_EASY}
    return {"error": "not all completed", "remaining": [
        k for k, v in PROGRESS.items() if not v
    ]}, 400
