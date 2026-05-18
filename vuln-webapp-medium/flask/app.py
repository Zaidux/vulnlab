"""DevBlog — Deliberately vulnerable. Medium difficulty.
Tripwires, honeypots, and 3 hidden vulnerabilities.
"""

import os
import re
import subprocess
import time
from functools import wraps

from flask import Flask, request, Response, render_template_string

app = Flask(__name__)

_SECRET_FLAG = "flag{cache_poisoning_reflected_xss_stored_xss_command_injection}"
BAN_SECONDS = 240  # 4 minutes
_banned = {}  # real_ip -> expiry

# Tripwire: paths that trigger instant 4-min ban
_HONEYPOT_PATHS = {
    "/admin", "/debug", "/shell", "/exec", "/cmd",
    "/wp-admin", "/wp-login", "/.env", "/config",
    "/backup", "/db", "/sql", "/phpmyadmin", "/manager",
    "/console", "/vuln", "/test", "/shell.php",
    "/config.php", "/.git", "/.git/config",
    "/server-status", "/actuator", "/swagger",
    "/api/admin", "/api/debug", "/api/secret",
    "/setup", "/install", "/phpinfo",
}

_TRIP_PATTERNS = {
    re.compile(r"<\s*script", re.I): "<script> tag detected",
    re.compile(r"alert\s*\(", re.I): "suspicious function call",
    re.compile(r"confirm\s*\(", re.I): "suspicious function call",
    re.compile(r"prompt\s*\(", re.I): "suspicious function call",
    re.compile(r"document\.cookie", re.I): "suspicious property access",
    re.compile(r"\b1\s*=\s*1\b"): "boolean tautology detected",
}


def _get_real_ip():
    forwarded = request.headers.get("X-Forwarded-For", "")
    if forwarded:
        return forwarded.split(",")[0].strip()
    return request.remote_addr or "unknown"


def _is_banned(ip):
    ex = _banned.get(ip, 0)
    if time.time() < ex:
        return True
    if ex:
        del _banned[ip]
    return False


def _do_ban(ip, reason=""):
    _banned[ip] = time.time() + BAN_SECONDS


def _check_tripwires(ip):
    """Scan request args/form for tripwire patterns."""
    for vals in request.args.values():
        for v in vals if isinstance(vals, list) else [vals]:
            for pat, label in _TRIP_PATTERNS.items():
                if pat.search(v):
                    _do_ban(ip, label)
                    return True
    if request.method == "POST":
        data = request.get_json(silent=True) or {}
        for v in data.values() if isinstance(data, dict) else []:
            if isinstance(v, str):
                for pat, label in _TRIP_PATTERNS.items():
                    if pat.search(v):
                        _do_ban(ip, label)
                        return True
    return False


def tripwire_guard(f):
    """Applied to ALL routes. Blocks banned IPs and scans for triggers."""
    @wraps(f)
    def wrapper(*a, **kw):
        ip = _get_real_ip()
        if _is_banned(ip):
            remaining = int(_banned[ip] - time.time())
            return Response(
                f"Rate limit active. Try again in {remaining} seconds.",
                429,
            )
        if _check_tripwires(ip):
            return Response(
                "Request blocked. Rate limit active. Try again later.",
                429,
            )
        return f(*a, **kw)
    return wrapper


# Before-request: check honeypot paths
@app.before_request
def _honeypot_path_check():
    ip = _get_real_ip()
    if _is_banned(ip):
        return None
    path = request.path.lower().rstrip("/")
    for hp in _HONEYPOT_PATHS:
        hp_norm = hp.lower().rstrip("/")
        if path == hp_norm or path.startswith(hp_norm + "/"):
            _do_ban(ip, "restricted path")
            remaining = int(_banned[ip] - time.time())
            return Response(
                f"Rate limit active. Try again in {remaining} seconds.",
                429,
            )
    return None


# In-memory data
POSTS = [
    {"id": 1, "title": "Getting Started with Python", "slug": "python-intro",
     "body": "<p>Python is a versatile language for beginners and experts alike.</p>"},
    {"id": 2, "title": "Understanding HTTP Caching", "slug": "http-caching",
     "body": "<p>HTTP caching can dramatically improve web performance.</p>"},
    {"id": 3, "title": "Building REST APIs with Flask", "slug": "flask-apis",
     "body": "<p>Flask makes it easy to build lightweight RESTful services.</p>"},
]
FEEDBACK = []


# ------------------------- Routes -------------------------

@app.route("/")
@tripwire_guard
def index():
    """Home page — cache-poisonable via X-Forwarded-Host.
    Uses pure Jinja2 (no f-string conflict) so {{ host }} evaluates.
    """
    forwarded_host = request.headers.get("X-Forwarded-Host", request.host)
    post_list = "".join(
        f'<li><a href="/post/{p["slug"]}/">{p["title"]}</a></li>'
        for p in POSTS
    )
    return render_template_string(
        """<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<title>DevBlog</title>
<script src="http://{{ host }}/track.js"></script>
<style>
*{box-sizing:border-box;margin:0;padding:0}
body{font-family:system-ui,sans-serif;background:#f0f2f5;color:#1a1a1a;padding:2em}
.wrap{max-width:800px;margin:0 auto}
.header{border-bottom:2px solid #e5e7eb;padding-bottom:1em;margin-bottom:2em}
.header h1{color:#1a56db;font-size:2em}
.header a{color:#6b7280;text-decoration:none;margin-right:1.5em;font-size:.95em}
.posts{background:#fff;border-radius:10px;10px;padding:2em;box-shadow:0 1px 4px rgba(0,0,0,.08)}
.posts h2{margin-bottom:1em;font-size:1.3em;color:#374151}
.posts ul{list-style:none}
.posts li{padding:.6em 0;border-bottom:1px solid #f3f4f6}
.posts li:last-child{border:none}
.posts a{color:#1a56db;text-decoration:none;font-size:1.1em}
.posts a:hover{text-decoration:underline}
.search{margin:2em 0 0}
.search input{padding:.5em .8em;border:1px solid #d1d5db;border-radius:6px;width:240px}
.search button{padding:.5em 1em;background:#1a56db;color:#fff;border:none;border-radius:6px;cursor:pointer}
.footer{margin-top:3em;color:#9ca3af;font-size:.85em;text-align:center}
</style>
</head>
<body>
<div class="wrap">
<div class="header">
<h1>DevBlog</h1>
<div>
<a href="/">Home</a>
<a href="/about">About</a>
<a href="/contact">Contact</a>
</div>
</div>
<div class="posts">
<h2>Latest Posts</h2>
<ul>{{ posts|safe }}</ul>
</div>
<form class="search" action="/search" method="get">
<input type="text" name="q" placeholder="Search posts..." aria-label="Search">
<button type="submit">Search</button>
</form>
<div class="footer">DevBlog &mdash; Built with &hearts;</div>
</div>
</body>
</html>""",
        host=forwarded_host,
        posts=post_list,
    )


@app.route("/about")
@tripwire_guard
def about():
    return Response(
        """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>About — DevBlog</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:2em auto;color:#333;line-height:1.6}</style>
</head>
<body><h1>About DevBlog</h1>
<p>DevBlog is a community platform for developers to share knowledge about
web technologies, backend engineering, and security.</p>
<p><a href="/">\u2190 Back to Home</a></p></body></html>""",
        200, content_type="text/html",
    )


@app.route("/contact")
@tripwire_guard
def contact():
    return Response(
        """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Contact — DevBlog</title>
<style>body{font-family:system-ui,sans-serif;max-width:640px;margin:2em auto;color:#333}</style>
</head>
<body><h1>Contact Us</h1>
<p>Have feedback? We'd love to hear from you.</p>
<form action="/feedback" method="post">
<p><textarea name="content" rows="5" cols="50" placeholder="Your feedback..." required></textarea></p>
<p><button type="submit">Send Feedback</button></p>
</form>
<p><a href="/">\u2190 Back to Home</a></p></body></html>""",
        200, content_type="text/html",
    )


@app.route("/post/<slug>/")
@tripwire_guard
def post_detail(slug):
    post = next((p for p in POSTS if p["slug"] == slug), None)
    if post is None:
        return Response("Not found", 404)
    return render_template_string(
        """<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>{{ title }} — DevBlog</title>
<style>body{font-family:system-ui,sans-serif;max-width:720px;margin:2em auto;color:#333;line-height:1.7}
h1{color:#1a56db}.meta{color:#9ca3af;font-size:.9em}a{color:#1a56db}</style>
</head>
<body>
<h1>{{ title }}</h1>
<div class="meta">Published on DevBlog</div>
<div>{{ body|safe }}</div>
<p><a href="/">\u2190 Back to Home</a></p>
</body>
</html>""",
        title=post["title"],
        body=post["body"],
    )


@app.route("/search")
@tripwire_guard
def search():
    """Reflected XSS — reflects `q` directly into HTML.
    Tripwires block: <script>, alert(), confirm(), prompt(), document.cookie
    Allowed vectors: <img src=x onerror=...>, <svg/onload=...>,
                     <body onload=...>, <style>@import...</style>, etc.
    """
    q = request.args.get("q", "")
    results = f"<li>No results for: {q}</li>"
    # Use f-string + Response — no Jinja2 involved here
    return Response(
        f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Search — DevBlog</title>
<style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:2em auto;color:#333}}</style>
</head>
<body>
<h1>Search Results</h1>
<ul>{results}</ul>
<p><a href="/">\u2190 Back to Home</a></a></p>
</body>
</html>""",
        200,
        content_type="text/html",
    )


@app.route("/feedback", methods=["POST"])
@tripwire_guard
def submit_feedback():
    """Stored XSS — saves content, renders on /review-feedback.
    Tripwires block <script> but onerror/onload/onfocus etc. work.
    """
    content = request.form.get("content", "")
    if not content:
        content = "empty"
    FEEDBACK.append(content)
    return Response(
        f"Thank you. Your feedback (#{len(FEEDBACK)}) has been received.",
        201,
    )


@app.route("/review-feedback")
@tripwire_guard
def review_feedback():
    """Displays all stored feedback — unsanitized."""
    items = "".join(
        f'<li style="padding:.5em 0;border-bottom:1px solid #eee">{i}</li>'
        for i in FEEDBACK
    )
    return Response(
        f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="utf-8"><title>Feedback Queue — DevBlog</title>
<style>body{{font-family:system-ui,sans-serif;max-width:640px;margin:2em auto;color:#333}}
h1{{color:#1a56db}}ul{{list-style:none;padding:0}}</style>
</head>
<body>
<h1>Feedback Queue</h1>
<p>Showing {len(FEEDBACK)} submission(s):</p>
<ul>{items}</ul>
<p><a href="/">\u2190 Back to Home</a></p>
</body>
</html>""",
        200,
        content_type="text/html",
    )


@app.route("/tools/export")
@tripwire_guard
def export():
    """Command injection — hidden in the `format` parameter.

    /tools/export?format=pdf&id=1           # normal use
    /tools/export?format=pdf;id             # RCE
    /tools/export?format=pdf|id             # RCE
    /tools/export?format=pdf`id`            # RCE via backticks
    """
    fmt = request.args.get("format", "pdf")
    post_id = request.args.get("id", "1")
    # Shell=True with user-controlled format — RCE
    cmd = f"echo 'Converted post {post_id} to format: {fmt}'"
    try:
        result = subprocess.check_output(cmd, shell=True, timeout=5, stderr=subprocess.STDOUT)
        return Response(result.decode().strip(), content_type="text/plain")
    except subprocess.CalledProcessError as e:
        return Response(f"Error: {e.output.decode()}", 500)
    except subprocess.TimeoutExpired:
        return Response("Timeout", 500)


@app.route("/hide-flag")
@tripwire_guard
def hidden_flag():
    return Response(_SECRET_FLAG)


if __name__ == "__main__":
    app.run(host="0.0.0.0", port=5000, debug=True)

# ── Progression tracking ────────────────────────────────────────────────

PROGRESS = {"cache": False, "xss": False, "stored": False, "rce": False}
PROGRESS_TOKEN_MEDIUM = "nexus-unlock-medium-mode"


@app.route("/progress/complete/<vuln>", methods=["POST"])
def medium_progress_complete(vuln):
    if vuln in PROGRESS:
        PROGRESS[vuln] = True
        return {"status": "ok", "vuln": vuln}
    return {"error": "unknown vuln"}, 400


@app.route("/progress/status")
def medium_progress_status():
    return {**PROGRESS, "all_done": all(PROGRESS.values())}


@app.route("/progress/token")
def medium_progress_token():
    if all(PROGRESS.values()):
        return {"token": PROGRESS_TOKEN_MEDIUM}
    return {"error": "not all completed", "remaining": [
        k for k, v in PROGRESS.items()	if not v
    ]}, 400
