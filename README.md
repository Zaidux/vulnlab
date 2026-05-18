# VulnLab 🚩

Deliberately vulnerable web applications for **local security exploration practice**. Three progressive difficulty modes, all running on localhost only.

## Quick Start

```bash
docker compose up --build
```

Open **http://127.0.0.1:7070** in your browser → Nexus launcher shows all modes.

## Modes

| Mode | Port | Architecture | Difficulty |
|------|------|-------------|------------|
| **Easy** | `:8080` | Nginx + Flask (2 containers) | Beginner |
| **Medium** | `:9090` | Nginx + Flask + tripwires + honeypots | Intermediate |
| **Hard** | `:9191` | Gateway + API + Internal (3 containers + SSRF chain) | Advanced |

## Progression

Each mode tracks your exploitation progress. Work through the vulnerabilities, then POST to mark them complete:

```bash
# After manually confirming each vulnerability works:
curl -X POST http://localhost:8080/progress/complete/cache   # Easy
curl -X POST http://localhost:8080/progress/complete/xss     # Easy
curl -X POST http://localhost:8080/progress/complete/stored  # Easy
curl -X POST http://localhost:8080/progress/complete/rce     # Easy

# Check progress
curl http://localhost:8080/progress/status

# Claim your unlock token when all 4 are done
curl http://localhost:8080/progress/token
```

## Safety

**Ports are bound to `127.0.0.1` only.** Nothing is exposed to the network. Each container runs in an isolated Docker network. Do not deploy or expose to any network.

## Structure

```
testing_env/
├── docker-compose.yml     # Unified launcher — runs all modes
├── README.md
├── nexus/                 # Progression tracker UI
│   ├── app.py
│   ├── Dockerfile
│   └── templates/
├── vuln-webapp/           # Easy mode
├── vuln-webapp-medium/    # Medium mode
└── vuln-webapp-hard/      # Hard mode
```
