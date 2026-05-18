# VulnLab — Medium Mode

**Port:** `127.0.0.1:9090`

No map given. Explore carefully.

## Rules

- Tripwires exist. Hit one → wait **4 minutes** before the app responds to your IP again.
- The app resets when you `docker compose down`.
- You have **no guide** to the endpoints or vulnerabilities.
- Win condition == find and exploit all three vulnerabilities (plus any bonus ones you uncover).

## Known vulnerabilities (from Easy Mode, now hidden or hardened)

| Vuln | Easy Mode | Medium Mode |
|------|-----------|-------------|
| Cache poisoning | `/` with `X-Forwarded-Host` | Same Nginx config — still there. Find the right page. |
| Reflected XSS | `/search?q=` | Same endpoint — but `<script>` is **tripwired**. Use other vectors. |
| Stored XSS | `/store` + `/display` | Moved. Different endpoint name. No `<script>` allowed. |
| RCE | `/run?cmd=` | Moved and disguised. Was **NOT** the only trip-wired path — don't guess blindly. |

## Tip

Not every path you try will ban you. Some will just 404. Tripwires trigger on specific known-vulnerable paths. A good walk finds the right endpoints before the wires do.