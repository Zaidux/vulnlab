# Orbit — Hard Mode

**Port:** `127.0.0.1:9191`

Multi-service architecture with an API gateway, an external API service, and an internal service. Contains tripwires — hit one and wait 4 minutes.

No map, no hints, no documentation. Good luck.

## Architecture

```
Browser → Gateway (:9191) → API (:5001) → Internal (:5002)
                                  ↑            ↑
                              public net    docker net only
```

The internal service is **not** reachable from the gateway directly.

## Finding the flag

The flag is a string stored inside the internal service. Find a way to reach it.

## Tips

- Crawl the surface. Don't brute-force paths — honeypots are everywhere.
- Some endpoints require auth. If something feels locked, there might be a way around it.
- Something on the external API can reach the internal service. Find it.
- Not everything is a vulnerability. Some things are decoys.
