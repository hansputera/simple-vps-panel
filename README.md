# VPS Panel (C edition)

A single-binary VPS management panel written in C, statically linked against musl libc.
It uses about 0.3MB RSS (0.2MB per cgroup) and sits behind Caddy with automatic HTTPS.
Live at `tencent140.vps.hanifu.id`.

## Features

| Tab | What it does |
|---|---|
| Dashboard | Live CPU % and model, memory/swap/disk, load, uptime, fail2ban counters, service health |
| Sites | Add, edit, delete reverse proxies. The panel writes a Caddyfile snippet, runs `caddy validate`, and hot-reloads with zero downtime. Per-site custom Caddy directives plus a standalone Validate button |
| Terminal | Root shell (bash), 60s timeout, 256KB output cap |
| Processes | Top 40 processes by live CPU usage, kill with PID 1/self protection |
| Ports | All LISTEN sockets (tcp/tcp6) mapped to the owning process, with ESTABLISHED connection counts |
| Files | Root file manager: browse, edit (up to 512KB), upload (up to 8MB base64), download (up to 16MB), mkdir, rename/move, recursive delete (refuses `/`) |
| Services | List systemd units, start/stop/restart |

## Source layout

```
/opt/caddy-panel-c/
├── panel.c          # C backend, all API and logic (~1.1k lines)
├── index.html       # UI (vanilla JS + CSS, particles.js background from cdnjs)
├── panel            # compiled binary (musl static)
├── panel.glibc      # fallback glibc build
├── config           # bcrypt hash of the panel password (chmod 600)
├── sites.conf       # site registry: domain|target|auth_user|auth_hash
└── extra/           # per-site custom directives: <domain>.conf
/etc/systemd/system/panel-c.service   # systemd unit (hardened)
/etc/caddy/Caddyfile                  # global options + site imports
/etc/caddy/sites/*.caddy              # per-site snippets (written by the panel)
```

## Build

The production binary is statically linked with musl. It needs `musl-tools`, plus
libmicrohttpd compiled static for musl, and a small `crypt.h` shim with a `crypt_r`
wrapper (musl keeps `crypt_r` internal as `__crypt_r`). The `trim_heap()` macro and
the `mallopt()` calls are no-ops on non-glibc builds, so the same source compiles
cleanly on both.

```bash
musl-gcc -Os -static -I/tmp/musl-crypt -I/opt/mhd-musl/include \
    -ffunction-sections -fdata-sections -Wl,--gc-sections \
    -o panel panel.c wrap.c /opt/mhd-musl/lib/libmicrohttpd.a
strip panel
systemctl restart panel-c
```

Fallback glibc build (dynamic, ~4.6MB RSS):

```bash
gcc -O2 -o panel panel.c -lmicrohttpd -lcrypt -lpthread
```

A prebuilt glibc fallback is kept as `panel.glibc`.

To test without touching the live instance (your real password stays untouched):

```bash
gcc -O2 -o /tmp/ptest/panel-test -DPORT=9090 -DBASE='"/tmp/ptest"' \
    -DCREDS_PATH='"/tmp/ptest/creds.txt"' panel.c -lmicrohttpd -lcrypt -lpthread
```

## API

Auth is a `pan_token` session cookie (12 hours). Every POST must send the
`X-Requested-With: fetch` header.

| Endpoint | Method | Purpose |
|---|---|---|
| /api/login | POST | Login, per-IP rate limit (5 failures per 5 minutes) |
| /api/logout | POST | Destroy the session |
| /api/me | GET | Check auth state |
| /api/password | POST | Change panel password (min 10 chars) |
| /api/status | GET | Memory, swap, disk, load, uptime, CPU, fail2ban, services |
| /api/sites | GET/POST | List sites, add a site (`extra` holds optional directives) |
| /api/sites/update | POST | Change target, extra, or auth of an existing site |
| /api/sites/<domain> | DELETE | Remove a site |
| /api/caddy/validate | POST | Validate a snippet without saving it |
| /api/exec | POST | `{command}` run as root through bash |
| /api/processes | GET | Process list with CPU % |
| /api/kill | POST | SIGKILL a PID |
| /api/ports | GET | Listening ports with owner process and connection counts |
| /api/files?path= | GET | List a directory |
| /api/file/view?path= | GET | Read a text file |
| /api/file/download?path= | GET | Download a file |
| /api/file/save | POST | Write a file |
| /api/file/mkdir | POST | Create a directory |
| /api/file/rename | POST | Rename or move |
| /api/file/delete | POST | Delete a file or directory (recursive) |
| /api/file/upload | POST | `{path, b64}` upload |

## How "Add site" works

1. Input validation (domain regex, `host:port` format, safe characters)
2. Write `/etc/caddy/sites/managed-<domain>.caddy` (reverse_proxy, headers, optional
   basic_auth, then the custom directives)
3. Run `caddy validate --config /etc/caddy/Caddyfile`
4. On failure: automatic rollback, stale files cleaned up, parser error shown
5. On success: `caddy reload` (hot, zero downtime), then save to `sites.conf` and `extra/`

## Security model

- bcrypt password hash (`$2b$10`), 64-hex random session secret
- Login rate limiting is per IP. The real client IP comes from `X-Forwarded-For`,
  trusted only when the request arrives from loopback (Caddy)
- Cookie is `HttpOnly; SameSite=Strict`, plus an `X-Requested-With` check on POSTs
- `NoNewPrivileges=true` and `MemoryMax=64M` on the unit. The filesystem sandbox is
  intentionally loose because Terminal and Files need full root access by design
- The panel password equals root access to the VPS. Pick something strong and unique

## Operations

```bash
systemctl restart panel-c        # restart (also resets login lockouts, state is in-memory)
journalctl -u panel-c -f         # panel logs
journalctl -u caddy -f           # caddy and ACME logs
tail -f /var/log/vps-alerts.log  # resource alerts
```

The panel starts on boot. Sites added through the panel need DNS pointing at the VPS
(a wildcard `*.tencent140.vps.hanifu.id -> 43.173.38.140` is recommended). Caddy issues
the HTTPS certificate automatically once DNS resolves.

## Old Python panel

The Flask version lives in `/opt/caddy-panel/`. It is disabled and safe to remove:

```bash
rm -rf /opt/caddy-panel /etc/systemd/system/caddy-panel.service
```

*Connected and built for [hanifu.id](https://hanifu.id) / [github.com/hansputera](https://github.com/hansputera)*
