# fwall — Simple Linux Firewall

A lightweight, UFW-inspired firewall for Linux built with Python and Bash.
Wraps `iptables` with a clean CLI, persistent rules, systemd integration, and audit logging.

---

## Requirements

- Linux (tested on Ubuntu 22.04+, Debian 11+)
- Python 3.10+
- `iptables`, `iptables-save`, `iptables-restore`
- `systemd`
- Root / sudo access

---

## Installation

```bash
git clone https://github.com/youruser/fwall.git
cd fwall
sudo bash installer.sh
```

To uninstall:
```bash
sudo bash installer.sh --uninstall
```

---

## Quick Start

```bash
# 1. Allow SSH so you don't lock yourself out
sudo fwall allow 22

# 2. Allow web traffic
sudo fwall allow 80/tcp
sudo fwall allow 443/tcp

# 3. Set default policy: block everything else incoming
sudo fwall default deny
# (equivalent to: sudo fwall default incoming deny)

# 4. Start the firewall
sudo fwall start

# 5. Enable on boot (survive reboots)
sudo fwall enable
```

---

## Command Reference

### Lifecycle

| Command | Description |
|---|---|
| `sudo fwall start` | Activate firewall, apply all saved rules |
| `sudo fwall stop` | Flush all rules (machine open — for maintenance) |
| `sudo fwall enable` | Enable fwall service to start on boot |
| `sudo fwall disable` | Disable fwall service from starting on boot |
| `sudo fwall status` | Show current rules and iptables state |
| `sudo fwall reset` | Clear all rules and stop firewall |

### Rules

```bash
# Allow by port
sudo fwall allow 22
sudo fwall allow 80/tcp
sudo fwall allow 53/udp

# Deny by port
sudo fwall deny 23
sudo fwall deny 3306/tcp

# Allow/deny by IP or subnet
sudo fwall allow --from 192.168.1.0/24
sudo fwall deny  --from 10.0.0.5

# Allow port from specific IP
sudo fwall allow 22 --from 192.168.1.100

# Allow outgoing
sudo fwall allow 443/tcp --direction out

# Delete a rule by ID (get IDs from status)
sudo fwall delete 3

# Set default policy (incoming, outgoing, or forwarding)
sudo fwall default deny                # incoming (scope omitted = incoming)
sudo fwall default incoming allow
sudo fwall default outgoing deny
sudo fwall default forwarding deny
```

### Logging

```bash
sudo fwall log on
sudo fwall log off
```

---

## File Locations

| Path | Purpose |
|---|---|
| `/usr/local/bin/fwall` | CLI binary (available system-wide) |
| `/usr/local/lib/fwall/engine.sh` | iptables executor (called by fwall.py) |
| `/etc/fwall/fwall.conf` | Configuration file |
| `/etc/fwall/rules.json` | Persisted rules (auto-managed) |
| `/etc/fwall/iptables.rules` | Raw iptables save file |
| `/var/log/fwall.log` | Audit log |
| `/etc/systemd/system/fwall.service` | systemd unit |

---

## Configuration (`/etc/fwall/fwall.conf`)

```ini
[policy]
[policy]
default_incoming   = deny    # deny | allow  (reference only — use `fwall default` to change)
default_outgoing   = allow   # deny | allow
default_forwarding = deny    # deny | allow

[logging]
enabled = true             # true | false
level = info               # debug | info | warn | error
path = /var/log/fwall.log

[engine]
backend = iptables         # iptables (nftables planned)
```

Changes take effect on next `sudo fwall start`.

---

## How It Works

```
fwall <command>
  └─► fwall.py         # parses CLI, manages rules.json, reads config
        └─► engine.sh  # executes raw iptables commands
              └─► iptables / kernel netfilter
```

`fwall.py` handles all logic and state. `engine.sh` is a thin executor — the only file that touches `iptables` directly. This separation makes it easy to swap backends (e.g. nftables) in the future.

---

## Project Structure

```
fwall/
├── fwall.py          # Core: CLI + rule model + state + engine bridge
├── engine.sh         # Bash: raw iptables executor
├── fwall.conf        # Default config (copied to /etc/fwall/ on install)
├── fwall.service     # systemd unit file
├── installer.sh      # System installer / uninstaller
└── README.md
```

---
