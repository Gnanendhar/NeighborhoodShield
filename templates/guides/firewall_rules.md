# firewall_rules.csv — router and firewall rules

**Why:** finds remote desktop or file sharing open to the internet, "allow everything" rules, and guest Wi-Fi that can reach business devices (CIS v8.1 4.2, 4.4, 4.5, 6.4).

| Column | Allowed values | Notes |
|---|---|---|
| rule_id | any | |
| enabled | `Y` `N` | |
| action | `allow` `deny` | |
| direction | `inbound` `outbound` | inbound = from the internet in |
| source | `any` `lan` `guest` `wan` or an address range | IP addresses are shortened to the network on upload |
| destination | same as source | |
| service_or_port | port number(s), name, or `any` | e.g. `3389`, `rdp`, `80,443` |
| comment | text | Empty = "unexplained rule" finding |

## How to export

**Most home/ISP routers** have no export. Open the *Port Forwarding* / *Virtual Server* page and copy each line into this template (one row per forward: `inbound, wan, <device>, <port>`). If the page is empty, upload a file with just the default rule — that is a good result.

**pfSense** — *Diagnostics → Backup & Restore → Download configuration as XML*. A converter is planned (stretch goal); until then copy the rules under *Firewall → Rules*. Docs: https://docs.netgate.com/pfsense/en/latest/backup/

**OPNsense** — *System → Configuration → Backups → Download*. Same as pfSense.

**WatchGuard Firebox** — *Firewall → Firewall Policies*; export via WatchGuard System Manager *Policy Manager → File → Save as* (XML) or copy by hand.

Never upload the configuration file itself to anyone you do not trust: it can contain password hashes and VPN keys.
