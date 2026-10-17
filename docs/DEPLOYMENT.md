# Deployment Guide

This guide takes you from a clean host to a working **Parental Gateway** that
actually routes and filters your family's traffic.

* [1. Choose a topology](#1-choose-a-topology)
* [2. Prerequisites](#2-prerequisites)
* [3. Docker deployment](#3-docker-deployment)
* [4. LXC deployment (Proxmox)](#4-lxc-deployment-proxmox)
* [5. Point your clients at the gateway](#5-point-your-clients-at-the-gateway)
* [6. Verify the setup](#6-verify-the-setup)
* [7. Networking reference](#7-networking-reference)
* [8. Hardening checklist](#8-hardening-checklist)
* [9. Backup, upgrade, removal](#9-backup-upgrade-removal)

---

## 1. Choose a topology

### Option A — Container is the LAN gateway (recommended)

```
        [Internet]
             │
        ┌────┴─────┐
        │  Router   │  (modem/ONT, NAT disabled or in bridge mode)
        └────┬──────┘
             │ WAN interface (eth0)
   ┌─────────┴──────────────────────────┐
   │        Parental Gateway            │  ← this container
   │   IP forwarding + NAT + PCTRL      │
   └─────────┬──────────────────────────┘
             │ LAN interface (eth1 / br0)
        ┌────┴──────────────────────┐
        │   Switch / Access Point    │
        └────┬───────┬───────┬──────┘
          phones   laptops   TVs
```

The container has two roles: it hands out addresses (or your existing DHCP
server points clients at it) and it is the **default gateway** for every
device. Nothing can bypass it.

### Option B — Existing router stays in place, container becomes the client gateway

Keep your router's DHCP, but set the **router option (option 3 / "gateway")**
to the container's IP. The container NATs out to the router. Simple, and it is
the least disruptive option on most home networks.

### Option C — UI only (no enforcement)

Run the container in bridge networking with `GATEWAY_MODE=0` and
`FIREWALL_MODE=off` to evaluate the interface before committing. Rules are
computed and shown, but never applied.

---

## 2. Prerequisites

* A Linux host with Docker **or** an LXC container you can grant capabilities to
* At least one network interface on your LAN
* Your router/firewall able to hand out the container's IP as the default gateway
* ~512 MB RAM, 100 MB disk

---

## 3. Docker deployment

### 3.1 Get the files

The repository is currently **private**, so clone it with credentials (a GitHub
token with the `repo` scope, or `gh auth login`). `curl` on
`raw.githubusercontent.com` returns 404 for private repositories.

**Using the published image** (no build step, multi-arch so it works on a Pi):

```bash
gh repo clone Thorinas112/parental-gateway /opt/parental-gateway
cd /opt/parental-gateway
```

`docker-compose.yml` already points at `ghcr.io/thorinas112/parental-gateway:latest`,
so `docker compose up -d` pulls it. You will also need a Personal Access Token
with `read:packages` for the image:

```bash
docker login ghcr.io -u Thorinas112 --password-stdin
```

**Or building from source:**

```bash
git clone https://<TOKEN>@github.com/Thorinas112/parental-gateway.git /opt/parental-gateway
cd /opt/parental-gateway
```

then use the build override in [3.4](#34-start).

### 3.2 Configure

```bash
cp .env.example .env
nano .env
```

At minimum set:

```bash
ADMIN_PASSWORD=<a long random password>
SECRET_KEY=<32+ random characters>
LAN_IFACE=eth1        # interface facing your clients
WAN_IFACE=eth0        # interface facing the internet
LAN_SUBNET=192.168.1.0/24
TZ=Europe/London
```

### 3.3 Host preparation

```bash
# let the container route (also applied by the entrypoint)
sudo sysctl -w net.ipv4.ip_forward=1
echo 'net.ipv4.ip_forward=1' | sudo tee /etc/sysctl.d/99-parental-gateway.conf

# if you run ufw/firewalld, allow forwarding and the web port
sudo ufw route allow in on eth1 out on eth0
sudo ufw allow from 192.168.1.0/24 to any port 8080 proto tcp
```

If you use **Option A** with a dedicated LAN NIC, give it an address now (or
set `LAN_IP_CIDR=192.168.1.1/24` in `.env` and let the entrypoint do it):

```bash
sudo ip addr replace 192.168.1.1/24 dev eth1
sudo ip link set eth1 up
```

### 3.4 Start

```bash
# running the published image
docker compose up -d

# ...or building from source
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build

docker compose logs -f parental-gateway
```

You should see:

```
[entrypoint] net.ipv4.ip_forward = 1 (via /proc)
[entrypoint] auto-detected LAN_SUBNET=192.168.1.0/24 on eth1
[entrypoint] NAT: MASQUERADE 192.168.1.0/24 -> eth0
pg.db          database ready at /app/data/app.db
pg.auth        created bootstrap user 'admin'
pg.gateway     Gateway bootstrap: {...}
```

### 3.5 First login

Open `http://<host-ip>:8080`, sign in as `admin` with the password from `.env`,
then press **Scan**.

---

## 4. LXC deployment (Proxmox)

Docker inside an LXC works well; you can also run the app directly in the
container. Either way the LXC **must not be unprivileged-only** in a way that
strips `NET_ADMIN`.

### 4.1 Create the container

* Template: Debian 12 / Ubuntu 24.04
* Disk: 4 GB, RAM: 512 MB–1 GB, CPU: 1–2 cores
* Network: attach a **bridged** NIC to your LAN bridge (`vmbr1`)
* Unprivileged: **off** (or keep it on and add the nesting/idmap settings below)

### 4.2 Grant the required capabilities

On the **Proxmox host**, edit `/etc/pve/lxc/<CTID>.conf`:

```
lxc.cap.drop:
lxc.cap.drop: mknod
lxc.mount.entry: /lib/modules lib/modules none bind,optional 0 0
lxc.apparmor.profile: unconfined
```

Then restart the container. Confirm inside it:

```bash
ip link                      # should list your real interfaces
sysctl net.ipv4.ip_forward   # must be writable
```

### 4.3 Install Docker inside the LXC

```bash
apt update && apt install -y curl ca-certificates
curl -fsSL https://get.docker.com | sh
systemctl enable --now docker
```

### 4.4 Deploy

Follow [section 3](#3-docker-deployment) using `docker compose`.

> **Alternative — bare Python in the LXC:** install
> `python3 python3-venv iptables iproute2 libpcap0.8`, create a venv,
> `pip install -r requirements.txt`, then run `entrypoint.sh` via a systemd
> unit. The entrypoint is plain bash and works without Docker.

---

## 5. Point your clients at the gateway

Enforcement happens in the `FORWARD` path — clients must **route through** the
container.

### dnsmasq (common on routers / Pi-hole)

```conf
# /etc/dnsmasq.d/parental-gateway.conf
dhcp-option=option:router,192.168.1.1
dhcp-option=option:dns-server,192.168.1.1
```

### ISC DHCP Server

```
option routers 192.168.1.1;
option domain-name-servers 192.168.1.1;
```

### Kea DHCP

```json
"option-data": [
  { "name": "routers", "data": "192.168.1.1" },
  { "name": "domain-name-servers", "data": "192.168.1.1" }
]
```

### MikroTik / Ubiquiti / OpenWrt

Set the LAN **DHCP Gateway** (option 3) to `192.168.1.1`. In OpenWrt this is
*Network → Interfaces → LAN → DHCP Server → Advanced → DHCP-Options*: `3,192.168.1.1`.

### Static clients

Set the default gateway (and ideally DNS) to `192.168.1.1` manually.

> **Tip:** renew the lease on each device afterwards (`ipconfig /renew`,
> `dhclient -r && dhclient`, or toggle Wi-Fi) so the new gateway is picked up.

If you want the container to also answer DNS, run dnsmasq or unbound on it and
point clients at it — or keep DNS on the router and just route through the
container.

---

## 6. Verify the setup

From a client device:

```bash
# 1. default route points at the container
ip route | grep default
#   default via 192.168.1.1 ...

# 2. it is forwarding
ping -c3 1.1.1.1

# 3. it is NATing (from the container)
docker exec parental-gateway iptables -t nat -S POSTROUTING
#   -A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE
```

Then in the UI:

1. **Scan** — the client should appear with its MAC.
2. Rename it, add it to a group.
3. Toggle **Block all** on that group.
4. Within a few seconds the client should lose internet:
   ```bash
   docker exec parental-gateway iptables -S PCTRL
   -N PCTRL
   -A PCTRL -m mac --mac-source AA:BB:CC:DD:EE:01 -j DROP
   -A PCTRL -j RETURN
   ```
5. Press **Apply** or wait for the auto-reconcile if it did not take effect.

---

## 7. Networking reference

### What the entrypoint sets up

```bash
# forwarding
sysctl -w net.ipv4.ip_forward=1

# NAT: masquerade LAN traffic out of the WAN interface
iptables -t nat -A POSTROUTING -s 192.168.1.0/24 -o eth0 -j MASQUERADE

# allow return traffic
iptables -I FORWARD 1 -m state --state ESTABLISHED,RELATED -j ACCEPT

# allow LAN -> WAN
iptables -A FORWARD -i eth1 -o eth0 -j ACCEPT
```

### What the application manages

A single chain, jumped to from the top of `FORWARD`:

```
-N PCTRL
-A FORWARD -j PCTRL
-A PCTRL -m mac --mac-source AA:BB:CC:DD:EE:01 -j DROP   ← blocked device
-A PCTRL -j RETURN
```

Because `PCTRL` is inserted at **position 1**, it always sees the packet first.
Removing a device from the UI removes its rule on the next reconcile.

### Multi-NIC with macvlan (optional)

If you want the container to have its own IP on the LAN rather than using the
host's:

```yaml
# docker-compose override
services:
  parental-gateway:
    networks:
      lan_net:
        ipv4_address: 192.168.1.1

networks:
  lan_net:
    driver: macvlan
    driver_opts:
      parent: eth1
    ipam:
      config:
        - subnet: 192.168.1.0/24
          gateway: 192.168.1.254
```

Remove `network_mode: host` when you do this, and keep
`cap_add: [NET_ADMIN, NET_RAW]`.

---

## 8. Hardening checklist

- [ ] `ADMIN_PASSWORD` changed from the default
- [ ] `SECRET_KEY` set to a long random value (keeps sessions across rebuilds)
- [ ] `SESSION_COOKIE_SECURE=1` if you front the UI with TLS (Caddy/nginx)
- [ ] Web UI bound to the LAN only, or firewall the port to your subnet
- [ ] `./data` volume backed up and not world-readable
- [ ] Host `unattended-upgrades` (or equivalent) enabled
- [ ] Family members told the network is filtered

### Putting TLS in front (Caddy example)

```
gateway.home.lan {
    reverse_proxy 127.0.0.1:8080
}
```

Then set `SESSION_COOKIE_SECURE=1` and `WEB_PORT=8080`, and browse to
`https://gateway.home.lan`.

---

## 9. Backup, upgrade, removal

```bash
# backup: the entire state lives in one directory
tar czf parental-gateway-$(date +%F).tar.gz ./data .env

# upgrade (published image)
docker compose pull
docker compose up -d
docker compose logs -f

# upgrade (built from source)
docker compose -f docker-compose.yml -f docker-compose.build.yml up -d --build

# stop & remove (data in ./data is preserved)
docker compose down

# full removal
docker compose down -v && rm -rf ./data
```

The SQLite database (`data/app.db`) holds devices, names, groups, schedules and
sessions. The generated signing key lives in `data/secret.key`.

---

## Appendix: `scripts/setup-gateway.sh`

A convenience script for the **host** that enables forwarding, optionally
assigns the LAN address and prints the exact `iptables` lines for your subnet:

```bash
sudo ./scripts/setup-gateway.sh --lan eth1 --wan eth0 --subnet 192.168.1.0/24
```

It only writes kernel sysctls and prints commands — it never modifies the
application's managed chain.
