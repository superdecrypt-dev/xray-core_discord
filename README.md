# xray-core_discord

Setup-only installer untuk **Xray-core + Nginx (nginx.org official repo) + acme.sh** dengan reverse proxy **port 80 & 443** (1 server block).  
Menu manajemen user akan menyusul (belum termasuk di repo ini).

---

## Fitur ✨

### OS & Virtualisasi
- OS support:
  - **Ubuntu >= 20.04**
  - **Debian >= 11**
- Virtualisasi: **KVM/QEMU-KVM only**

### Nginx (nginx.org mainline)
- Install dari **repo resmi nginx.org (mainline)** (bukan default distro)
- 1 server block untuk **port 80 & 443**
- Redirect **80 → 443**
- `map $http_upgrade $connection_upgrade` untuk WS/HTTPUpgrade
- Header proxy untuk WS & HTTPUpgrade:
  - `X-Real-IP`, `X-Forwarded-For`, `X-Forwarded-Proto`
- Timeout koneksi panjang:
  - WS/HUP: `proxy_read_timeout 1d`, `proxy_send_timeout 1d`
  - gRPC: `grpc_read_timeout 1d`, `grpc_send_timeout 1d`

### TLS (acme.sh)
- Sertifikat via **acme.sh**
- Output cert:
  - `/opt/cert/fullchain.pem`
  - `/opt/cert/privkey.pem`
- Metode issue cert:
  - **Input domain sendiri** → `standalone` (nginx stop sementara)
  - **Domain disediakan (Cloudflare)** → `wildcard dns_cf` (nginx stop sementara)

### Domain (menu domain_menu_v2)
Menu input domain:
1. Input domain sendiri
2. Gunakan domain yang disediakan (Cloudflare)

Jika pilih domain disediakan:
- List **domain induk** dari Cloudflare Zone API
- Pilih metode subdomain:
  1. Generate acak (huruf kecil + angka, max 5)
  2. Input sendiri (hanya `a-z`, `0-9`, `.`, `-`)
- Validasi DNS A record:
  - Jika FQDN sudah ada dan IP sama → konfirmasi lanjut (y/n)
  - Jika FQDN sudah ada tapi IP beda → stop (minta ganti subdomain)
  - Jika ada A record lain dengan IP sama → dihapus (sesuai desain script)

### Xray-core
- Generator inbound:
  - **VLESS**, **VMess**, **Trojan**
- Transport:
  - **WebSocket**, **HTTPUpgrade**, **gRPC**
- Internal port & internal path/serviceName: **random**
- Public path Nginx (fixed):
  - `/vless-ws`, `/vmess-ws`, `/trojan-ws`
  - `/vless-hup`, `/vmess-hup`, `/trojan-hup`
  - `/vless-grpc`, `/vmess-grpc`, `/trojan-grpc`
- Log level: **info**
- Sniffing enabled (`destOverride`): `http`, `tls`, `quic`
- Include section: `log`, `dns`, `api`, `policy`, `routing`, `stats`
- Fix permission config/log setelah write config:
  - `/usr/local/etc/xray/config.json`
  - `/var/log/xray/*`

### WARP (wgcf + wireproxy)
- Install `wgcf` dan `wireproxy`
- Setup:
  - `wgcf register` + `wgcf generate`
  - Copy `wgcf-profile.conf` → `wireproxy config.conf` dan tambah:
    - `[Socks] BindAddress = 127.0.0.1:40000`
  - Hapus `wgcf-profile.conf` dan `wgcf-account.toml`
- Systemd service untuk wireproxy
- Xray outbound:
  - SOCKS `127.0.0.1:40000` tag `warp`

### Routing & security
- Outbound `blocked` (blackhole)
- Block:
  - `geosite:private` → `blocked`
  - `protocol: bittorrent` → `blocked`
- Direct routing (penanda):
  - `geosite:apple, meta, google, openai, spotify, netflix, reddit` → `direct`
  - `inboundTag: dummy-inbounds` → `direct`
  - `user: dummy-user` → `direct`
- Rule direct all ports:
  - `port 1-65535` → `direct`

### Hardening & system tuning
- fail2ban mode **aggressive**:
  - `sshd`, `nginx-botsearch`, `nginx-http-auth`, `recidive`
- TCP BBR
- Auto swap 2GB
- Tuning ulimit
- Auto time sync (chrony)

### Logs & maintenance
- **logrotate** untuk log nginx & xray:
  - daily, rotate 7, compress, copytruncate
- Update geodata Xray otomatis tiap 24 jam:
  - Script: `/usr/local/bin/xray-update-geodata`
  - Cron: `/etc/cron.d/xray-update-geodata`

---

## File yang dibuat 📁
- Xray config:
  - `/usr/local/etc/xray/config.json`
- Nginx conf:
  - `/etc/nginx/conf.d/xray.conf`
- Sertifikat:
  - `/opt/cert/fullchain.pem`
  - `/opt/cert/privkey.pem`
- Output info client:
  - `/root/xray-client-info.txt`
- Logrotate:
  - `/etc/logrotate.d/xray-nginx`
- Cron geodata:
  - `/etc/cron.d/xray-update-geodata`

---

## Cara pakai 🚀

### Jalankan dari repo (disarankan untuk private)
```bash
chmod +x setup.sh
sudo ./setup.sh