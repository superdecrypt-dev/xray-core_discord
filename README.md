# Xray Core Discord - Auto Setup + Menu Operasional Harian

Automasi instalasi dan operasional VPS untuk Xray-core dengan pendekatan:
- `setup.sh` untuk provisioning awal (sekali jalan)
- `manage.sh` untuk operasional harian berbasis menu interaktif

Fokus project ini: operasional cepat untuk admin, bukan sekadar template config statis.

## Quick Install
Jalankan sebagai `root`:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/superdecrypt-dev/xray-core_discord/main/run.sh)
```

`run.sh` akan:
1. Clone repo
2. Install command `manage` ke `/usr/local/bin/manage`
3. Menjalankan `setup.sh`

## Struktur File
| File | Peran |
|---|---|
| `setup.sh` | One-time setup dari nol sampai service aktif |
| `manage.sh` | Menu operasional harian (runtime changes) |
| `install-discord-bot.sh` | Kerangka installer BOT Discord (placeholder) |
| `run.sh` | Bootstrap installer cepat |

## Highlight Fitur Menu (`manage.sh`)
Menu utama saat ini:

```text
Main Menu
  1) Status & Diagnostics
  2) User Management
  3) Quota & Access Control
  4) Network Controls
  5) Domain Control
  6) Speedtest
  7) Security
  8) Maintenance
  9) Install BOT Discord
  0) Exit
```

Selain daftar menu, bagian atas Main Menu menampilkan header realtime:
- `SYSTEM OS`, `RAM`, `UPTIME`
- `IP VPS`, `ISP`, `COUNTRY`
- `DOMAIN`, `TLS EXPIRED`, `WARP STATUS`
- Ringkasan horizontal jumlah akun: `VLESS | VMESS | TROJAN`

## Fitur Per Menu

### 1) Status & Diagnostics
Untuk health check cepat server:
- Status service inti (`xray`, `nginx`)
- Status daemon (`xray-expired`, `xray-quota`, `xray-limit-ip`)
- Validasi file penting, JSON config, listener, TLS expiry
- Ringkasan “siap pakai / ada warning”

### 2) User Management
Operasi akun harian:
- Add user (`vless` / `vmess` / `trojan`)
- Delete user
- Extend/Set expiry
- List users

Input Add User:
- Username
- Masa aktif (hari)
- Quota (GB)
- IP limit `on/off` + nilai limit
- Speed limit `on/off` + speed download/upload

### 3) Quota & Access Control
Menu kontrol detail per akun (fitur paling operasional):

```text
1) View JSON
2) Set Quota Limit (GB)
3) Reset Quota Used (set 0)
4) Manual Block/Unblock (toggle)
5) IP Limit Enable/Disable (toggle)
6) Set IP Limit (angka)
7) Unlock IP Lock
8) Set Speed Download (Mbps)
9) Set Speed Upload (Mbps)
10) Speed Limit Enable/Disable (toggle)
0) Back
```

Status detail akun menampilkan:
- Quota Limit / Quota Used / Expired
- IP Limit ON/OFF + nilai max
- Lock reason (`manual`, `quota`, `ip_limit`)
- Speed download/upload + status speed limit

### 4) Network Controls
Pusat kontrol routing dan jaringan:
- Egress mode: `direct`, `warp`, `balancer`
- Balancer strategy + selector + observatory tuning
- Adblock custom geosite:
  - Rule entry: `ext:custom.dat:adblock`
  - Opsi mode: `blocked`, `direct`, `warp`, `balancer (direct+warp)`, `disable`
  - Balancer adblock memakai tag khusus `adblock-balance` (terisolasi dari balancer global `egress-balance`)
- WARP controls:
  - Global
  - Per-user
  - Per-protocol inbound
  - Per-domain/geosite
  - **WARP Tier (Free/Plus)** dengan status:
    - `Target Tier` (tujuan tersimpan)
    - `Live Tier` (hasil realtime)
- DNS settings + DNS advanced editor
- Diagnostics routing/conf.d/service status

### 5) Domain Control
Fitur domain yang setara dengan flow setup:
- Set domain + issue certificate (flow penuh)
- Show current domain + status cert/key

### 6) Speedtest
- Run speedtest (Ookla)
- Show speedtest version

### 7) Security
- TLS & Certificate:
  - Show cert info
  - Check expiry
  - Renew cert
  - Reload nginx
- Fail2ban protection:
  - Show jail status
  - Show banned IP
  - Unban IP
  - Restart fail2ban
- System hardening status (BBR, swap, ulimit, chrony)
- Security overview ringkas

### 8) Maintenance
Operasi service tanpa keluar menu:
- Restart `xray`, `nginx`, atau keduanya
- Tail log `xray` / `nginx`
- Wireproxy status (mode ringkas) + restart
- Daemon status & restart (`xray-expired`, `xray-quota`, `xray-limit-ip`, `xray-speed`)
- Log daemon sekarang **on-demand** agar layar tidak penuh

### 9) Install BOT Discord
- Menu kerangka untuk fitur install bot Discord
- Script `install-discord-bot.sh` saat ini masih placeholder (belum diimplementasikan)

## Ringkasan Fitur `setup.sh` (One-Time)
`setup.sh` menangani provisioning awal end-to-end:
1. Install dependency OS
2. Install Nginx dari repo resmi `nginx.org`
3. Install Xray-core + geodata updater + custom geosite adblock (`custom.dat`)
4. Generate modular config di `/usr/local/etc/xray/conf.d/`
5. Issue TLS dengan acme.sh (standalone atau `dns_cf_wildcard`)
6. Install WARP stack (`wgcf` + `wireproxy`)
7. Install runtime daemon:
   - `xray-expired`
   - `xray-quota`
   - `xray-limit-ip`
   - `xray-speed`
8. Install hardening baseline (fail2ban, sysctl/BBR, swap, ulimit, logrotate)
9. Install speedtest via snap

Catatan custom geosite adblock:
- Sumber file: `https://github.com/superdecrypt-dev/custom-geosite-xray/raw/main/custom.dat`
- Lokasi install: `/usr/local/share/xray/custom.dat`
- Routing tidak dipaksa dari `setup.sh`; pengaturan mode dilakukan dari menu `manage.sh` -> `4) Network Controls` -> `6) Adblock (Custom Geosite)`

## Daemon Runtime
Service yang menopang automasi operasional:
- `xray-expired`: hapus user expired dari inbounds/routing
- `xray-quota`: lock user ketika quota habis
- `xray-limit-ip`: lock user saat IP aktif melebihi limit
- `xray-speed`: apply limit speed per user (tc + nft)

Cek cepat:

```bash
systemctl status xray xray-expired xray-quota xray-limit-ip xray-speed --no-pager
```

## Lokasi Data Penting
```text
/usr/local/etc/xray/conf.d/
/etc/nginx/conf.d/xray.conf
/opt/cert/fullchain.pem
/opt/cert/privkey.pem

/opt/account/{vless,vmess,trojan}/
/opt/quota/{vless,vmess,trojan}/
/opt/speed/{vless,vmess,trojan}/

/etc/xray-speed/config.json
/var/lib/xray-speed/state.json
/var/lib/xray-manage/
/var/log/xray-manage/
```

## Menjalankan Menu
```bash
manage
```

atau

```bash
/usr/local/bin/manage
```

## Troubleshooting Singkat
| Kasus | Tindakan |
|---|---|
| `Jalankan sebagai root` | Jalankan dengan `sudo` atau login root |
| TLS issue gagal (dns_cf) | Pastikan token Cloudflare valid + scope DNS edit & zone read |
| Speed limit tidak terasa | Cek `xray-speed` service dan status apply policy |
| User tidak auto-lock/unlock | Cek `xray-quota` + `xray-limit-ip` service |
| `Target Tier` unknown | Jalankan switch tier (Free/Plus) sekali agar target tersimpan |

---
Dokumentasi ini sengaja menonjolkan fitur operasional menu karena itu inti workflow harian admin di project ini.
