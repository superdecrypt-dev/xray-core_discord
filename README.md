# Autoscript

> Auto setup + menu operasional harian untuk Xray-core di VPS Linux.

![Shell](https://img.shields.io/badge/Shell-Bash-121011?logo=gnu-bash)
![OS](https://img.shields.io/badge/OS-Ubuntu%20%2F%20Debian-0B3D91)
![Xray](https://img.shields.io/badge/Xray%20Core-Operational-1F6FEB)
![Mode](https://img.shields.io/badge/Mode-Menu%20Driven-2EA043)

`setup.sh` dipakai sekali untuk provisioning. `manage.sh` dipakai terus untuk operasi harian.  
Untuk automasi chatops, tersedia bot standalone Discord (`bot-discord/`) dan Telegram (`bot-telegram/`).

[Quick Install](#quick-install-root) | [Fitur Utama](#fitur-utama-highlight) | [Fitur manage.sh](#fitur-unggulan-managesh) | [Bot Discord](#fitur-bot-discord-standalone) | [Bot Telegram](#fitur-bot-telegram-standalone) | [Transport](#transport-yang-didukung) | [Troubleshooting](#troubleshooting-cepat)

## Kenapa Project Ini
| Nilai Utama | Penjelasan Singkat |
|---|---|
| Cepat dipakai | Satu command install, lanjut operasi lewat menu interaktif |
| Operasional terpusat | User, quota, speed, routing, domain, dan security di satu panel |
| Aman untuk runtime changes | Ada validasi config, lock file, dan pemisahan setup vs daily operations |
| Ramah admin | Status realtime server tampil di header menu utama |

## Fitur Utama (Highlight)
- One-time provisioning lengkap via `setup.sh`: Xray, Nginx, TLS, WARP, daemon runtime.
- Operasional harian terpusat via `manage.sh` menu 1-11 (status, user, quota, network, security, maintenance, analytics, installer bot).
- Bot Discord standalone dengan UX interaktif tombol/select/modal (`/panel` sebagai entry point minimal).
- Bot Telegram standalone dengan UX interaktif tombol/select/modal (`/panel` + `/cleanup`).
- Bot Telegram kini setara penuh kontrol WARP (status/restart/global/per-user/per-inbound/per-domain/tier/reconnect).
- Installer bot terpisah (`install-discord-bot.sh`) dengan mode menu + quick setup all-in-one.
- Installer bot Telegram terpisah (`install-telegram-bot.sh`) dengan mode menu + quick setup all-in-one.
- Deploy source bot memakai verifikasi checksum archive sebelum extract (lebih aman dari archive corrupt/tampered).
- Transport `xhttp` sudah dinonaktifkan dari stack default karena kompatibilitas domain fronting.

## Quick Install (Root)
```bash
bash <(curl -fsSL https://raw.githubusercontent.com/superdecrypt-dev/autoscript/main/run.sh)
```

`run.sh` akan:
1. Clone repo
2. Install command `manage` ke `/usr/local/bin/manage`
3. Menjalankan `setup.sh`

Catatan path source:
- Canonical source installer: `/opt/autoscript`
- Alias kompatibilitas lama: `/root/xray-core_discord`

## Alur Operasional
```mermaid
flowchart LR
    A[run.sh] --> B[setup.sh one-time provisioning]
    B --> C[service dan daemon siap]
    C --> D[manage.sh daily operations]
```

## Struktur File
| File | Peran |
|---|---|
| `setup.sh` | One-time setup dari nol sampai service aktif |
| `manage.sh` | Menu operasional harian (runtime changes) |
| `run.sh` | Bootstrap installer cepat |
| `install-discord-bot.sh` | Installer bot Discord standalone (menu + quick setup) |
| `install-telegram-bot.sh` | Installer bot Telegram standalone (menu + quick setup) |

## Fitur Unggulan `manage.sh`
`manage.sh` adalah pusat kontrol runtime untuk pekerjaan harian admin.

### Peta Menu
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
  10) Traffic Analytics
  11) Install BOT Telegram
  0) Exit
```

Catatan kompatibilitas:
- Input `12` tetap diarahkan ke menu Traffic Analytics (alias lama).

Header realtime di Main Menu menampilkan:
- `SYSTEM OS`, `RAM`, `UPTIME`
- `IP VPS`, `ISP`, `COUNTRY`
- `DOMAIN`, `TLS EXPIRED`, `WARP STATUS`
- Jumlah akun: `VLESS | VMESS | TROJAN`

### Ringkasan Fitur Per Menu
| Menu | Fokus Operasional | Dampak |
|---|---|---|
| `1) Status & Diagnostics` | Cek status `xray/nginx`, daemon, TLS, listener, validasi config | Diagnosa cepat saat ada gangguan |
| `2) User Management` | Add, delete, set expiry, list user | Lifecycle akun harian lebih efisien |
| `3) Quota & Access Control` | Quota, block, IP limit, speed limit per user | Kontrol abuse lebih presisi |
| `4) Network Controls` | Egress direct/warp/balancer, adblock geosite, DNS, WARP tier | Routing fleksibel sesuai kebutuhan |
| `5) Domain Control` | Set domain + issue cert, cek status cert/key, domain guard | Manajemen domain dari satu menu |
| `6) Speedtest` | Jalankan Ookla speedtest + cek versi | Verifikasi performa jaringan cepat |
| `7) Security` | TLS ops, fail2ban, hardening status | Meningkatkan keamanan operasional |
| `8) Maintenance` | Restart service/daemon, tail log, wireproxy status | Maintenance tanpa keluar panel |
| `9) Install BOT Discord` | Launcher installer bot standalone (`/usr/local/bin/install-discord-bot`) | Setup, deploy, update, restart, dan uninstall bot dari menu |
| `10) Traffic Analytics` | Overview traffic, top users, search user, export JSON report | Observabilitas pemakaian traffic lebih cepat |
| `11) Install BOT Telegram` | Launcher installer bot standalone (`/usr/local/bin/install-telegram-bot`) | Setup, deploy, update, restart, dan uninstall bot dari menu |

### Detail Penting: `3) Quota & Access Control`
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
- Quota limit, quota used, expired date
- Status IP limit dan nilai maksimum
- Lock reason: `manual`, `quota`, `ip_limit`
- Speed download/upload + status speed limiter

### Detail Penting: `4) Network Controls`
- Egress mode: `direct`, `warp`, `balancer`
- Balancer strategy, selector, observatory tuning
- Adblock geosite custom (`ext:custom.dat:adblock`) dengan mode:
  `blocked`, `direct`, `warp`, `balancer (direct+warp)`, `disable`
- WARP controls: global, per-user, per-protocol inbound, per-domain/geosite
- WARP tier management: `Target Tier` dan `Live Tier`
- DNS settings + advanced DNS editor

## Fitur Bot Discord (Standalone)
Bot Discord berada di `bot-discord/` dan sengaja berdiri sendiri (tidak mengeksekusi `manage.sh`).

Highlight kemampuan:
- Status rilis saat ini: **Stabil** (siap produksi, tetap disarankan staging-first sebelum perubahan besar).
- UX Discord: dominan button/select/modal, slash command minimal (`/panel`).
- Cakupan menu mengikuti pola `manage.sh` (menu 1-8 + Traffic Analytics) agar familiar untuk admin.
- Menu `1)` sudah mencakup observability action (`snapshot`, `status`, `alert log`).
- Menu `5)` sudah mencakup domain guard action (`check`, `status`, `renew-if-needed`).
- Menu `12)` menyediakan traffic analytics (`overview`, `top users`, `search`, `export JSON`).
- Flow `Add User`, `Extend/Set Expiry`, `Account Info`, dan aksi Network/Domain tertentu sudah select-driven untuk meminimalkan typo input.
- Hasil `Add User` dan `Account Info` ditampilkan sebagai embed ringkas + lampiran file `username@protokol.txt`.
- Menu Domain Control disederhanakan menjadi:
  - `Set Domain Manual` (domain milik sendiri, sudah pointing ke IP VPS)
  - `Set Domain Auto (API Cloudflare)` (pakai root domain bawaan sistem)
- Arsitektur terpisah gateway TypeScript (`discord.js`) + backend Python (`FastAPI`).
- Role-based access lewat `DISCORD_ADMIN_ROLE_IDS` dan `DISCORD_ADMIN_USER_IDS`.
- Deploy produksi via `install-discord-bot.sh` ke `/opt/bot-discord` + systemd service terpisah.

## Fitur Bot Telegram (Standalone)
Bot Telegram berada di `bot-telegram/` dan berdiri sendiri (tidak mengeksekusi `manage.sh`).

Highlight kemampuan:
- Slash command minimal: `/panel` dan `/cleanup`.
- Flow interaktif button/select/modal untuk menu operasi yang sinkron dengan backend.
- Add User mendukung speed limit saat provisioning akun (`speed_limit_enabled`, `speed_down_mbit`, `speed_up_mbit`).
- Delete User memakai picker protocol + daftar username agar admin tidak perlu hafal user.
- Menu `4) Network Controls` sekarang memiliki parity WARP penuh:
  - `warp_status`, `warp_restart`
  - `set_warp_global_mode`, `set_warp_user_mode`, `set_warp_inbound_mode`, `set_warp_domain_mode`
  - `warp_tier_status`, `warp_tier_switch_free`, `warp_tier_switch_plus`, `warp_tier_reconnect`
- Hardening Telegram terbaru:
  - Backend `/health` sekarang wajib header `X-Internal-Shared-Secret`.
  - ACL default-deny (wajib isi admin IDs, kecuali override eksplisit).
  - Output hasil action disanitasi agar token/secret sensitif tidak bocor ke chat.
  - Throttle/cooldown action dan cleanup untuk menekan spam/double-trigger.
- Menu `10) Backup/Restore`:
  - `create_backup`, `list_backups`, `restore_latest`, `restore_from_upload`.
  - Scope backup mencakup conf Xray/Nginx, state account/quota/speed, network state, wireproxy config, dan cert TLS.
  - Restore memakai safety snapshot + rollback otomatis saat validasi/restart service gagal.
- Deploy produksi via `install-telegram-bot.sh` ke `/opt/bot-telegram` + systemd service terpisah.

## Transport Yang Didukung
Stack default saat ini menyediakan endpoint berikut:
- `ws`
- `httpupgrade`
- `grpc`

Catatan:
- Transport `xhttp` sudah dihapus dari template `setup.sh`, `manage.sh`, dan generator link bot.
- Tujuan perubahan: mencegah masalah koneksi pada skenario domain fronting.

## Ringkasan `setup.sh` (One-Time)
`setup.sh` menangani provisioning awal end-to-end:
1. Install dependency OS
2. Install Nginx dari repo resmi `nginx.org`
3. Install Xray-core + geodata updater + custom geosite adblock (`custom.dat`)
4. Generate modular config di `/usr/local/etc/xray/conf.d/`
5. Issue TLS via acme.sh (standalone atau `dns_cf_wildcard`)
6. Install WARP stack (`wgcf` + `wireproxy`)
7. Install daemon runtime: `xray-expired`, `xray-quota`, `xray-limit-ip`, `xray-speed`
8. Apply baseline hardening (fail2ban, sysctl/BBR, swap, ulimit, logrotate)
9. Install speedtest via snap

Catatan custom geosite adblock:
- Sumber: `https://github.com/superdecrypt-dev/custom-geosite-xray/raw/main/custom.dat`
- Lokasi install: `/usr/local/share/xray/custom.dat`
- Aktivasi routing dilakukan dari `manage.sh` -> `4) Network Controls` -> `6) Adblock (Custom Geosite)`

## Daemon Runtime
| Service | Fungsi |
|---|---|
| `xray-expired` | Hapus user expired dari inbounds/routing |
| `xray-quota` | Lock user saat quota habis |
| `xray-limit-ip` | Lock user saat IP aktif melebihi limit |
| `xray-speed` | Terapkan speed policy per user (tc + nft) |

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

Atau:
```bash
/usr/local/bin/manage
```

## Troubleshooting Cepat
| Kasus | Tindakan |
|---|---|
| `Jalankan sebagai root` | Jalankan dengan `sudo` atau login root |
| TLS issue gagal (dns_cf) | Pastikan token Cloudflare valid, scope DNS edit + zone read |
| Speed limit tidak terasa | Cek service `xray-speed` dan status apply policy |
| User tidak auto-lock/unlock | Cek service `xray-quota` + `xray-limit-ip` |
| `Target Tier` unknown | Jalankan switch tier (Free/Plus) sekali agar target tersimpan |

---
Dokumentasi ini sengaja menempatkan `manage.sh` sebagai pusat workflow harian admin.
