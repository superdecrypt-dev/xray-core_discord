# Xray VPN Server - Auto Setup and Management

Automasi instalasi dan operasional server proxy berbasis Xray-core, dengan dukungan protokol VLESS, VMess, dan Trojan melalui WS, HTTPUpgrade, dan gRPC, serta TLS termination di Nginx.

## Instalasi Cepat
Jalankan di VPS sebagai `root`:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/superdecrypt-dev/xray-core_discord/main/run.sh)
```

`run.sh` akan:
1. Clone repository.
2. Install command `manage` ke `/usr/local/bin/manage`.
3. Menjalankan `setup.sh` (interaktif, one-time).

## File Utama
| File | Fungsi |
|---|---|
| `setup.sh` | Instalasi awal server (one-time setup) |
| `manage.sh` | Operasional harian (menu interaktif) |
| `run.sh` | Bootstrap installer cepat (clone + install `manage` + jalankan setup) |

## Persyaratan
- OS: Ubuntu >= 20.04 atau Debian >= 11
- Hak akses: root
- Akses internet keluar (untuk install paket, ACME, geodata, dan download binary)

Dependency dasar dipasang otomatis oleh `setup.sh`.

## Ringkasan `setup.sh`
`setup.sh` menangani provisioning dari nol sampai siap dipakai:

1. Install dependency sistem.
2. Install Nginx dari repo resmi `nginx.org`.
3. Install Xray-core.
4. Generate konfigurasi Xray modular di `/usr/local/etc/xray/conf.d/`.
5. Install TLS certificate via acme.sh.
6. Install daemon operasional: `xray-expired`, `xray-quota`, `xray-limit-ip`, `xray-speed`.
7. Install hardening dasar (fail2ban, sysctl, logrotate, dsb).

### Domain Mode saat Setup
`setup.sh` menyediakan 2 mode domain:

1. `input domain sendiri`
- Domain harus sudah mengarah ke IP VPS.
- ACME mode: `standalone` (port 80 diperlukan saat issue cert).

2. `gunakan domain yang disediakan`
- Pilih root domain dari daftar bawaan, lalu pilih/generate subdomain.
- Script membuat/mengupdate A record via Cloudflare API.
- ACME mode: `dns_cf_wildcard`.

### Catatan Cloudflare Token
- Variable yang dipakai: `CLOUDFLARE_API_TOKEN`.
- Di `setup.sh` sudah ada default token hardcoded.
- Anda tetap bisa override via environment variable sebelum menjalankan setup:

```bash
export CLOUDFLARE_API_TOKEN="token-anda"
```

## Ringkasan `manage.sh`
`manage.sh` adalah menu operasional harian. Berbeda dengan versi dokumentasi lama, script ini memang melakukan perubahan konfigurasi runtime (inbounds, routing, outbounds, metadata) saat aksi operasional dijalankan.

Struktur menu utama:

```text
Main Menu
  1) Status & Diagnostics
  2) User Management
  3) Quota & Access Control
  4) Network Controls
  5) Security
  6) Maintenance
  0) Exit
```

### User Management
- Add user (VLESS/VMess/Trojan)
- Delete user
- Extend/Set expiry
- List users

Input saat add user:
- username
- masa aktif (hari)
- quota (GB)
- IP limit on/off + nilai limit
- speed limit on/off + speed download/upload

### Quota and Access Control
Detail menu per user:

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

Status yang ditampilkan di detail:
- Quota Limit / Used / Expired
- IP Limit ON/OFF + max IP
- Block Reason (MANUAL / QUOTA / IP_LIMIT)
- Speed Download / Speed Upload / Speed Limit ON/OFF

## Daemon Runtime
Daemon yang dipasang oleh setup:

- `xray-expired`: hapus user expired dari inbounds/routing.
- `xray-quota`: sinkron usage dari Xray API, lock user jika quota habis.
- `xray-limit-ip`: lock user jika jumlah IP aktif melebihi batas.
- `xray-speed`: apply shaping per-user berbasis mark (tc + nft).

Cek status:

```bash
systemctl status xray xray-expired xray-quota xray-limit-ip xray-speed --no-pager
```

## Struktur Direktori Penting
```text
/usr/local/etc/xray/conf.d/
  00-log.json
  01-api.json
  02-dns.json
  10-inbounds.json
  20-outbounds.json
  30-routing.json
  40-policy.json
  50-stats.json
  60-observatory.json

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

## Catatan Teknis Penting
- Operasi write ke config dilakukan atomik dan memakai lock file untuk mengurangi race condition daemon.
- Permission file config Xray yang disarankan:
  - `/usr/local/etc/xray/conf.d/10-inbounds.json` -> `640 root:xray`
  - `/usr/local/etc/xray/conf.d/20-outbounds.json` -> `640 root:xray`
  - `/usr/local/etc/xray/conf.d/30-routing.json` -> `640 root:xray`
- Setelah perubahan besar pada user/routing/speed, `xray` bisa direstart oleh script agar perubahan langsung aktif.

## Troubleshooting Cepat
| Masalah | Solusi |
|---|---|
| `Jalankan sebagai root` | Jalankan dengan `sudo` atau login root |
| `Cannot find DNS API hook for: dns_cf` | Jalankan setup versi terbaru (acme source bundle + bootstrap dns_cf hook sudah ditangani) |
| `permission denied ... 30-routing.json` saat start xray | Set `chown root:xray` dan `chmod 640` untuk file routing |
| Speed limit tidak terasa | Cek `systemctl status xray-speed`, lalu `xray-speed status --config /etc/xray-speed/config.json` |
| User tidak terhapus/terkunci sesuai ekspektasi | Cek status daemon `xray-quota` dan `xray-limit-ip` |

## Operasi Dasar
Jalankan menu manajemen:

```bash
manage
```

Atau:

```bash
/usr/local/bin/manage
```
