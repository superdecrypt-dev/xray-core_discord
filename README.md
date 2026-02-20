# Xray VPN Server — Auto Setup & Management

Script bash untuk instalasi dan manajemen server proxy berbasis **Xray-core** dengan dukungan protokol **VLESS**, **VMess**, dan **Trojan** melalui transport **WebSocket (WS)**, **HTTPUpgrade**, dan **gRPC**, dilengkapi TLS via Nginx dan sertifikat SSL otomatis.

---

## ⚡ Instalasi Cepat

Jalankan perintah berikut di VPS sebagai root:

```bash
bash <(curl -fsSL https://raw.githubusercontent.com/superdecrypt-dev/xray-core_discord/main/run.sh)
```

Script akan otomatis mengunduh repositori, memasang perintah `manage`, dan menjalankan setup interaktif.

---

## 📁 File Utama

| File | Fungsi |
|------|--------|
| `setup.sh` | Instalasi awal server (satu kali jalan) |
| `manage.sh` | Manajemen harian pasca-setup (menu interaktif) |

---

## ⚙️ Persyaratan Sistem

- **OS:** Ubuntu ≥ 20.04 atau Debian ≥ 11
- **Virtualisasi:** KVM only
- **Hak akses:** Root (`sudo`)
- **Dependency:** `curl`, `python3`, `jq`, `unzip`, `socat`, `cron`, `dnsutils`, `iproute2`

> Dependency akan dipasang otomatis oleh `setup.sh` jika belum tersedia.

---

## 🚀 Instalasi (`setup.sh`)

Script ini menangani seluruh proses setup dari nol hingga server siap dipakai.

### Yang Dilakukan setup.sh

- Memeriksa kompatibilitas OS
- Menginstal dependency dasar
- Menginstal **Xray-core** dari sumber resmi
- Menginstal dan mengkonfigurasi **Nginx** (dari nginx.org repo)
- Menerbitkan sertifikat TLS via **acme.sh** dengan dua mode:
  - `standalone` — untuk domain milik sendiri (verifikasi port 80)
  - `dns_cf_wildcard` — wildcard cert via Cloudflare DNS API
- Mengkonfigurasi Xray dengan **port & path internal yang diacak** (lebih aman)
- Menyimpan sertifikat ke `/opt/cert/fullchain.pem` dan `/opt/cert/privkey.pem`
- Mendukung domain sendiri **atau** subdomain dari daftar domain yang disediakan

### Opsi Domain

Saat setup dijalankan, Anda akan diminta memilih:

1. **Input domain sendiri** — masukkan domain/subdomain yang sudah diarahkan ke IP VPS
2. **Gunakan domain yang disediakan** — subdomain otomatis dibuat di atas domain bawaan via Cloudflare API

---

## 🛠️ Manajemen Harian (`manage.sh`)

Script interaktif berbasis menu untuk operasi setelah setup selesai.

### Struktur Menu

```
Main Menu
├── 1) Status & Diagnostics      — Cek status layanan, koneksi, dan konfigurasi
├── 2) User Management           — Tambah / hapus / lihat akun pengguna
├── 3) Quota & Access Control    — Kelola kuota data per user per protokol
├── 4) Network Controls          — Pengaturan jaringan
├── 5) Security                  — TLS, Fail2ban, Hardening, Security Overview
│   ├── TLS & Certificate        — Cek dan perbarui sertifikat SSL
│   ├── Fail2ban Protection      — Lihat jail, banned IP, unban, restart
│   ├── System Hardening Status  — Cek BBR, Swap, Ulimit, Chrony
│   └── Security Overview        — Ringkasan status keamanan server
└── 6) Maintenance               — Restart layanan, lihat log Xray/Nginx
```

### Fitur Utama manage.sh

**User Management**
- Tambah/hapus akun untuk protokol VLESS, VMess, atau Trojan
- Validasi username (aman dari path traversal)
- Generate UUID otomatis untuk akun baru

**Quota & Access Control**
- Set kuota data (dalam GB) per user per protokol
- Pantau penggunaan dan sisa kuota
- Data kuota disimpan di `/opt/quota/`

**Security**
- Pantau masa berlaku sertifikat TLS
- Kelola IP yang diblokir oleh Fail2ban (SSH, Nginx, Recidive jail)
- Cek status BBR, Swap, file descriptor limit (ulimit), dan Chrony

**Maintenance**
- Restart Xray, Nginx, atau keduanya sekaligus
- Tampilkan log real-time (`tail`) dari Xray maupun Nginx

---

## 📂 Struktur Direktori

```
/usr/local/etc/xray/conf.d/     # Konfigurasi Xray (modular)
  ├── 00-log.json
  ├── 01-api.json
  ├── 02-dns.json
  ├── 10-inbounds.json
  ├── 20-outbounds.json
  ├── 30-routing.json
  ├── 40-policy.json
  ├── 50-stats.json
  └── 60-observatory.json

/etc/nginx/conf.d/xray.conf     # Konfigurasi Nginx
/opt/cert/                      # Sertifikat TLS
  ├── fullchain.pem
  └── privkey.pem

/opt/account/                   # Data akun user (read-only referensi)
  ├── vless/
  ├── vmess/
  └── trojan/

/opt/quota/                     # Metadata kuota per user
  ├── vless/
  ├── vmess/
  └── trojan/

/var/lib/xray-manage/           # Direktori kerja internal (atomic write)
/var/log/xray-manage/           # Laporan & export
```

---

## 🔐 Keamanan

- Port dan path internal Xray **diacak saat setup** untuk menghindari deteksi mudah
- Path publik Nginx tetap konsisten (sesuai konfigurasi)
- Integrasi Fail2ban untuk proteksi SSH dan Nginx
- Dukungan Cloudflare DNS API untuk wildcard cert (tidak memerlukan port 80 terbuka)

---

## 📝 Catatan Penting

- `setup.sh` hanya dijalankan **sekali** saat instalasi awal
- `manage.sh` **tidak mengubah** konfigurasi yang dibuat oleh `setup.sh`
- Semua operasi di `manage.sh` menggunakan **atomic write** untuk menghindari kerusakan konfigurasi
- Script membutuhkan akses **root** untuk dijalankan

---

## 🆘 Troubleshooting

| Masalah | Solusi |
|---------|--------|
| `Jalankan sebagai root` | Gunakan `sudo ./manage.sh` |
| `File immutable` | Jalankan `chattr -i <file>` lalu ulangi |
| `python3 tidak ditemukan` | `apt-get install -y python3` |
| Sertifikat expired | Masuk menu **5 → 1 (TLS & Certificate)** |
| Layanan tidak aktif | Masuk menu **6 → 1/2/3 (Restart)** |
