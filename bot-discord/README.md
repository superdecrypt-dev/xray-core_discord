# Bot Discord Standalone (UI Button + Select + Modal)

Bot ini berdiri sendiri dan tidak menjalankan `manage.sh`. Perilaku menunya dibuat mirip struktur `manage.sh` (menu 1-8), tetapi seluruh aksi dieksekusi lewat backend sendiri.

## Arsitektur
- `gateway-ts/`: Discord gateway (`discord.js`) untuk slash command minimal (`/panel`), tombol, modal, dan select.
- `backend-py/`: API internal (`FastAPI`) untuk operasi sistem/Xray.
- `shared/`: kontrak menu/action yang dipakai gateway dan backend.
- `systemd/`: template service untuk deployment.

## Alur Interaksi
1. Admin jalankan `/panel`.
2. Gateway kirim panel menu utama (button 1-8).
3. User pilih action via button/select/modal.
4. Gateway memanggil backend (`/api/menu/{id}/action`) dengan secret internal.
5. Backend menjalankan aksi dan mengembalikan hasil ke Discord.

## UX Terkini (RELEASE)
- Alur yang membutuhkan pilihan protokol/user diprioritaskan memakai select untuk menurunkan risiko typo.
- `Add User`:
  - memilih protokol via select,
  - output sukses berupa embed ringkasan (`Username`, `Protokol`, `Masa Aktif`, `Quota`, `IP Limit`, `Speed Limit`),
  - lampiran file `username@protokol.txt`.
- `Account Info`:
  - pemilihan user via select,
  - output berupa embed ringkasan + lampiran file `username@protokol.txt`.
- `Domain Control`:
  - `Set Domain Manual` untuk domain sendiri (sudah pointing ke IP VPS),
  - `Set Domain Auto (API Cloudflare)` untuk root domain bawaan sistem,
  - root domain dipilih via select (`vyxara1.web.id`, `vyxara2.web.id`, `vyxara1.qzz.io`, `vyxara2.qzz.io`).
- `Network Controls`:
  - `Set Egress Mode`, `Set Balancer Strategy`, `Set Balancer Selector`, `Set DNS Query Strategy` memakai select.
- `Run Speedtest` diringkas ke metrik inti: ISP, Latency, Packet Loss, Download, Upload.

## Jalankan Lokal
```bash
cd bot-discord
cp .env.example .env

# Backend
python3 -m venv .venv
. .venv/bin/activate
pip install -r backend-py/requirements.txt
uvicorn backend-py.app.main:app --host 127.0.0.1 --port 8080 --reload

# Gateway (terminal lain)
cd gateway-ts
npm install
npm run dev
```

## Otomasi Pengujian Gate
Satu command untuk menjalankan paket uji bertahap:

```bash
cd bot-discord
./scripts/gate-all.sh local   # Gate 1,2,3 (local/staging non-produksi)
./scripts/gate-all.sh prod    # Gate 3.1,5,6 (produksi via LXC)
./scripts/gate-all.sh all     # Gate 1-6 (Gate 4 pakai STAGING_INSTANCE)
```

Override target instance jika perlu:

```bash
PROD_INSTANCE=xray-itg-1771777921 STAGING_INSTANCE=xray-stg-gate3-1771864485 ./scripts/gate-all.sh all
```

## Rotasi Token Discord (Aman)
Jalankan langsung di VPS agar token tidak terkirim ke chat/log:

```bash
cd /opt/bot-discord
./scripts/rotate-discord-token.sh
```

Script akan:
- meminta token baru dengan input tersembunyi,
- update `DISCORD_BOT_TOKEN` di env file deploy,
- restart `xray-discord-gateway`,
- menampilkan status service setelah restart.

## Monitoring Ringan (Timer)
Deploy terbaru memasang timer `xray-discord-monitor.timer` (interval 5 menit) yang menjalankan:

```bash
/opt/bot-discord/scripts/monitor-lite.sh
```

Cakupan cek:
- status `xray-discord-backend`,
- status `xray-discord-gateway`,
- endpoint `GET /health` backend.

Lihat status timer:

```bash
systemctl status xray-discord-monitor.timer --no-pager
tail -n 50 /var/log/xray-discord-bot/monitor-lite.log
```

## Menu yang Didukung (Mirip manage.sh)
- `1) Status & Diagnostics`
- `2) User Management`
- `3) Quota & Access Control`
- `4) Network Controls`
- `5) Domain Control`
- `6) Speedtest`
- `7) Security`
- `8) Maintenance`

## Catatan Keamanan
- Simpan token hanya di env file (`/etc/xray-discord-bot/bot.env` saat deploy).
- Secret API internal wajib diset (`INTERNAL_SHARED_SECRET`).
- Beberapa aksi maintenance (restart service) butuh root/sudo dan sebaiknya dibatasi role admin Discord.
