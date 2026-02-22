# Bot Discord Standalone (UI Button + Modal)

Bot ini berdiri sendiri dan tidak menjalankan `manage.sh`. Perilaku menunya dibuat mirip struktur `manage.sh` (menu 1-9), tetapi seluruh aksi dieksekusi lewat backend sendiri.

## Arsitektur
- `gateway-ts/`: Discord gateway (`discord.js`) untuk slash command minimal (`/panel`), tombol, modal, dan select.
- `backend-py/`: API internal (`FastAPI`) untuk operasi sistem/Xray.
- `shared/`: kontrak menu/action yang dipakai gateway dan backend.
- `systemd/`: template service untuk deployment.

## Alur Interaksi
1. Admin jalankan `/panel`.
2. Gateway kirim panel menu utama (button 1-9).
3. User pilih action via button/modal.
4. Gateway memanggil backend (`/api/menu/{id}/action`) dengan secret internal.
5. Backend menjalankan aksi dan mengembalikan hasil ke Discord.

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

## Menu yang Didukung (Mirip manage.sh)
- `1) Status & Diagnostics`
- `2) User Management`
- `3) Quota & Access Control`
- `4) Network Controls`
- `5) Domain Control`
- `6) Speedtest`
- `7) Security`
- `8) Maintenance`
- `9) Install BOT Discord`

## Catatan Keamanan
- Simpan token hanya di env file (`/etc/xray-discord-bot/bot.env` saat deploy).
- Secret API internal wajib diset (`INTERNAL_SHARED_SECRET`).
- Beberapa aksi maintenance (restart service) butuh root/sudo dan sebaiknya dibatasi role admin Discord.
