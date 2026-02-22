# Bot Discord Architecture Lock

Dokumen ini mengunci keputusan implementasi agar konsisten saat eksekusi berikutnya.

## 1) Struktur Bot Discord (Standalone)
Bot Discord berjalan standalone dan tidak mengeksekusi `manage.sh` secara langsung.

```text
bot-discord/
├─ README.md
├─ .env.example
├─ shared/
│  ├─ commands.json
│  ├─ error_codes.json
│  └─ schemas/
├─ gateway-ts/
│  ├─ package.json
│  ├─ tsconfig.json
│  └─ src/
│     ├─ index.ts
│     ├─ config.ts
│     ├─ authz.ts
│     ├─ router.ts
│     ├─ api_client.ts
│     ├─ interactions/
│     └─ views/
├─ backend-py/
│  ├─ requirements.txt
│  └─ app/
│     ├─ main.py
│     ├─ config.py
│     ├─ auth.py
│     ├─ routes/
│     ├─ services/
│     ├─ adapters/
│     └─ utils/
├─ runtime/
│  ├─ logs/
│  ├─ locks/
│  └─ tmp/
├─ systemd/
│  ├─ xray-discord-gateway.service.tpl
│  └─ xray-discord-backend.service.tpl
└─ scripts/
   ├─ dev-up.sh
   ├─ dev-down.sh
   └─ smoke-test.sh
```

## 2) Struktur Menu `install-discord-bot.sh`
Mode utama yang dipakai: `menu`.

```text
1) Quick Setup Bot Discord (All-in-One)
2) Install Dependencies
3) Configure Bot (.env)
4) Ganti Discord Bot Token
5) Deploy/Update Bot Files
6) Install/Update systemd Services
7) Start/Restart Services
8) Status Services
9) View Logs
10) Uninstall Bot
0) Back
```

### Mekanisme fungsi menu
- `1` menjalankan full flow: dependencies -> input token/env -> deploy source -> install/update service -> start bot -> verifikasi status.
- `2` memasang prasyarat OS/runtime (idempotent).
- `3` membuat/memperbarui `/etc/xray-discord-bot/bot.env`.
- `4` memperbarui `DISCORD_BOT_TOKEN` secara aman (`read -s`, mask, permission 600).
- `5` deployment source ke `/opt/bot-discord`.
- `6` pasang/update service systemd yang menunjuk ke `/opt/bot-discord`.
- `7` restart/start service bot.
- `8` cek status service.
- `9` tampilkan log (`journalctl`).
- `10` uninstall dengan konfirmasi.

## 3) Lokasi Deploy (Fixed)
Lokasi bot Discord dikunci di:

```text
/opt/bot-discord
```

Lokasi operasional terkait:
- Launcher menu: `/usr/local/bin/install-discord-bot.sh`
- Env file: `/etc/xray-discord-bot/bot.env`
- Runtime data/log: `/var/lib/xray-discord-bot`, `/var/log/xray-discord-bot`

## 4) Mekanisme Deploy Source di VPS (Tanpa Repo Lokal)
Deploy menggunakan archive terstruktur (tar.gz) dari GitHub lalu sync ke target:
1. Download archive dengan `REF` yang dipin (tag/commit).
2. Extract ke staging `/tmp`.
3. Validasi struktur wajib (`gateway-ts/package.json`, `backend-py/requirements.txt`, `systemd/*.service.tpl`).
4. Sync ke `/opt/bot-discord` menggunakan `rsync -a --delete` dengan exclude file runtime (`.env`, `.venv`, `node_modules`, `__pycache__`, `*.pyc`).
5. Install dependency app lalu restart service.

Keputusan ini menjadi baseline implementasi berikutnya sampai ada perubahan eksplisit.
