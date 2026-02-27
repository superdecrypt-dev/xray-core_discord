# Bot Telegram (Standalone)

Bot Telegram ini adalah pelengkap CLI `manage.sh`, berjalan standalone di `/opt/bot-telegram`.

## Tujuan
- Panel Telegram untuk action yang setara menu operasional `manage.sh`.
- Tidak menjalankan `manage.sh` secara langsung dari bot.
- Menggunakan backend API lokal (`backend-py`) + gateway Telegram (`gateway-py`).

## Struktur
- `backend-py/`: FastAPI service action menu operasional Telegram (status, user, quota, network, domain, speedtest, security, maintenance, traffic analytics, backup/restore).
- `gateway-py/`: Bot Telegram berbasis `python-telegram-bot`.
- `shared/commands.json`: definisi menu/action.
- `systemd/`: template unit backend/gateway/monitor.
- `scripts/`: gate/smoke/monitor helper.

## Env penting
Dikelola di `/etc/xray-telegram-bot/bot.env`:
- `INTERNAL_SHARED_SECRET`
- `TELEGRAM_BOT_TOKEN`
- `TELEGRAM_ADMIN_CHAT_IDS` (opsional, CSV)
- `TELEGRAM_ADMIN_USER_IDS` (opsional, CSV)
- `TELEGRAM_ALLOW_UNRESTRICTED_ACCESS` (default `false`, tidak direkomendasikan)
- `TELEGRAM_ACTION_COOLDOWN_SECONDS` (default `1`)
- `TELEGRAM_CLEANUP_COOLDOWN_SECONDS` (default `30`)
- `TELEGRAM_MAX_INPUT_LENGTH` (default `128`)
- `BACKEND_BASE_URL`
- `COMMANDS_FILE`

## Backup/Restore (Menu 10)
Fitur `10) Backup/Restore` dipakai untuk membuat arsip backup lokal, melihat daftar backup, restore backup lokal terbaru, dan restore dari upload `.tar.gz`.

Scope file yang dibackup:
- `/usr/local/etc/xray/conf.d` (seluruh file konfigurasi Xray)
- `/etc/nginx/conf.d/xray.conf`
- `/opt/account`
- `/opt/quota`
- `/opt/speed`
- `/etc/xray-speed/config.json`
- `/var/lib/xray-speed/state.json`
- `/var/lib/xray-manage/network_state.json`
- `/etc/wireproxy/config.conf`
- `/etc/xray/domain`
- `/opt/cert/fullchain.pem`
- `/opt/cert/privkey.pem`

Catatan penting:
- Backup tidak menyertakan env bot (token Telegram, shared secret, ACL chat/user).
- Restore bekerja sebagai rollback ke kondisi backup (bukan merge data incremental).
- Akun yang dibuat setelah titik backup bisa hilang, dan akun lama yang terhapus setelah backup bisa muncul lagi.
- Restore menulis file dari arsip ke path yang diizinkan dan tidak melakukan purge massal direktori.
- Setiap restore membuat safety snapshot lebih dulu. Jika validasi/restart service gagal, sistem mencoba rollback otomatis.
- Action restore/create backup termasuk dangerous action dan mengikuti `ENABLE_DANGEROUS_ACTIONS`.

## Operasional cepat
- Installer menu: `sudo /usr/local/bin/install-telegram-bot menu`
- Status: `sudo /usr/local/bin/install-telegram-bot status`
- Smoke: `sudo /opt/bot-telegram/scripts/smoke-test.sh`
