# Bot Telegram (Standalone)

Bot Telegram ini adalah pelengkap CLI `manage.sh`, berjalan standalone di `/opt/bot-telegram`.

## Tujuan
- Panel Telegram untuk action yang setara menu operasional `manage.sh`.
- Tidak menjalankan `manage.sh` secara langsung dari bot.
- Menggunakan backend API lokal (`backend-py`) + gateway Telegram (`gateway-py`).

## Struktur
- `backend-py/`: FastAPI service action menu 1-8 dan traffic analytics.
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

## Operasional cepat
- Installer menu: `sudo /usr/local/bin/install-telegram-bot menu`
- Status: `sudo /usr/local/bin/install-telegram-bot status`
- Smoke: `sudo /opt/bot-telegram/scripts/smoke-test.sh`
