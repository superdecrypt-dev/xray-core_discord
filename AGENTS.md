# Repository Guidelines

## Struktur Proyek & Organisasi Modul
Repositori ini memiliki dua area utama. Area root berisi skrip operasional server: `setup.sh` (provisioning awal), `manage.sh` (menu harian), `run.sh` (bootstrap installer), `tc-limit.sh` (traffic shaping), dan `install-discord-bot.sh` (installer bot Discord). Area `bot-discord/` adalah stack bot standalone dengan `gateway-ts/` (UI Discord tombol/modal), `backend-py/` (API FastAPI per menu 1-9), `shared/` (kontrak action), `systemd/`, dan `scripts/`.

## Build, Test, dan Command Pengembangan
- `bash -n setup.sh manage.sh run.sh tc-limit.sh install-discord-bot.sh`: validasi syntax skrip shell.
- `shellcheck *.sh`: lint shell di root.
- `sudo bash run.sh`: instalasi cepat (pasang `manage` + `install-discord-bot` ke `/usr/local/bin` lalu jalankan setup).
- `sudo manage`: buka menu operasional utama.
- `sudo /usr/local/bin/install-discord-bot menu`: buka installer bot Discord.
- `python3 -m py_compile $(find bot-discord/backend-py/app -name '*.py')`: cek syntax backend bot.
- `cd bot-discord/gateway-ts && npm run build`: validasi build gateway TypeScript.

## Gaya Kode & Konvensi Penamaan
Gunakan Bash strict mode (`set -euo pipefail`) dan pola defensif yang sudah ada (`ok`, `warn`, `die`). Indentasi utama 2 spasi untuk shell. Nama fungsi `snake_case`, konstanta/env `UPPER_SNAKE_CASE`, nama skrip `kebab-case.sh`. Untuk Python/TypeScript bot, gunakan nama modul yang deskriptif per domain menu (`menu_1_status`, `menu_8_maintenance`, dst).

## Panduan Testing
Minimum sebelum merge: syntax check + lint shell + smoke check layanan terkait. Untuk perubahan runtime Xray, verifikasi `systemctl status xray xray-expired xray-quota xray-limit-ip xray-speed --no-pager` dan `xray run -test -confdir /usr/local/etc/xray/conf.d`. Untuk bot Discord, uji `backend-py` health endpoint dan alur `/panel` -> button -> modal di server Discord staging.

## Commit & Pull Request
Ikuti konvensi commit yang sudah dipakai: `feat`, `fix`, `docs`, `chore`, `refactor`, `style`, `security` (opsional dengan scope, contoh `feat(bot): ...`). PR wajib memuat ringkasan perubahan, risiko/rollback, command validasi yang dijalankan, serta bukti hasil (log/screenshot) untuk perubahan interaksi menu.

## Keamanan & Konfigurasi
Jangan commit token/secret/key. Simpan rahasia pada env file (contoh: `/etc/xray-discord-bot/bot.env`) dan gunakan masking saat ditampilkan. Semua skrip diasumsikan berjalan sebagai root; selalu uji dulu di VPS non-produksi sebelum rollout ke produksi.
