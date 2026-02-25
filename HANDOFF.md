# Handoff Proyek

## Anchor Konteks (Wajib)
"oke saat ini kamu mengingatnya bahwa menggunakan repo superdecrypt-dev/autoscript"

Agent AI baru wajib memulai dari konteks di atas.

## Baseline Saat Ini
- Repo utama: `https://github.com/superdecrypt-dev/autoscript`
- Workspace aktif (Codex): `/codex/autoscript`
- Source kerja installer `run.sh`: `/opt/autoscript` (alias kompatibilitas lama: `/root/xray-core_discord`)
- Deploy bot Discord: `/opt/bot-discord`
- Deploy bot Telegram: `/opt/bot-telegram`

## Status Operasional Terkini (2026-02-25)
- Commit terbaru di `main`:
  - `b86e6d8` — `feat(bot-telegram): polish panel flows and add user speed-limit fields`
  - `8bcf1d4` — `fix(xray): remove xhttp transport from setup, manage, and bot links`
- Perubahan penting terbaru:
  - UX bot Telegram dipoles (flow panel, picker user delete, cleanup, Add User speed limit).
  - Transport `xhttp` dihapus dari template `setup.sh`, generator `manage.sh`, dan backend bot Discord/Telegram.
  - Menu CLI sekarang menampilkan `10) Traffic Analytics` dan `11) Install BOT Telegram` (input `12` tetap kompatibel ke Traffic Analytics).
- Validasi runtime terakhir setelah patch `xhttp`:
  - `xray run -test -confdir /usr/local/etc/xray/conf.d` -> `Configuration OK`
  - `nginx -t` -> valid
  - `systemctl is-active xray nginx` -> `active`

## Riwayat Aktivitas Yang Sudah Dilalui (Ringkas)
1. Sinkronisasi UX bot agar alur pilih protocol/user minim typo.
2. Perapihan output `Add User` / `Account Info` menjadi ringkas + lampiran file akun.
3. Penyederhanaan Domain Control (`Manual` vs `Auto`) dengan root domain select.
4. Penambahan Observability + Domain Guard + Traffic Analytics.
5. Penambahan installer Telegram (`install-telegram-bot.sh`) sebagai pelengkap menu CLI.
6. Penghapusan `xhttp` untuk menstabilkan skenario domain fronting.

## Catatan Working Tree Saat Handoff
- Working tree saat ini clean (`git status --short` kosong).
- Perubahan utama sudah commit + push ke `main`.

## Prinsip Operasional
- Gunakan `staging` untuk test/R&D; production hanya setelah validasi.
- Bot Discord dan Telegram harus tetap standalone (tidak mengeksekusi `manage.sh` langsung).
- Kedua bot diposisikan sebagai pelengkap CLI `manage.sh`, bukan pengganti penuh.

## Checklist Mulai Agent Baru
1. Baca `AGENTS.md`, `RELEASE_NOTES.md`, `TESTING_PLAYBOOK.md`, dan file ini.
2. Konfirmasi anchor konteks repo `superdecrypt-dev/autoscript`.
3. Jalankan `git status --short` dan pastikan baseline jelas.
4. Validasi minimum sebelum perubahan lanjutan:
   - `bash -n setup.sh manage.sh run.sh install-discord-bot.sh install-telegram-bot.sh`
   - `shellcheck setup.sh manage.sh`
   - `python3 -m py_compile $(find bot-discord/backend-py/app -name '*.py')`
   - `python3 -m py_compile $(find bot-telegram/backend-py/app -name '*.py')`
5. Jika menyentuh runtime Xray/Nginx, wajib cek:
   - `xray run -test -confdir /usr/local/etc/xray/conf.d`
   - `nginx -t`
   - `systemctl is-active xray nginx`

## Command Cepat Lanjutan Agent
- Gate bot Discord:
  - `bot-discord/scripts/gate-all.sh local`
- Build gateway Discord:
  - `cd bot-discord/gateway-ts && npm run build`
- Cek service bot (sesuaikan environment):
  - Discord: `systemctl is-active xray-discord-backend xray-discord-gateway`
  - Telegram: `systemctl is-active xray-telegram-backend xray-telegram-gateway`

## SOP Testing Wajib
- Semua pengujian shell script (`run.sh`, `setup.sh`, `manage.sh`, installer bot) dan bot mengacu ke `TESTING_PLAYBOOK.md`.
- Jika ada konflik langkah uji antar dokumen, prioritaskan `TESTING_PLAYBOOK.md` lalu sinkronkan dokumen lain.

## Catatan Risiko Diterima
- Hardcoded Cloudflare token pada lokasi legacy diperlakukan sebagai accepted risk/by design, kecuali ada instruksi eksplisit untuk mengubah.
