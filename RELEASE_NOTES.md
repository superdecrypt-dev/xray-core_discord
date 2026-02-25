# Release Notes

## Rilis 2026-02-25 (Update Malam)

### Ringkasan
Update ini menutup dua pekerjaan besar: penyempurnaan UX bot Telegram untuk operasi harian, dan penghapusan transport `xhttp` dari stack default karena tidak stabil untuk mode domain fronting.

### Perubahan Utama
1. Bot Telegram: UX flow dipoles untuk operasional nyata
- Perbaikan alur panel interaktif (button/select/manual fallback) agar input minim typo.
- `Add User` sekarang mendukung speed limit saat create akun:
  - `speed_limit_enabled`
  - `speed_down_mbit`
  - `speed_up_mbit`
- `Delete User` memakai picker protocol + daftar username, jadi admin tidak perlu mengetik username manual.
- `/cleanup` diperbarui agar mode default membersihkan chat dan menyisakan 1 pesan hasil cleanup.

2. Penghapusan Transport `xhttp` dari Stack Default
- `setup.sh`:
  - inbound `xhttp` dihapus dari template Xray
  - route/mapping/location `xhttp` di template Nginx dihapus
- `manage.sh`:
  - generator link account tidak lagi membuat link `xhttp`
  - compat checker account info diperbarui (basis validasi ke baris `gRPC`)
- Bot backend (`bot-discord` + `bot-telegram`):
  - generator link account tidak lagi memasukkan `xhttp`
  - output account info tidak lagi menampilkan baris `XHTTP`
- `opt/manage/features/network.sh`:
  - deteksi tag default Xray disesuaikan tanpa suffix `-xhttp`

3. Sinkronisasi Runtime Live
- Konfigurasi runtime ikut dibersihkan:
  - `/usr/local/etc/xray/conf.d/10-inbounds.json`
  - `/etc/nginx/conf.d/xray.conf`
- Validasi runtime setelah patch:
  - `xray run -test -confdir /usr/local/etc/xray/conf.d` -> `Configuration OK`
  - `nginx -t` -> syntax valid
  - `systemctl is-active xray nginx` -> `active`

### Commit
- `b86e6d8` — `feat(bot-telegram): polish panel flows and add user speed-limit fields`
- `8bcf1d4` — `fix(xray): remove xhttp transport from setup, manage, and bot links`

### Hasil Validasi
- Shell:
  - `bash -n setup.sh manage.sh run.sh install-discord-bot.sh` -> PASS
  - `shellcheck setup.sh manage.sh opt/manage/features/network.sh` -> PASS
- Python:
  - `python3 -m py_compile $(find bot-discord/backend-py/app -name '*.py') $(find bot-telegram/backend-py/app -name '*.py')` -> PASS
- Runtime:
  - `xray run -test -confdir /usr/local/etc/xray/conf.d` -> PASS
  - `nginx -t` -> PASS

## Rilis 2026-02-25

### Ringkasan
Rilis ini memfinalkan integrasi fitur baru bot Discord untuk operasional staging, sekaligus menyiapkan dokumentasi handoff agar agent berikutnya dapat melanjutkan aktivitas tanpa kehilangan konteks.

### Perubahan Utama
1. Integrasi Fitur Bot (menu 1, 5, 12)
- Menu `1) Status & Diagnostics` ditambah action:
  - `observe_snapshot`
  - `observe_status`
  - `observe_alert_log`
- Menu `5) Domain Control` ditambah action:
  - `domain_guard_check`
  - `domain_guard_status`
  - `domain_guard_renew`
- Menu baru `12) Traffic Analytics`:
  - `overview`
  - `top_users`
  - `search_user`
  - `export_json` (attachment file JSON)

2. Standardisasi Label UX Bot
- Label tombol pada menu gateway diseragamkan dengan pola:
  - `View ...`
  - `Run ...`
  - `Set ...`
  - `Toggle ...`
- Sinkronisasi label juga diterapkan ke `shared/commands.json`.

3. Penguatan Gate Testing Bot
- `bot-discord/scripts/gate-all.sh` diperbarui agar:
  - mengenali kehadiran menu `12`
  - menambah smoke check `observe_status` dan `menu12.overview`
  - memperluas regression read-only smoke hingga menu `12`.

4. Dokumentasi Continuity Agent
- Dokumen handoff/arsitektur/testing/release diperbarui dengan status aktivitas terbaru, ringkasan jalur uji, dan panduan kelanjutan untuk agent baru.

### Commit
- Commit ter-push: `fec6834`
- Pesan: `feat(bot): add menu 12 analytics and observability/domain-guard controls`

### Hasil Validasi
- Validasi lokal:
  - `python3 -m py_compile $(find bot-discord/backend-py/app -name '*.py')` -> PASS
  - `(cd bot-discord/gateway-ts && npm run build)` -> PASS
  - `bash -n bot-discord/scripts/gate-all.sh` -> PASS
- Validasi staging:
  - service `xray-discord-backend` dan `xray-discord-gateway` -> active
  - checklist action `/panel` untuk menu `1`, `5`, `12` -> PASS semua (18/18 action).

## Rilis 2026-02-24

### Ringkasan
Rilis ini memfokuskan finalisasi bot Discord untuk penggunaan produksi dan hardening operasional shell di staging: konsistensi mode select, output hasil yang lebih ringkas, sinkronisasi domain control, serta penguatan runtime quota watcher.

### Perubahan Utama
1. Konsistensi UX Select di Bot Discord
- Alur yang membutuhkan pemilihan protokol/user dipindahkan ke mode select agar minim typo.
- Alur ini mencakup `Add User`, `Extend/Set Expiry`, `Account Info`, dan aksi select-based di `Network Controls`.

2. Output User Management Lebih Ringkas
- `Add User` sukses kini menampilkan embed ringkasan + lampiran `username@protokol.txt`.
- `Account Info` menampilkan embed ringkasan + lampiran `username@protokol.txt`.
- `Account Info` ditingkatkan dengan fallback summary dari file account ketika file quota tidak tersedia.

3. Penyederhanaan Domain Control
- Nama aksi diperjelas menjadi:
  - `Set Domain Manual`
  - `Set Domain Auto (API Cloudflare)`
- Root domain Cloudflare dipilih via select (`vyxara1.web.id`, `vyxara2.web.id`, `vyxara1.qzz.io`, `vyxara2.qzz.io`).
- Perilaku boolean invalid di wizard Cloudflare tidak lagi silent: tetap fallback aman, tetapi sekarang memberi warning eksplisit.

4. Hardening Shell Runtime & Staging
- `run.sh` menambah kompatibilitas path canonical `/opt/autoscript` dengan alias legacy `/root/xray-core_discord`.
- `install-discord-bot.sh` merapikan source archive URL agar konsisten memakai `BOT_SOURCE_OWNER/BOT_SOURCE_REPO/BOT_SOURCE_REF`.
- Generator `xray-quota` di `setup.sh` sekarang mendukung fallback endpoint API (`127.0.0.1:10080` dan `127.0.0.1:10085`) untuk mengurangi warning transien `statsquery`.

### Hasil Validasi
- Validasi lokal:
  - `bash -n setup.sh manage.sh run.sh install-discord-bot.sh` -> PASS
  - `python3 -m py_compile $(find bot-discord/backend-py/app -name '*.py')` -> PASS
  - `(cd bot-discord/gateway-ts && npm run build)` -> PASS
  - `bot-discord/scripts/gate-all.sh local` -> PASS
- Validasi staging (24 Februari 2026):
  - smoke + negative untuk `manage.sh`/`install-discord-bot.sh` -> PASS
  - `xray run -test -confdir /usr/local/etc/xray/conf.d` -> `Configuration OK`
  - setelah update `xray-quota`, audit `journalctl -u xray-quota -p warning` pada window uji tidak menemukan warning baru.

## Update Handoff 2026-02-23

### Ringkasan
Update ini mencatat perubahan identitas proyek ke `autoscript`, pembaruan source path installer, dan perapihan UX bot Discord agar lebih profesional dan minim spam output.

### Perubahan Utama
1. Rebranding Proyek ke Autoscript
- Remote/identitas repo dipindah ke `superdecrypt-dev/autoscript`.
- Referensi URL source pada `run.sh`, `install-discord-bot.sh`, dan `README.md` disesuaikan.

2. Perubahan Source Working Directory Installer
- `run.sh` kini memakai source kerja persist di `/opt/autoscript`.
- Pola clone/update source diperbarui untuk mode deploy server yang lebih konsisten.

3. Perapihan UX Bot Discord
- Gateway interaction memakai `flags: MessageFlags.Ephemeral` (mengganti opsi lama yang deprecated).
- Output result dipotong agar tidak spam panjang di Discord mobile.
- Copywriting menu/error dipoles agar lebih profesional dan ringkas.

4. Dokumentasi SOP Testing
- Ditambahkan `TESTING_PLAYBOOK.md` sebagai panduan tunggal pengujian:
  preflight, smoke, negative/failure, integration, dan gate bot Discord.
- Dokumen ini dijadikan referensi utama untuk proses handoff agent baru.

### Validasi Tambahan
- `bash -n run.sh install-discord-bot.sh`: PASS.
- Build gateway TypeScript: PASS.
- Gate staging yang terakhir dijalankan:
  - Gate 4 (Negative/Failure): PASS
  - Gate 5 (Discord command check): PASS
  - Gate 6 (Regression read-only menu smoke): PASS

### Catatan Operasional
- Baseline handoff saat ini mengacu pada repo `autoscript`.
- Deploy bot tetap di `/opt/bot-discord`; env di `/etc/xray-discord-bot/bot.env`.

## Rilis 2026-02-23

### Ringkasan
Rilis ini memfinalkan paket stabilisasi bot Discord standalone dan alur operasional installer. Fokus utama: penguatan keamanan token, rollback safety, otomasi pengujian gate, dan monitoring runtime ringan.

### Perubahan Utama
1. Rotasi Token Discord (Security)
- Token bot produksi telah diganti (regenerate) dan diverifikasi aktif.
- Ditambahkan script rotasi aman: `bot-discord/scripts/rotate-discord-token.sh`.
- Token tetap disimpan di env file deploy: `/etc/xray-discord-bot/bot.env`.

2. Snapshot Rollback
- Snapshot pra-perubahan dibuat untuk rollback cepat:
  `xray-itg-1771777921/pre-gate123-20260224-011832`.

3. Otomasi Pengujian Gate
- Ditambahkan script orkestrasi test gate:
  `bot-discord/scripts/gate-all.sh`.
- Profil yang tersedia:
  - `local` -> Gate 1,2,3
  - `prod` -> Gate 3.1,5,6
  - `all` -> Gate 1-6 (Gate 4 via `STAGING_INSTANCE`)

4. Monitoring Ringan
- Ditambahkan health monitor:
  `bot-discord/scripts/monitor-lite.sh`.
- Ditambahkan unit systemd:
  - `xray-discord-monitor.service`
  - `xray-discord-monitor.timer` (interval 5 menit)
- Log monitor:
  `/var/log/xray-discord-bot/monitor-lite.log`.

### Hasil Validasi
- `bash -n` dan `shellcheck` untuk script terkait: lulus.
- Gate produksi (`gate-all.sh prod`) pada 2026-02-23:
  - Gate 3.1: PASS
  - Gate 5: PASS
  - Gate 6: PASS
- Status runtime produksi:
  - `xray-discord-backend`: active
  - `xray-discord-gateway`: active
  - `xray-discord-monitor.timer`: active

### Risiko Diketahui (Accepted Risk)
- Hardcoded Cloudflare token di lokasi legacy diperlakukan sebagai by design/accepted risk sesuai kebijakan proyek saat ini.
- Logika penghapusan A record lain pada IP yang sama tetap dipertahankan sesuai desain operasional.

### Catatan Operasional
- Lokasi deploy bot: `/opt/bot-discord`.
- Installer: `/usr/local/bin/install-discord-bot`.
- Untuk rollback darurat, gunakan snapshot LXC yang disebutkan pada bagian Snapshot Rollback.
