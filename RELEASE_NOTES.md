# Release Notes

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
