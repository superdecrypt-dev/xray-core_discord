# Release Notes

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
