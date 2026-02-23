# Handoff Proyek

## Anchor Konteks (Wajib)
"oke saat ini kamu mengingatnya bahwa menggunakan repo superdecrypt-dev/autoscript"

Agent AI baru wajib memulai dari konteks di atas.

## Baseline Saat Ini
- Repo utama: `https://github.com/superdecrypt-dev/autoscript`
- Workspace aktif (Codex): `/codex/xray-core_discord` (rename folder lokal bisa berbeda per host)
- Source kerja installer `run.sh`: `/opt/autoscript`
- Deploy bot Discord: `/opt/bot-discord`

## Prinsip Operasional
- Gunakan `staging` untuk test/R&D.
- Production hanya untuk layanan live dan rollout setelah validasi.
- Bot Discord standalone; tidak mengeksekusi `manage.sh` langsung.

## Checklist Mulai Agent Baru
1. Baca `AGENTS.md`, `bot-discord/ARCHITECTURE_LOCK.md`, `RELEASE_NOTES.md`, `TESTING_PLAYBOOK.md`, dan file ini.
2. Konfirmasi ulang anchor konteks repo `superdecrypt-dev/autoscript`.
3. Jalankan cek awal: `git status`, lalu ringkas perubahan yang belum commit.
4. Lanjut pekerjaan berikutnya hanya setelah status baseline jelas.

## SOP Testing Wajib
- Semua pengujian shell script (`run.sh`, `setup.sh`, `manage.sh`, `install-discord-bot.sh`) dan bot Discord mengacu ke `TESTING_PLAYBOOK.md`.
- Jika ada konflik langkah uji antar dokumen, prioritaskan `TESTING_PLAYBOOK.md` lalu sinkronkan dokumen lain.

## Catatan Risiko Diterima
- Hardcoded Cloudflare token pada lokasi legacy diperlakukan sebagai accepted risk/by design, kecuali ada instruksi eksplisit untuk mengubah.
