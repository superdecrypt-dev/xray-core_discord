# Handoff Proyek

## Anchor Konteks (Wajib)
"oke saat ini kamu mengingatnya bahwa menggunakan repo superdecrypt-dev/autoscript"

Agent AI baru wajib memulai dari konteks di atas.

## Baseline Saat Ini
- Repo utama: `https://github.com/superdecrypt-dev/autoscript`
- Workspace aktif (Codex): `/codex/autoscript` (rename folder lokal bisa berbeda per host)
- Source kerja installer `run.sh`: `/opt/autoscript` (alias kompatibilitas lama: `/root/xray-core_discord`)
- Deploy bot Discord: `/opt/bot-discord`

## Status Operasional Terkini (2026-02-25)
- Environment staging aktif untuk bot: `xray-stg-gate3-1771864485`.
- Layanan bot staging terakhir terverifikasi:
  - `xray-discord-backend`: active
  - `xray-discord-gateway`: active
- Jalur validasi terakhir yang dilalui:
  - patch backend+gateway untuk Observability, Domain Guard, dan menu `12) Traffic Analytics`.
  - harmonisasi label tombol UI agar konsisten (`View/Run/Set/Toggle`).
  - E2E checklist `/panel` untuk menu `1`, `5`, dan `12` dinyatakan PASS.
- Commit bot terbaru yang sudah dipush ke `main`: `fec6834`.

## Riwayat Aktivitas Yang Sudah Dilalui (Ringkas)
1. Penyelarasan UX select mode untuk protocol/user agar minim typo.
2. Revisi output `Add User`/`Account Info` menjadi ringkas + lampiran file akun.
3. Penyederhanaan Domain Control (`Manual` vs `Auto`) termasuk root domain select.
4. Penambahan fitur:
   - Observability & Alerting
   - Domain & Cert Guard
   - Traffic Analytics (menu 12)
5. Pengujian bertahap:
   - contract test
   - fault injection
   - staging E2E
   - soak test singkat
6. Re-run manual checklist `/panel` untuk menu 1/5/12 dengan hasil PASS per action.

## Catatan Working Tree Saat Handoff
- Perubahan bot sudah ter-commit dan ter-push.
- `manage.sh` dan `setup.sh` masih ada modifikasi lokal terpisah (belum termasuk commit bot terbaru).
- Jangan lakukan reset hard/revert massal tanpa instruksi owner.

## Prinsip Operasional
- Gunakan `staging` untuk test/R&D.
- Production hanya untuk layanan live dan rollout setelah validasi.
- Bot Discord standalone; tidak mengeksekusi `manage.sh` langsung.
- Bot Discord berfungsi sebagai pelengkap CLI `manage.sh`, bukan pengganti penuh operasi CLI.

## Checklist Mulai Agent Baru
1. Baca `AGENTS.md`, `bot-discord/ARCHITECTURE_LOCK.md`, `RELEASE_NOTES.md`, `TESTING_PLAYBOOK.md`, dan file ini.
2. Konfirmasi ulang anchor konteks repo `superdecrypt-dev/autoscript`.
3. Jalankan cek awal: `git status`, lalu ringkas perubahan yang belum commit.
4. Verifikasi service staging bot:
   - `lxc exec xray-stg-gate3-1771864485 -- systemctl is-active xray-discord-backend xray-discord-gateway`
5. Lanjut pekerjaan berikutnya hanya setelah status baseline jelas.

## Command Cepat Lanjutan Agent
- Validasi bot lokal:
  - `python3 -m py_compile $(find bot-discord/backend-py/app -name '*.py')`
  - `cd bot-discord/gateway-ts && npm run build`
- Gate test:
  - `bot-discord/scripts/gate-all.sh local`
- Smoke action staging (backend):
  - `POST /api/menu/1/action` (`observe_status`)
  - `POST /api/menu/5/action` (`domain_guard_status`)
  - `POST /api/menu/12/action` (`overview`)

## SOP Testing Wajib
- Semua pengujian shell script (`run.sh`, `setup.sh`, `manage.sh`, `install-discord-bot.sh`) dan bot Discord mengacu ke `TESTING_PLAYBOOK.md`.
- Jika ada konflik langkah uji antar dokumen, prioritaskan `TESTING_PLAYBOOK.md` lalu sinkronkan dokumen lain.

## Catatan Risiko Diterima
- Hardcoded Cloudflare token pada lokasi legacy diperlakukan sebagai accepted risk/by design, kecuali ada instruksi eksplisit untuk mengubah.
