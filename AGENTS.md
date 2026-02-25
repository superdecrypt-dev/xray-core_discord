# Repository Guidelines

## Identitas Proyek (Terkini)
- Nama proyek/repo aktif: `autoscript`
- Remote utama: `https://github.com/superdecrypt-dev/autoscript`
- Source kerja installer `run.sh` di VPS: `/opt/autoscript` (alias kompatibilitas lama: `/root/xray-core_discord`)
- Deploy bot Discord tetap: `/opt/bot-discord`

## Struktur Proyek & Organisasi Modul
Repositori ini memiliki dua area utama. Area root berisi skrip operasional server: `setup.sh` (provisioning awal), `manage.sh` (menu harian), `run.sh` (bootstrap installer), dan `install-discord-bot.sh` (installer bot Discord). Area `bot-discord/` adalah stack bot standalone dengan `gateway-ts/` (UI Discord tombol/modal), `backend-py/` (API FastAPI per menu 1-8 dan 12), `shared/` (kontrak action), `systemd/`, dan `scripts/`.

## Build, Test, dan Command Pengembangan
- `bash -n setup.sh manage.sh run.sh install-discord-bot.sh`: validasi syntax skrip shell.
- `shellcheck *.sh`: lint shell di root.
- `sudo bash run.sh`: instalasi cepat (pasang `manage` + `install-discord-bot` ke `/usr/local/bin` lalu jalankan setup).
- `sudo manage`: buka menu operasional utama.
- `sudo /usr/local/bin/install-discord-bot menu`: buka installer bot Discord.
- `python3 -m py_compile $(find bot-discord/backend-py/app -name '*.py')`: cek syntax backend bot.
- `cd bot-discord/gateway-ts && npm run build`: validasi build gateway TypeScript.
- `TESTING_PLAYBOOK.md`: SOP pengujian lengkap untuk shell script + bot Discord (preflight, smoke, negative, integration, gate).

## Gaya Kode & Konvensi Penamaan
Gunakan Bash strict mode (`set -euo pipefail`) dan pola defensif yang sudah ada (`ok`, `warn`, `die`). Indentasi utama 2 spasi untuk shell. Nama fungsi `snake_case`, konstanta/env `UPPER_SNAKE_CASE`, nama skrip `kebab-case.sh`. Untuk Python/TypeScript bot, gunakan nama modul yang deskriptif per domain menu (`menu_1_status`, `menu_8_maintenance`, dst).

## Panduan Testing
Minimum sebelum merge: syntax check + lint shell + smoke check layanan terkait. Untuk perubahan runtime Xray, verifikasi `systemctl status xray xray-expired xray-quota xray-limit-ip xray-speed --no-pager` dan `xray run -test -confdir /usr/local/etc/xray/conf.d`. Untuk bot Discord, uji `backend-py` health endpoint dan alur `/panel` -> button -> modal di server Discord staging.
Gunakan `TESTING_PLAYBOOK.md` sebagai sumber langkah testing yang baku sebelum rilis.

## Environment Separation (Wajib)
Gunakan pemisahan environment agar perubahan aman:
- `Staging environment`: khusus test/R&D, validasi gate, smoke, failure, dan eksperimen.
- `Production environment`: khusus layanan running/live user.
- Alur rilis wajib: uji di staging dulu, baru promote ke production.
- Selalu siapkan snapshot/rollback sebelum perubahan besar di production.

## Commit & Pull Request
Ikuti konvensi commit yang sudah dipakai: `feat`, `fix`, `docs`, `chore`, `refactor`, `style`, `security` (opsional dengan scope, contoh `feat(bot): ...`). PR wajib memuat ringkasan perubahan, risiko/rollback, command validasi yang dijalankan, serta bukti hasil (log/screenshot) untuk perubahan interaksi menu.

## Keamanan & Konfigurasi
Jangan commit token/secret/key. Simpan rahasia pada env file (contoh: `/etc/xray-discord-bot/bot.env`) dan gunakan masking saat ditampilkan. Semua skrip diasumsikan berjalan sebagai root; selalu uji dulu di VPS non-produksi sebelum rollout ke produksi.
Standar OAuth2 invite bot Discord: gunakan scope `bot` + `applications.commands`, dengan permissions minimum `View Channels`, `Send Messages`, `Embed Links`, `Read Message History` (permission integer `84992`). Hindari permission `Administrator`; tambahkan `Attach Files` hanya jika fitur kirim file log memang dipakai.
Catatan khusus proyek ini: temuan hardcoded Cloudflare token pada lokasi legacy tertentu diperlakukan sebagai by design (accepted risk) dan diabaikan dalam review rutin, kecuali ada instruksi eksplisit untuk mengubahnya.

## Catatan Handoff (Ringkas)
- Bot Discord dijaga standalone dan tidak mengeksekusi `manage.sh` secara langsung.
- Bot Discord diposisikan sebagai pelengkap CLI `manage.sh`, bukan pengganti penuh alur CLI.
- Target UX bot: profesional, minim teks tidak perlu, dan anti-spam output panjang.
- Update gateway terbaru memakai `flags: MessageFlags.Ephemeral` (bukan `ephemeral: true`).
- Rilis dilakukan lewat staging terlebih dulu; production hanya setelah validasi gate/smoke selesai.
- SOP validasi lintas shell+bot terpusat di `TESTING_PLAYBOOK.md`.

## Aktivitas Terkini (Update 2026-02-25)
- Fokus sprint terbaru: sinkronisasi UX bot Discord dengan CLI `manage.sh` + stabilisasi staging.
- Perubahan besar yang sudah dilalui:
  - Konsistensi select mode untuk alur yang butuh pilihan (protocol/user/action tertentu).
  - `Add User` dan `Account Info` menampilkan ringkasan embed + lampiran file TXT akun.
  - Domain Control disederhanakan (`Set Domain Manual` dan `Set Domain Auto`) + root domain Cloudflare via select.
  - Speedtest output diringkas (ISP, latency, packet loss, download, upload).
  - Fitur baru shell+bot:
    - Observability & Alerting
    - Domain & Cert Guard
    - `12) Traffic Analytics`
  - Label tombol menu bot diseragamkan dengan pola `View/Run/Set/Toggle`.
- Commit bot terbaru yang sudah di-push: `fec6834` (`feat(bot): add menu 12 analytics and observability/domain-guard controls`).
- Validasi staging terbaru untuk menu `/panel` yang diuji (menu 1, 5, 12): seluruh action checklist PASS.
- Catatan workspace saat handoff ini ditulis:
  - Perubahan bot sudah tercatat commit.
  - `manage.sh` dan `setup.sh` masih memiliki perubahan lokal terpisah; jangan di-reset tanpa instruksi owner.

## Checklist Agent Baru (Praktis)
1. Jalankan `git status --short` untuk cek perubahan lokal sebelum mulai.
2. Baca `HANDOFF.md` bagian "Status Operasional Terkini".
3. Validasi cepat bot:
   - `python3 -m py_compile $(find bot-discord/backend-py/app -name '*.py')`
   - `cd bot-discord/gateway-ts && npm run build`
4. Uji staging sebelum perubahan baru:
   - `bot-discord/scripts/gate-all.sh local`
   - lanjut E2E manual `/panel` sesuai `TESTING_PLAYBOOK.md`.

## Kalimat Anchor Owner (Wajib Lanjutkan Dari Sini)
- Kalimat referensi wajib: "oke saat ini kamu mengingatnya bahwa menggunakan repo superdecrypt-dev/autoscript".
- Semua agent baru harus menganggap kalimat di atas sebagai baseline konteks proyek.
