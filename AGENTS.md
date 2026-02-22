# Repository Guidelines

## Project Structure & Module Organization
Repositori ini sengaja berbentuk flat (berbasis skrip di root). `setup.sh` menangani provisioning one-time server, `manage.sh` untuk operasi harian melalui menu, `run.sh` sebagai bootstrap installer cepat, dan `tc-limit.sh` sebagai helper traffic shaping berbasis `tc`. `README.md` berisi alur operator dan ringkasan fitur. Jika menambah file baru, pertahankan pemisahan ini: provisioning di `setup.sh`, operasi runtime di `manage.sh`, utilitas terpisah di skrip sendiri.

## Build, Test, and Development Commands
- `bash -n setup.sh manage.sh run.sh tc-limit.sh`: cek syntax Bash tanpa eksekusi.
- `shellcheck *.sh`: lint statis (direkomendasikan sebelum PR).
- `sudo bash run.sh`: bootstrap penuh (clone repo, pasang `manage`, jalankan setup).
- `sudo bash setup.sh`: provisioning langsung tanpa bootstrap.
- `sudo manage`: buka menu operasi harian.
- `sudo xray run -test -confdir /usr/local/etc/xray/conf.d`: validasi konfigurasi Xray setelah perubahan.

## Coding Style & Naming Conventions
Gunakan Bash strict mode (`set -euo pipefail`) dan pertahankan gaya defensif yang sudah ada. Indentasi utama 2 spasi. Nama fungsi gunakan `snake_case`, konstanta dan environment variable gunakan `UPPER_SNAKE_CASE`, dan nama file skrip gunakan pola `kebab-case.sh`. Selalu quote ekspansi variabel, gunakan `local` di fungsi, dan konsolidasikan output status melalui helper seperti `ok`, `warn`, dan `die`.

## Testing Guidelines
Belum ada framework test terpisah di repo ini. Minimum validasi sebelum merge: syntax check + `shellcheck` + smoke test di VPS Debian/Ubuntu disposable. Untuk perubahan runtime, verifikasi `systemctl status xray xray-expired xray-quota xray-limit-ip xray-speed --no-pager` dan ulangi test config Xray. Jika menambah skrip test, gunakan pola nama `test_<area>.sh`.

## Commit & Pull Request Guidelines
Ikuti gaya commit yang sudah terlihat di histori: `feat`, `fix`, `docs`, `chore`, `refactor`, `style`, `security` (opsional dengan scope, mis. `fix(manage): ...`). Subjek commit harus ringkas dan fokus satu perubahan. PR wajib berisi ringkasan tujuan, risiko/rollback, daftar command validasi yang dijalankan, serta cuplikan output/screenshot bila ada perubahan perilaku menu.

## Security & Configuration Tips
Jangan commit token, private key, atau domain sensitif. Gunakan environment variable (contoh: `CLOUDFLARE_API_TOKEN`) dan redaksi nilai pada dokumentasi/log. Semua skrip diasumsikan berjalan sebagai root; uji dulu di environment non-produksi sebelum diterapkan ke VPS produksi.
