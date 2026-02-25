# Testing Playbook

Dokumen ini adalah SOP pengujian untuk proyek `autoscript` (anchor: "oke saat ini kamu mengingatnya bahwa menggunakan repo superdecrypt-dev/autoscript").

## 1. Prinsip Utama
- Wajib uji di `staging` terlebih dulu, baru `production`.
- Jangan lakukan perubahan live tanpa snapshot/rollback plan.
- Jangan commit token/secret; gunakan env file runtime.

## 2. Preflight
Jalankan sebelum semua paket uji:

```bash
AUTO_SCRIPT_ROOT="${AUTO_SCRIPT_ROOT:-/opt/autoscript}"
if [[ ! -d "${AUTO_SCRIPT_ROOT}" && -d /root/xray-core_discord ]]; then
  AUTO_SCRIPT_ROOT="/root/xray-core_discord"
fi
cd "${AUTO_SCRIPT_ROOT}"

git status --short
bash -n setup.sh manage.sh run.sh install-discord-bot.sh install-telegram-bot.sh
shellcheck *.sh
python3 -m py_compile $(find bot-discord/backend-py/app -name '*.py')
python3 -m py_compile $(find bot-telegram/backend-py/app -name '*.py') $(find bot-telegram/gateway-py/app -name '*.py')
(cd bot-discord/gateway-ts && npm run build)
bash bot-telegram/scripts/gate-all.sh
```

Kriteria lulus:
- Tidak ada syntax error.
- `shellcheck` tidak menghasilkan error kritikal.
- Build TypeScript dan compile Python sukses.

## 3. Pengujian 4 File Shell

### 3.1 Static & Lint
Sudah tercakup di bagian preflight.

### 3.2 Smoke (menu dasar)

```bash
printf "0\n" | timeout 20 bash manage.sh
bash install-discord-bot.sh status
printf "0\n" | timeout 20 bash install-discord-bot.sh menu
bash install-telegram-bot.sh status
printf "0\n" | timeout 20 bash install-telegram-bot.sh menu
```

Kriteria lulus:
- Menu bisa terbuka dan keluar normal via `0/back`.
- Command `status` berjalan tanpa crash.

### 3.3 Negative/Failure

Uji root guard:

```bash
setpriv --reuid 65534 --regid 65534 --clear-groups bash run.sh
setpriv --reuid 65534 --regid 65534 --clear-groups bash setup.sh
```

Kriteria lulus:
- Kedua script menolak eksekusi non-root dengan pesan error jelas.

Uji input invalid:

```bash
printf "xyz\n0\n" | timeout 20 bash manage.sh
printf "xyz\n0\n" | timeout 20 bash install-discord-bot.sh menu
printf "xyz\n0\n" | timeout 20 bash install-telegram-bot.sh menu
```

Kriteria lulus:
- Input invalid ditangani aman.
- Alur tetap bisa kembali ke menu/keluar.

### 3.4 Integration (staging)
Contoh pola (sesuaikan environment staging):

```bash
systemctl status xray xray-expired xray-quota xray-limit-ip xray-speed --no-pager
xray run -test -confdir /usr/local/etc/xray/conf.d
```

Kriteria lulus:
- Service utama aktif.
- Konfigurasi Xray valid.

Khusus runtime bot Telegram:

```bash
set -a; . /etc/xray-telegram-bot/bot.env; set +a
systemctl is-active xray-telegram-backend xray-telegram-gateway
/opt/bot-telegram/scripts/smoke-test.sh
```

Kriteria lulus:
- Service Telegram backend/gateway aktif.
- Smoke test Telegram PASS.

## 4. Pengujian Bot Discord

Gunakan harness resmi:

```bash
bot-discord/scripts/gate-all.sh local
bot-discord/scripts/gate-all.sh prod
bot-discord/scripts/gate-all.sh all
```

Catatan:
- `local` = Gate 1,2,3
- `prod` = Gate 3.1,5,6
- `all` = Gate 1-6 (Gate 4 via `STAGING_INSTANCE`)

### 4.1 Gate Wajib
1. Gate 1: Static & Build.
2. Gate 2: API Smoke (domain/service actions).
3. Gate 3/3.1: Integration endpoint + auth guard.
4. Gate 4: Negative/Failure (invalid param, unauthorized).
5. Gate 5: Discord E2E server-side check (`/panel` terdaftar).
6. Gate 6: Regression read-only menu 1-9.

### 4.2 E2E Manual di Discord (staging)
1. Jalankan `/panel`.
2. Klik beberapa button menu utama.
3. Jalankan modal input (misal domain/user action aman).
4. Pastikan response private dan tidak spam output panjang.
5. Pastikan tidak ada warning deprecate untuk opsi ephemeral lama.

### 4.3 Checklist Manual /panel (Rekomendasi Terbaru)
Gunakan checklist ini saat regresi fitur bot terbaru:

1. Menu `1) Status & Diagnostics`
- `View Status`
- `Run Xray Test`
- `View TLS Info`
- `Run Observe Snap`
- `View Observe Stat`
- `View Alert Log`

2. Menu `5) Domain Control`
- `View Domain Info`
- `Run Guard Check`
- `View Guard Stat`
- `Run Guard Renew`
- `View Nginx Name`
- `Refresh Accounts`

3. Menu `9) Traffic Analytics`
- `View Overview`
- `View Top Users` (isi limit)
- `Search User` (isi query)
- `Export JSON` (pastikan file attachment terkirim)

Kriteria lulus:
- Semua action mengembalikan respons dengan schema `ok/code/title/message`.
- Action export analytics menyertakan `download_file` valid.
- Tidak ada crash service gateway/backend selama uji.

### 4.4 Format Rekap PASS/FAIL Per Action
Contoh format ringkas:

```text
Tanggal:
Environment: staging
Checklist: /panel manual (menu 1, 5, 9)

1.overview: PASS
1.xray_test: PASS
...
9.export_json: PASS

Total PASS:
Total FAIL:
Catatan:
```

## 5. Checklist Rilis
Sebelum promote ke production:

1. Semua preflight PASS.
2. Smoke + negative 4 file shell PASS.
3. Gate bot Discord sesuai target PASS.
4. Gate bot Telegram (`bash bot-telegram/scripts/gate-all.sh`) PASS.
5. Smoke runtime Telegram (`/opt/bot-telegram/scripts/smoke-test.sh`) PASS.
6. Bukti uji tersimpan (log/screenshot ringkas).
7. Snapshot rollback tersedia.

## 6. Pengujian Bot Telegram

Gunakan harness resmi:

```bash
bash bot-telegram/scripts/gate-all.sh
```

Catatan:
- Endpoint `/health` backend Telegram sekarang wajib header secret internal.
- Action menu `4) Network Controls` wajib diuji untuk regresi WARP parity.

### 6.1 E2E Manual Telegram (staging)
1. Jalankan `/panel`.
2. Masuk `4) Network Controls`.
3. Uji action WARP:
   - `View WARP Status`
   - `Set WARP Global`
   - `Set WARP per User`
   - `Set WARP Inbound`
   - `Set WARP Domain`
   - `View WARP Tier`
4. Jalankan `/cleanup`.
5. Pastikan output tidak membocorkan token/secret/license dalam plain text.

### 6.2 Kriteria Lulus Telegram
- Semua action mengembalikan schema `ok/code/title/message`.
- Tidak ada crash service `xray-telegram-backend` dan `xray-telegram-gateway`.
- ACL admin berjalan sesuai env (`TELEGRAM_ADMIN_*`).

## 7. Format Laporan Singkat
Gunakan format ini setelah pengujian:

```text
Tanggal:
Environment: staging / production
Commit:

Shell:
- Static/Lint: PASS/FAIL
- Smoke: PASS/FAIL
- Negative: PASS/FAIL
- Integration: PASS/FAIL

Bot Discord:
- Gate 1: PASS/FAIL
- Gate 2: PASS/FAIL
- Gate 3/3.1: PASS/FAIL
- Gate 4: PASS/FAIL
- Gate 5: PASS/FAIL
- Gate 6: PASS/FAIL

Bot Telegram:
- Gate all: PASS/FAIL
- Smoke runtime: PASS/FAIL
- E2E menu 4 WARP: PASS/FAIL

Catatan risiko:
Keputusan lanjut:
```
