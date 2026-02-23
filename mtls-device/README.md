# mTLS Device Mode (Terpisah dari setup/manage)

Dokumen ini menjelaskan implementasi mTLS per-device **tanpa mengubah** `setup.sh`, `manage.sh`, atau alur installer utama.

## Tujuan
- Mewajibkan client membawa sertifikat device saat konek.
- Menolak koneksi jika sertifikat client tidak valid.
- Tetap kompatibel dengan arsitektur saat ini: TLS terminate di Nginx, Xray inbound internal tetap non-TLS.

## Arsitektur yang Disarankan
1. Client konek ke Nginx (443) + kirim client certificate.
2. Nginx verifikasi cert client terhadap CA internal.
3. Jika valid, request diteruskan ke inbound Xray internal (`127.0.0.1`).
4. Jika tidak valid, Nginx return `403`.

## Catatan Soal "1 Device Only"
mTLS kuat untuk autentikasi cert, tetapi tidak otomatis "anti-copy cert".
- Jika cert+key dicopy ke perangkat lain, perangkat lain bisa lolos.
- Untuk memperketat: gunakan keystore non-exportable (Android Keystore / iOS Secure Enclave), sertifikat berumur pendek, dan rotasi/revoke rutin.

## Langkah Manual Singkat
1. Buat CA internal.
2. Issue sertifikat per device/user.
3. Pasang CA cert di server Nginx.
4. Aktifkan `ssl_verify_client on;`.
5. Reload Nginx dan uji koneksi dengan/ tanpa cert.

## Perintah Uji
Tanpa cert (harus gagal):
```bash
curl -vk https://your-domain.example/vless-ws
```

Dengan cert (harus lolos TLS client auth):
```bash
curl -vk https://your-domain.example/vless-ws \
  --cert client.crt --key client.key
```
