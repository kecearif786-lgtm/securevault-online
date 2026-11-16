# SecureVault Online

Aplikasi demonstrasi pesan online berbasis Flask + MySQL. Pesan dienkripsi di browser sebelum dikirim; server menyimpan paket ciphertext dan metadata.

## Fitur
- Registrasi, login, logout dengan password hash.
- Dashboard, inbox, pesan terkirim, detail pesan.
- Pengiriman pesan terenkripsi AES-256-GCM (Web Crypto API).
- PBKDF2-SHA256 untuk menurunkan kunci dari passphrase bersama.
- Pemeriksaan tanda tangan Dissanayake sebagai demonstrasi akademik.

## Catatan keamanan penting
Versi ini adalah prototipe akademik, bukan aplikasi untuk rahasia sungguhan. Untuk demo, pengirim dan penerima harus menyepakati passphrase pesan melalui saluran lain. Jangan memakai password akun sebagai passphrase pesan. Implementasi Dissanayake yang diwarisi dari proyek awal menggunakan parameter yang tidak memadai dan belum diaudit; tanda tangan ini bukan bukti identitas pengirim karena kunci publik ikut dikirim bersama pesan. Jangan mengklaim sistem sudah aman untuk produksi. Sistem produksi membutuhkan desain pertukaran kunci, autentikasi kunci publik, HTTPS, proteksi CSRF/rate limit, pengelolaan kunci yang diaudit, dan review kriptografi independen.

## Instalasi lokal
1. Pasang Python 3.10+ dan MySQL.
2. Buat database dengan menjalankan `schema.sql` di MySQL.
3. Salin `.env.example` menjadi `.env`, lalu isi koneksi database dan SECRET_KEY.
4. Instal dependensi: `pip install -r requirements.txt`
5. Jalankan: `python app.py`
6. Buka `http://127.0.0.1:5000`.

## GitHub dari HP
1. Buka GitHub dan login.
2. Tekan **New repository**, beri nama `securevault-online`.
3. Pilih **Private** dan buat repository.
4. Pilih **Add file > Upload files**.
5. Unggah isi folder proyek (jangan unggah `.env`).
6. Tekan **Commit changes**.

## Hosting
Aplikasi ini belum otomatis online hanya karena diunggah ke GitHub. Untuk dipakai dari perangkat berbeda, deploy ke layanan hosting yang mendukung Flask dan MySQL, atur environment variables, aktifkan HTTPS, dan set `COOKIE_SECURE=1`.
