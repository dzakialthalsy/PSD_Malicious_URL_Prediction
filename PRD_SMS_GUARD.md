# PRD — SMS Guard: Pelindung dari Link Penipuan di SMS

**Versi:** 0.1 (draft untuk Booth Lab SI × Telkomsel)
**Tanggal:** 15 Juni 2026
**Acara:** Booth Lab SI, Auditorium G2 FILKOM — 18 Juni 2026
**Status:** Prototipe / Proof of Concept

---

## 1. Ringkasan eksekutif

**SMS Guard** adalah fitur keamanan yang secara otomatis memeriksa setiap link di dalam
SMS dan memperingatkan pengguna sebelum mereka membuka link penipuan (smishing).
Mesin deteksinya adalah model machine learning (LightGBM) yang sudah dilatih dan
di-deploy oleh tim, dengan akurasi mengklasifikasikan URL **malicious vs aman**.

Diposisikan sebagai **fitur utility di dalam MyTelkomsel** — dan, pada visi jangka
panjang, sebagai **filter SMS di level jaringan Telkomsel** yang melindungi seluruh
pelanggan tanpa perlu instalasi apa pun.

---

## 2. Latar belakang & masalah

Penipuan berbasis SMS (smishing) marak di Indonesia: "Selamat Anda menang hadiah",
tautan palsu bank/e-wallet (BRI, DANA, dll), notifikasi paket palsu, dan link phishing
pencuri data/OTP. Korbannya luas dan kerugiannya nyata. Operator seluler menjadi sorotan
publik dan regulator (Kominfo/OJK) atas peredaran SMS penipuan ini.

**Masalah inti:** pengguna sulit membedakan link aman dan link penipuan, dan keputusan
membuka link terjadi dalam hitungan detik — sebelum sempat berpikir.

---

## 3. Mengapa Telkomsel (positioning)

Aplikasi pihak ketiga terbatas oleh izin sistem operasi (Android membatasi izin SMS;
iOS hampir menutup akses). **Telkomsel tidak punya batasan itu** — sebagai operator,
SMS melewati jaringan mereka. Maka model yang sama bisa:

1. **Tahap dekat:** hadir sebagai fitur di **MyTelkomsel** (cek link manual + peringatan).
2. **Tahap visi:** berjalan di **level jaringan**, memberi label peringatan otomatis pada
   SMS phishing untuk **seluruh pelanggan** — termasuk pengguna HP non-smartphone.

Keunggulan ini eksklusif milik operator dan menjadi nilai jual utama produk ini.

---

## 4. Target pengguna

| Segmen | Kebutuhan |
|--------|-----------|
| Pelanggan umum Telkomsel | Perlindungan otomatis, tanpa ribet, dalam bahasa awam |
| Pengguna rentan (lansia, awam digital) | Peringatan jelas & tegas sebelum klik link |
| Telkomsel (bisnis) | Mengurangi kerugian pelanggan, citra peduli keamanan, kepatuhan regulasi |

---

## 5. Tujuan & metrik keberhasilan

**Tujuan produk**
- Mengurangi jumlah pengguna yang mengklik link penipuan dari SMS.
- Memberi peringatan real-time yang mudah dipahami.

**Metrik (jika diproduksikan)**
- % link malicious yang berhasil dideteksi (recall) & % salah-alarm (false positive).
- Jumlah peringatan ditampilkan & % pengguna yang mengurungkan klik.
- Waktu deteksi (dari SMS masuk → peringatan) < 2 detik.

**Metrik untuk booth (18 Juni)**
- Demo berjalan mulus, deteksi benar pada contoh phishing & contoh aman.
- Pengunjung memahami nilai produk dalam < 1 menit.

---

## 6. Lingkup

### 6.1 Dalam lingkup — Prototipe untuk booth (MVP demo)
- Tampilan **berbentuk aplikasi mobile** (inbox SMS layar penuh, bisa dibuka di HP).
- Beberapa SMS contoh (phishing & normal) yang "masuk" untuk disimulasikan.
- Setiap link diperiksa oleh **model asli** via API `/api/predict`.
- **Peringatan visual** (merah) saat link malicious + skor risiko.
- Mode "cek link manual" (tempel URL → cek) sebagai fitur tambahan.

### 6.2 Visi (di luar lingkup booth, untuk dipresentasikan sebagai roadmap)
- Integrasi nyata sebagai modul di MyTelkomsel.
- Penangkapan SMS otomatis (Android `BroadcastReceiver`, iOS SMS Filter Extension).
- Filter di level jaringan Telkomsel.
- Pelaporan & blokir nomor pengirim, pembaruan model berkala.

### 6.3 Di luar lingkup (eksplisit)
- Membuka/menganalisis isi halaman web tujuan (model hanya analisis URL lexical).
- Memindai aplikasi chat lain (WhatsApp/Telegram) — fokus produk ini SMS.
- Memblokir SMS secara permanen di prototipe.

---

## 7. Kebutuhan fungsional (prototipe)

| ID | Kebutuhan |
|----|-----------|
| F1 | Menampilkan daftar SMS layaknya inbox HP |
| F2 | Mensimulasikan SMS baru masuk (otomatis/lewat tombol) |
| F3 | Mengekstrak URL dari isi SMS |
| F4 | Mengirim URL ke model dan menerima label + probabilitas |
| F5 | Menandai SMS berbahaya dengan jelas (warna/ikon/peringatan) |
| F6 | Menampilkan dialog peringatan saat pengguna mencoba membuka link berbahaya |
| F7 | Mode cek link manual |
| F8 | Indikator bahwa deteksi memakai model ML (tampilkan skor) |

---

## 8. Kebutuhan non-fungsional

- **Keandalan booth:** jalan tanpa bergantung SMS asli/sinyal; bila API mati, ada mode contoh.
- **Privasi:** hanya URL yang dikirim ke server, bukan seluruh isi SMS.
- **Kecepatan:** respons deteksi terasa instan (< 2 dtk).
- **Tampilan:** terasa seperti aplikasi mobile asli saat dipegang di HP.

---

## 9. Risiko & batasan

1. Model hanya menilai URL secara lexical — link berbahaya yang "terlihat normal" bisa lolos.
2. Integrasi nyata ke MyTelkomsel & jaringan butuh kerja sama Telkomsel (bukan ranah prototipe).
3. Izin SMS di Android/iOS membatasi versi aplikasi pihak ketiga (justru jadi argumen "kenapa Telkomsel").
4. Ketergantungan internet untuk memanggil API (opsi on-device sebagai pengembangan lanjut).

---

## 10. Keterkaitan dokumen

- Arsitektur teknis lengkap: [ARSITEKTUR_SMS_DETECTOR.md](ARSITEKTUR_SMS_DETECTOR.md)
- Backend & model: `backend/main.py`, `lgb_model.joblib`
