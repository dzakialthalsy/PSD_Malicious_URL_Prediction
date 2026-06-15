# Arsitektur: Deteksi Otomatis Link Malicious pada SMS

Dokumen rancangan untuk aplikasi seluler yang **secara otomatis** memeriksa URL di dalam
SMS masuk dan memberi peringatan jika berbahaya, menggunakan model LightGBM yang sudah
ada di project ini.

Target: **Android + iOS**, jenis pesan: **SMS**.

---

## 1. Gambaran umum

```
                                  ┌─────────────────────────────┐
   SMS masuk berisi link          │      BACKEND (sudah ada)     │
        │                         │                             │
        ▼                         │  FastAPI  /api/predict      │
┌──────────────────┐   HTTPS      │     │                       │
│   APP DI HP      │ ───────────▶ │     ▼                       │
│  (Android/iOS)   │              │  feature_extractor.py       │
│                  │ ◀─────────── │     │  (ekstrak fitur URL)  │
│  - tangkap SMS   │   JSON       │     ▼                       │
│  - ambil URL     │              │  lgb_model.joblib           │
│  - panggil API   │              │     │                       │
│  - tampilkan     │              │     ▼                       │
│    peringatan    │              │  probabilitas + label       │
└──────────────────┘              └─────────────────────────────┘
```

**Inti yang sudah selesai:** "otak" deteksi sudah ada. Endpoint `POST /api/predict`
menerima URL mentah, mengekstrak fitur sendiri (`extract_many`), dan mengembalikan
probabilitas + label `Malicious` / `Not Malicious`. Model **tidak perlu diubah**.

Yang perlu dibangun: (a) penyesuaian backend agar siap diakses publik dengan aman, dan
(b) aplikasi di tiap platform yang menangkap SMS lalu memanggil API.

---

## 2. Komponen

### 2.1 Backend / Model (sudah ada — perlu sedikit penyesuaian)

| Hal | Status sekarang | Perlu diubah |
|-----|-----------------|--------------|
| Endpoint prediksi | `POST /api/predict` menerima `{"urls": [...]}` | ✅ siap, tidak diubah |
| Ekstraksi fitur | Lexical murni, offline, cepat | ✅ siap |
| CORS | Hanya `localhost:5173` | ➕ izinkan origin app / atau pakai API key |
| Host | Localhost | ➕ deploy ke server publik (HTTPS wajib) |
| Autentikasi | Tidak ada | ➕ tambahkan API key sederhana (header) |
| Rate limiting | Tidak ada | ➕ batasi per key (cegah abuse) |
| Endpoint untuk iOS | — | ➕ endpoint khusus format iOS (lihat 2.3) |

Kebutuhan deployment: server dengan HTTPS (sertifikat valid — wajib untuk iOS extension
dan praktik baik Android). Opsi: Railway / Render / Fly.io / VPS + Caddy/Nginx.

### 2.2 Aplikasi Android

**Cara menangkap SMS:** `BroadcastReceiver` dengan permission `RECEIVE_SMS`.

```
SMS masuk
  → BroadcastReceiver (android.provider.Telephony.SMS_RECEIVED)
  → ekstrak teks pesan
  → regex cari URL di dalam teks
  → (kalau ada URL) POST ke /api/predict
  → kalau Malicious → tampilkan Notification peringatan (high priority)
```

Komponen:
- `SmsReceiver` (BroadcastReceiver) — menerima event SMS.
- `UrlExtractor` — regex untuk menemukan URL (termasuk yang tanpa `http://`).
- `ApiClient` — Retrofit/OkHttp, POST ke backend, timeout pendek + retry.
- `AlertNotifier` — NotificationManager untuk peringatan ("⚠️ Link berbahaya terdeteksi").
- `WhitelistStore` — daftar domain aman lokal (opsional, kurangi panggilan API).

**Catatan kebijakan Google Play (PENTING):** permission `RECEIVE_SMS`/`READ_SMS`
termasuk *restricted permission*. Untuk publikasi di Play Store, aplikasi umumnya harus
menjadi **default SMS handler** atau mengajukan *Permissions Declaration* dengan use-case
yang disetujui. Untuk **pemakaian pribadi / sideload / skripsi**, ini tidak masalah —
cukup install langsung tanpa lewat Play Store.

### 2.3 Aplikasi iOS

**Cara menangkap SMS:** iOS **tidak** mengizinkan baca isi SMS langsung. Satu-satunya
jalur resmi adalah **SMS Filter Extension** (framework `IdentityLookup` —
`ILMessageFilterExtension`). Batasan penting:

- Hanya berlaku untuk SMS/MMS dari **pengirim tak dikenal** (bukan kontak).
- Extension berjalan di sandbox sangat ketat.
- Boleh melakukan **satu** panggilan jaringan via `deferQueryRequest(to:)` ke URL yang
  dikonfigurasi di `Info.plist` (`ILMessageFilterExtensionNetworkURL`). Apple yang
  mengirim request ke server Anda; server membalas kategori pesan.
- Output hanya berupa **kategori** (mis. `junk` / `promotional` / `transaction`).
  iOS **tidak** mengizinkan menampilkan notifikasi custom dari extension — pesan
  berbahaya otomatis dipindah ke folder Junk/Spam, bukan pop-up "link berbahaya".

```
SMS dari nomor tak dikenal
  → iOS panggil ILMessageFilterExtension
  → klasifikasi offline (opsional, pakai whitelist/blacklist lokal)
  → kalau ragu: deferQueryRequest → server Anda (/api/ios-filter)
  → server ekstrak URL → model → balas kategori
  → iOS taruh pesan di folder sesuai kategori
```

Karena perbedaan ini, backend perlu **endpoint terpisah `/api/ios-filter`** yang
menerima format request dari Apple dan membalas dalam format `ILNetworkResponse`.

**Konsekuensi UX:** di iOS pengalamannya "pesan spam/berbahaya otomatis tersaring",
bukan peringatan aktif. Tidak ada cara resmi membuat pop-up real-time seperti Android.

---

## 3. Alur data detail (Android, kasus utama)

1. SMS masuk → `SmsReceiver.onReceive()`.
2. Gabungkan multipart SMS → satu string teks.
3. `UrlExtractor` mencari semua URL. Jika tidak ada URL → berhenti (hemat API).
4. Cek whitelist lokal. Jika semua domain aman → berhenti.
5. `ApiClient` POST `{"urls": [...]}` + header `X-API-Key` ke `/api/predict`.
6. Terima JSON: `probability`, `risk_label` per URL.
7. Jika ada `risk_label == "Malicious"` (atau `probability >= threshold`):
   tampilkan notifikasi peringatan dengan URL & skor risiko.
8. (Opsional) simpan riwayat deteksi lokal untuk halaman "Riwayat".

Timeout & offline: jika API tak terjangkau, app bisa (a) diam saja, atau (b) memberi
peringatan ringan "tidak dapat memverifikasi link". Jangan blokir SMS.

---

## 4. Kontrak API

### Android — pakai endpoint yang sudah ada
```
POST /api/predict
Header: X-API-Key: <key>
Body:   { "urls": ["http://contoh.com/login"] }

Response:
{
  "threshold": 0.51,
  "results": [
    { "url": "http://contoh.com/login",
      "probability": 0.93, "percentage": 93.0,
      "predicted_label": 1, "risk_label": "Malicious" }
  ]
}
```

### iOS — endpoint baru
```
POST /api/ios-filter      (URL ini didaftarkan di Info.plist extension)
Body: dikirim oleh iOS (berisi konteks pesan)
Response: format ILNetworkResponse → {action: filter/allow, subAction: junk/...}
```

---

## 5. Keamanan & privasi

- **HTTPS wajib** di semua jalur (iOS menolak non-HTTPS; Android sebaiknya juga).
- **API key** per aplikasi + rate limiting agar API tidak disalahgunakan.
- **Minimkan data terkirim:** kirim **hanya URL**, bukan seluruh isi SMS. Ini penting
  secara privasi (isi SMS bisa berisi OTP/data pribadi).
- **Jangan simpan** URL/SMS di server lebih dari yang perlu (log secukupnya).
- Pertimbangkan ekstraksi fitur **di sisi HP** lalu kirim fitur (bukan URL) — lebih
  privat lagi, tapi perlu memport `feature_extractor.py` ke Kotlin/Swift. (Opsi lanjutan.)
- Sampaikan ke pengguna dengan jelas bahwa link dari SMS dicek ke server.

---

## 6. Rencana implementasi bertahap

| Fase | Output | Catatan |
|------|--------|---------|
| 0 | Backend siap publik: CORS, API key, rate limit, deploy HTTPS | Pondasi untuk kedua platform |
| 1 | App Android: tangkap SMS → cek API → notifikasi peringatan | Nilai tertinggi, paling cepat terlihat |
| 2 | Whitelist lokal + halaman Riwayat + pengaturan threshold | Polmakaian harian |
| 3 | iOS SMS Filter Extension + endpoint `/api/ios-filter` | Terbatas (auto-sort, bukan pop-up) |
| 4 | (Opsional) ekstraksi fitur on-device untuk privasi | Port feature_extractor |

---

## 7. Risiko & batasan yang harus diketahui sejak awal

1. **iOS sangat terbatas** — hanya SMS pengirim tak dikenal, hanya auto-sort ke Junk,
   tanpa pop-up peringatan. Ekspektasi pengguna iOS harus disesuaikan.
2. **Google Play membatasi permission SMS** — aman untuk pemakaian pribadi/sideload;
   untuk rilis publik perlu pengajuan khusus atau jadi default SMS app.
3. **Hanya menganalisis URL secara lexical** — model tidak membuka/mengecek isi
   halaman. Link malicious baru yang "terlihat normal" bisa lolos. Ini batasan model,
   bukan arsitektur.
4. **Ketergantungan jaringan** — perlu internet untuk memanggil API (kecuali pakai
   opsi on-device di Fase 4).
5. **Latensi** — proses harus cepat agar peringatan muncul sesaat setelah SMS masuk.
```
