# 🔗 Malicious URL Detection

Deteksi **URL berbahaya (malicious) vs aman** menggunakan model machine learning
**LightGBM** yang dilatih dari fitur leksikal URL. Proyek ini mencakup pipeline
pelatihan (notebook), **REST API** siap pakai (FastAPI), serta **demo web** interaktif.

> Mesin deteksi ini juga dipakai oleh **SMS Guard** — aplikasi Android yang memeriksa
> link pada SMS masuk secara real-time (repo terpisah).

---

## 📊 Dataset

Model dilatih menggunakan dataset publik dari Kaggle:

**[6.5 Lakh URLs labelled as 1 and 0](https://www.kaggle.com/datasets/somanshumahajan/65-lakh-urls-labelled-as-1-and-0)**
— ±6,5 juta URL dengan label `1` (malicious) dan `0` (benign).

> ⚠️ Dataset **tidak disertakan** di repo ini (ukurannya >1 GB). Unduh dari tautan di
> atas dan letakkan di folder lokal Anda. File dataset sudah masuk `.gitignore`.

---

## ✨ Fitur

- Klasifikasi URL **malicious / not malicious** beserta **probabilitas risiko**.
- **Ekstraksi fitur leksikal murni** (38 fitur) — cepat & offline, tanpa perlu
  mengakses isi halaman web. Contoh fitur: jumlah titik/`@`/`-`/digit, panjang URL &
  domain, kedalaman path, rasio karakter, entropi Shannon (domain/path/query),
  status HTTPS, validitas TLD (IANA), frekuensi TLD, deteksi alamat IP, dll.
- **REST API** untuk prediksi satu/banyak URL maupun unggah file (CSV/Excel).
- **Demo web** berbentuk antarmuka HP untuk presentasi.

---

## 🗂️ Struktur Proyek

```
.
├── PSD_malicious_url.ipynb      # Notebook: EDA, ekstraksi fitur, training & evaluasi
├── lgb_model.joblib             # Model LightGBM terlatih
├── backend/
│   ├── main.py                  # REST API (FastAPI)
│   ├── feature_extractor.py     # Ekstraksi 38 fitur leksikal dari URL
│   ├── tld_stats.json           # Statistik frekuensi TLD + daftar TLD IANA
│   └── __init__.py
├── demo/
│   └── sms_guard.html           # Demo web (disajikan di /demo)
├── requirements.txt
├── PRD_SMS_GUARD.md             # Product Requirements — SMS Guard
└── ARSITEKTUR_SMS_DETECTOR.md   # Dokumen arsitektur teknis
```

---

## 🧠 Model

- **Algoritma:** LightGBM (gradient boosting)
- **Input:** 38 fitur leksikal yang diekstrak dari string URL
- **Output:** probabilitas `[0,1]` — makin tinggi makin berbahaya
- **Threshold default:** `0.5119` (hasil penyetelan; URL dengan probabilitas ≥ threshold
  dilabeli *Malicious*)

Detail eksplorasi data, daftar fitur lengkap, proses pelatihan, dan evaluasi ada di
[`PSD_malicious_url.ipynb`](PSD_malicious_url.ipynb).

---

## 🚀 Menjalankan

Prasyarat: **Python 3.10+**.

```bash
# 1) Install dependency
pip install -r requirements.txt

# 2) Jalankan API + demo web
uvicorn backend.main:app --reload
```

Lalu buka:
- **Demo web:** http://127.0.0.1:8000/demo
- **Cek kesehatan API:** http://127.0.0.1:8000/api/health

> Untuk diakses dari perangkat lain (mis. HP di WiFi yang sama), jalankan dengan
> `--host 0.0.0.0` lalu akses `http://<IP-komputer>:8000`.

---

## 🔌 API

### `POST /api/predict`
Prediksi satu atau banyak URL.

```bash
curl -X POST http://127.0.0.1:8000/api/predict \
  -H "Content-Type: application/json" \
  -d '{"urls": ["http://contoh-phishing.xyz/login", "https://www.google.com"]}'
```

```json
{
  "threshold": 0.5119,
  "total": 2,
  "malicious": 1,
  "not_malicious": 1,
  "results": [
    {"id": 1, "url": "http://contoh-phishing.xyz/login",
     "probability": 0.97, "percentage": 97.0,
     "predicted_label": 1, "risk_label": "Malicious"},
    {"id": 2, "url": "https://www.google.com",
     "probability": 0.01, "percentage": 1.0,
     "predicted_label": 0, "risk_label": "Not Malicious"}
  ]
}
```

### `POST /api/predict-file`
Unggah file **CSV/XLSX** berisi kolom URL (`url`, `urls`, `link`, atau `website`)
untuk prediksi massal. Opsional: parameter form `threshold`.

### `GET /api/health`
Status server, jenis model, jumlah fitur, dan threshold.

---

## 📱 Aplikasi Pendamping — SMS Guard

Aplikasi Android (React Native + modul native Java) yang menangkap SMS masuk secara
otomatis & real-time, memeriksa setiap link ke API ini, lalu memunculkan notifikasi
peringatan bila berbahaya. Tersedia di repo terpisah.

Lihat [`PRD_SMS_GUARD.md`](PRD_SMS_GUARD.md) dan
[`ARSITEKTUR_SMS_DETECTOR.md`](ARSITEKTUR_SMS_DETECTOR.md) untuk detail produk & arsitektur.

---

## 🛠️ Teknologi

`Python` · `LightGBM` · `pandas` / `numpy` · `FastAPI` · `Uvicorn` · `Jupyter`

---

## ⚠️ Catatan & Batasan

- Model menilai URL **secara leksikal** (pola teks), tidak membuka/menelaah isi halaman.
  Link berbahaya yang "terlihat normal" tetap berpotensi lolos.
- Threshold dapat disesuaikan per kebutuhan (trade-off antara *false positive* dan
  *false negative*).

## 🙏 Kredit

Dataset: [Somanshu Mahajan — 6.5 Lakh URLs (Kaggle)](https://www.kaggle.com/datasets/somanshumahajan/65-lakh-urls-labelled-as-1-and-0).
