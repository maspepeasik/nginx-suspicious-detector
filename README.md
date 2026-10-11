# 🛡️ Nginx Auto-Ban Suspicious Bot (via Fail2ban)

Bot monitoring keamanan berbasis **Bash Script** yang memantau `access.log` Nginx secara *real-time*. Bot ini mendeteksi upaya eksploitasi web (SQLi, XSS, Path Traversal, RCE, dan pencarian file sensitif), mengekstrak IP penyerang, memblokirnya secara otomatis via **Fail2ban** selama 7 hari, serta mengirimkan notifikasi lengkap ke **Telegram**.

---

## ✨ Fitur Utama

- **⚡ Pemantauan Real-Time & Multi-Log**: Menggunakan `tail -F -q -n 0` yang ringan dan efisien. Mendukung pemantauan satu file, banyak file log spesifik, atau pola *wildcard* (contoh: `/var/log/nginx/*access*.log`).
- **🎯 Kategorisasi Serangan Akurat**: Memisahkan deteksi serangan ke dalam 5 kategori spesifik dengan file daftar pola masing-masing:
  1. `SQL Injection (SQLi)` ➔ **Instant Ban**
  2. `Cross-Site Scripting (XSS)` ➔ **Instant Ban**
  3. `Path Traversal / Local File Inclusion (LFI)` ➔ **Instant Ban**
  4. `Remote Code Execution (RCE) / Command Injection` ➔ **Instant Ban**
  5. `Akses File Sensitif` (`.env`, `.git`, dll) ➔ **Threshold Ban**
- **⏱️ Sistem Threshold Fleksibel**: Mencegah *false positive* pada akses file sensitif dengan aturan batas (contoh: hanya memblokir jika IP mencoba minimal **2 kali dalam 5 detik**).
- **🌐 Deteksi Domain Target**: Otomatis mengekstrak nama domain yang diserang (baik dari header Host Nginx maupun Referer URL).
- **📢 Notifikasi Telegram Lengkap**: Mengirimkan alert komprehensif ke bot Telegram dengan rincian:
  - 🛑 IP Terblokir
  - 🌐 Domain Target
  - 🎯 Method & Path URL
  - 📊 Status Code HTTP
  - ⏱️ Durasi Ban
  - ⚠️ Kategori Serangan
  - 🔍 Payload Spesifik yang Tertangkap
  - 📝 Baris Log Pemicu
- **🛡️ Whitelist IP Internal**: IP terpercaya (localhost, jaringan LAN/VPN, IP admin) kebal pemblokiran di level script maupun fail2ban.
- **🔐 Hak Akses Fleksibel**: Dijalankan secara *headless* via Systemd sebagai `root` (tanpa password prompt), dengan dukungan opsional `SUDO_PASSWORD` jika dijalankan secara manual oleh user non-root.
- **⚙️ Konfigurasi Standar `.env`**: Seluruh variabel sensitif (Token Telegram, Jail Name, Whitelist, Threshold) dikelola melalui file `.env`.

---

## 📁 Struktur Direktori

```text
├── bot.sh                       # Script utama pemantau log & eksekutor Fail2ban
├── bot.service                  # Unit file systemd untuk background daemon
├── .env                         # Konfigurasi aktif bot (Token, Jail, Whitelist, dll)
├── .env.example                 # Template acuan konfigurasi
├── nginx-bot-jail.conf          # Konfigurasi Jail Fail2ban (/etc/fail2ban/jail.d/)
├── nginx-bot-dummy-filter.conf  # Filter dummy Fail2ban (/etc/fail2ban/filter.d/)
├── patterns_sqli.txt            # Pola deteksi SQL Injection
├── patterns_xss.txt             # Pola deteksi XSS
├── patterns_traversal.txt       # Pola deteksi Path Traversal / LFI
├── patterns_rce.txt             # Pola deteksi RCE / Command Injection
└── patterns_sensitive.txt       # Pola deteksi Akses File Sensitif (.env, .git, dll)
```

---

## 🚀 Panduan Instalasi & Deployment

### 1. Prasyarat Sistem
Pastikan server Linux Anda telah terpasang:
- **Nginx**
- **Fail2ban**
- **Systemd** & **curl**

### 2. Konfigurasi Nginx Log Format (Opsional tapi Direkomendasikan)
Agar Nginx selalu mencatat domain target (`$host`) bahkan saat penyerang tidak menyertakan HTTP Referer:
Buka `/etc/nginx/nginx.conf`, tambahkan format `combined_host` pada bagian `Logging Settings`:
```nginx
log_format combined_host '$remote_addr - $remote_user [$time_local] "$request" $status $body_bytes_sent "$http_referer" "$http_user_agent" "$host"';
access_log /var/log/nginx/access.log combined_host;
```
Lalu uji dan reload Nginx:
```bash
sudo nginx -t && sudo systemctl reload nginx
```

### 3. Konfigurasi Fail2ban
Salin filter dummy dan konfigurasi jail ke direktori Fail2ban:
```bash
sudo cp nginx-bot-dummy-filter.conf /etc/fail2ban/filter.d/nginx-bot-dummy.conf
sudo cp nginx-bot-jail.conf /etc/fail2ban/jail.d/nginx-bot.conf
sudo systemctl restart fail2ban
```
Verifikasi bahwa jail `nginx-bot` sudah aktif:
```bash
sudo fail2ban-client status nginx-bot
```

### 4. Konfigurasi Bot (`.env`)
Salin template `.env.example` menjadi `.env`:
```bash
cp .env.example .env
nano .env
```
Sesuaikan parameter berikut:
```bash
# Path file log (bisa 1 file, spasi untuk banyak file, atau wildcard: /var/log/nginx/*access*.log)
LOG_FILES="/var/log/nginx/access.log"

# Nama jail Fail2ban
JAIL_NAME="nginx-bot"

# Daftar IP yang kebal ban (dipisahkan spasi)
WHITELIST_IPS="127.0.0.1 192.168.1. 10.0.0."

# Aturan Threshold untuk File Sensitif
THRESHOLD_LIMIT=2
THRESHOLD_TIME=5

# Notifikasi Telegram
TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID="YOUR_CHAT_ID_HERE"
```

Pastikan script memiliki izin eksekusi:
```bash
chmod +x bot.sh
```

### 5. Pasang Sebagai Service Systemd
Agar bot otomatis berjalan di background dan otomatis aktif saat server menyala (*boot*):

1. Sesuaikan path direktori `ExecStart` di `bot.service` dengan lokasi absolut `bot.sh` di server Anda:
   ```ini
   ExecStart=/home/username/auto-ban-bot/bot.sh
   ```
2. Salin dan aktifkan service:
   ```bash
   sudo cp bot.service /etc/systemd/system/
   sudo systemctl daemon-reload
   sudo systemctl enable --now bot.service
   ```

---

## 🔍 Monitoring & Pemeliharaan

### Melihat Log Bot Secara Real-Time
```bash
sudo journalctl -u bot.service -f
```

### Memeriksa Daftar IP yang Sedang Di-Ban
```bash
sudo fail2ban-client status nginx-bot
```

### Membuka Blokir (Unban) IP Secara Manual
```bash
sudo fail2ban-client set nginx-bot unbanip <IP_ADDRESS>
```

### Me-restart Service Bot
Setiap kali Anda mengubah file `.env` atau menambahkan pola baru di file `patterns_*.txt`, restart service bot dengan:
```bash
sudo systemctl restart bot.service
```

---

## 🧪 Skenario Pengujian

Anda dapat menguji respon bot secara lokal atau remote:
1. **Uji Path Traversal (Instant Ban)**:
   ```bash
   curl -I "http://IP_SERVER/etc/passwd"
   ```
2. **Uji SQL Injection (Instant Ban)**:
   ```bash
   curl -I "http://IP_SERVER/login='%20or%201=1"
   ```
3. **Uji File Sensitif (Threshold Ban - kirim 2x dalam < 5 detik)**:
   ```bash
   curl -I "http://IP_SERVER/.env"
   curl -I "http://IP_SERVER/.env"
   ```

*Catatan: Pastikan IP penguji tidak terdaftar di variabel `WHITELIST_IPS` saat melakukan simulasi pemblokiran.*

---

## 📄 Lisensi
Dilisensikan untuk penggunaan internal keamanan & operasional server.
