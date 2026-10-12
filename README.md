# 🛡️ Nginx Auto-Ban Suspicious Bot (via Fail2ban)

Bot monitoring keamanan berbasis **Bash Script** yang memantau `access.log` Nginx secara *real-time*. Bot ini mendeteksi upaya eksploitasi web (SQLi, XSS, Path Traversal, RCE, dan pencarian file sensitif), mengekstrak IP penyerang, memblokirnya secara otomatis via **Fail2ban** selama 7 hari, memantau error HTTP 4xx/5xx (notifikasi saja), serta mengirimkan notifikasi lengkap ke **Telegram** dengan waktu standar lokal (WIB).

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
- **🕒 Format Waktu Lokal Akurat (WIB)**: Timestamp log otomatis dikonversi ke zona waktu lokal (`YYYY-MM-DD HH:MM:SS WIB`), bebas dari kebingungan selisih waktu UTC.
- **📢 Notifikasi Telegram Komprehensif**: Mengirimkan alert langsung ke bot Telegram dengan format bersih dan informatif:
  - **Auto-Ban Alert**: Detail lengkap saat penyerang baru diblokir (IP, Waktu, Domain, Method & Path, Status Code, Durasi Ban, Kategori Serangan, Payload yang tertangkap, dan Baris Log).
  - **Persistent Attack Alert**: Notifikasi khusus untuk IP yang sudah terblokir tetapi masih mencoba menyerang (dikirim setiap kelipatan 2 kali percobaan).
  - **HTTP Error Alert (4xx & 5xx)**: Notifikasi real-time jika terjadi error client (`4xx` seperti 403, 404) atau server (`5xx` seperti 500, 502) **tanpa memblokir IP (Notif Only)**.
- **🛡️ Whitelist IP Internal**: IP terpercaya (localhost, jaringan LAN/VPN, IP admin) kebal pemblokiran di level script maupun Fail2ban.
- **🔐 Hak Akses Fleksibel**: Dijalankan secara *headless* via Systemd sebagai `root` (tanpa password prompt), dengan dukungan opsional `SUDO_PASSWORD` jika dijalankan secara manual oleh user non-root.
- **⚙️ Konfigurasi Terpusat `.env`**: Seluruh variabel (Token Telegram, Jail Name, Whitelist, Threshold, Timezone) dikelola rapi melalui satu file `.env`.

---

## 📁 Struktur Direktori

```text
├── bot.sh                       # Script utama pemantau log & eksekutor Fail2ban
├── bot.service                  # Unit file systemd untuk background daemon
├── .env                         # Konfigurasi aktif bot (Token, Jail, Whitelist, dll)
├── .env.example                 # Template acuan konfigurasi
├── README.md                    # Dokumentasi lengkap sistem
├── nginx-bot-jail.conf          # Konfigurasi Jail Fail2ban (/etc/fail2ban/jail.d/)
├── nginx-bot-dummy-filter.conf  # Filter dummy Fail2ban (/etc/fail2ban/filter.d/)
├── patterns_sqli.txt            # Pola deteksi SQL Injection (Instant Ban)
├── patterns_xss.txt             # Pola deteksi XSS (Instant Ban)
├── patterns_traversal.txt       # Pola deteksi Path Traversal / LFI (Instant Ban)
├── patterns_rce.txt             # Pola deteksi RCE / Command Injection (Instant Ban)
└── patterns_sensitive.txt       # Pola deteksi Akses File Sensitif (Threshold Ban)
```

---

## 🚀 Panduan Instalasi & Deployment

### 1. Prasyarat Sistem
Pastikan server Linux Anda telah terpasang paket berikut:
- **Nginx**
- **Fail2ban**
- **Systemd** & **curl**

Atur zona waktu server ke WIB (opsional tapi disarankan):
```bash
sudo timedatectl set-timezone Asia/Jakarta
```

### 2. Konfigurasi Format Log Nginx (Sangat Disarankan)
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

Contoh isi konfigurasi lengkap:
```bash
# Path file log Nginx (bisa 1 file, spasi untuk banyak file, atau wildcard: /var/log/nginx/*access*.log)
LOG_FILES="/var/log/nginx/access.log"

# Nama jail Fail2ban
JAIL_NAME="nginx-bot"

# Daftar IP yang kebal ban (dipisahkan spasi)
WHITELIST_IPS="127.0.0.1 192.168.1. 10.0.0."

# Aturan Threshold untuk File Sensitif
THRESHOLD_LIMIT=2
THRESHOLD_TIME=5

# Interval alert untuk IP yang sudah diban tapi masih mencoba menyerang
BANNED_REPEAT_INTERVAL=2

# Notifikasi HTTP Error (4xx & 5xx) - Notif Only (Tanpa Ban)
NOTIFY_HTTP_ERRORS="true"

# Zona Waktu Notifikasi Telegram (Default: Asia/Jakarta)
TIMEZONE="Asia/Jakarta"

# Kredensial Notifikasi Telegram
TELEGRAM_BOT_TOKEN="YOUR_BOT_TOKEN_HERE"
TELEGRAM_CHAT_ID="YOUR_CHAT_ID_HERE"

# Password Sudo / Root (Opsional, kosongkan jika via systemd)
SUDO_PASSWORD=""
```

Pastikan script memiliki izin eksekusi:
```bash
chmod +x bot.sh
```

### 5. Pasang Sebagai Service Systemd
Agar bot otomatis berjalan di background dan otomatis aktif saat server dinyalakan (*boot*):

1. Sesuaikan direktori `ExecStart` di `bot.service` dengan lokasi absolut `bot.sh` di server Anda:
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

## 📱 Format Notifikasi Telegram

### 1. Alert Pemblokiran Baru (Auto-Ban Alert)
```text
🚨 AUTO-BAN ALERT 🚨

🛑 IP Terblokir: 203.0.113.10
🕒 Waktu: 2026-10-12 11:08:50 WIB
🌐 Domain: example.com
🎯 Method & Path: GET /login='%20or%201=1
📊 Status Code: 404
⏱️ Durasi Ban: 7 Hari
⚠️ Kategori Serangan: SQL Injection (SQLi)
🔍 Payload Terdeteksi: %20or%201=1

📝 Log Pemicu:
203.0.113.10 - - [12/Oct/2026:11:08:50 +0700] "GET /login='%20or%201=1 HTTP/1.1" 404 3005 "-" "curl/8.5.0" "example.com"
```

### 2. Alert Serangan Berulang dari IP yang Sudah Di-Ban (Persistent Attack)
```text
🚫 PERSISTENT ATTACK ALERT (IP SUDAH DIBLOKIR) 🚫

🛑 IP Penyerang: 203.0.113.10 (Status: Aktif Terblokir)
🕒 Waktu: 2026-10-12 11:10:15 WIB
🔢 Percobaan Berulang: Percobaan ke-2
🌐 Domain Target: example.com
🎯 Method & Path: GET /etc/passwd
📊 Status Code: 404
⏱️ Status Ban: Masih Terblokir via Fail2ban
⚠️ Kategori Serangan: Path Traversal / Local File Inclusion (LFI)
🔍 Payload Terdeteksi: /etc/passwd

📝 Log Pemicu:
...
```

### 3. Alert HTTP Error 4xx / 5xx (Notif Only - Tanpa Ban)
```text
⚠️ NGINX 4xx ERROR DETECTED

IP: 114.10.151.100
Status HTTP: 404
Method: GET
Path: /halaman-tidak-ada
Time: 2026-10-12 11:15:30 WIB
User Agent: Mozilla/5.0...
Domain: example.com
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
4. **Uji HTTP 4xx (Notif Only - Tanpa Ban)**:
   ```bash
   curl -I "http://IP_SERVER/halaman-acak-404"
   ```

*Catatan: Pastikan IP penguji tidak terdaftar di variabel `WHITELIST_IPS` saat melakukan simulasi pemblokiran.*

---

## 📄 Lisensi
Dilisensikan untuk penggunaan internal keamanan & operasional server.
