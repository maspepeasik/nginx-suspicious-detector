#!/bin/bash

# ==========================================================
# Auto-Ban Bot for Nginx via Fail2ban
# ==========================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

CONFIG_FILE="${SCRIPT_DIR}/.env"
if [[ ! -f "$CONFIG_FILE" ]]; then
    echo "[!] Error: File .env tidak ditemukan! Silakan salin dari .env.example"
    exit 1
fi
source "$CONFIG_FILE"

TARGET_LOGS="${LOG_FILES:-$LOG_FILE}"
[[ -z "$TARGET_LOGS" ]] && TARGET_LOGS="/var/log/nginx/access.log"

# Lokasi file pola berdasarkan kategori
PATTERN_SQLI="${PATTERN_SQLI:-${SCRIPT_DIR}/patterns_sqli.txt}"
PATTERN_XSS="${PATTERN_XSS:-${SCRIPT_DIR}/patterns_xss.txt}"
PATTERN_TRAVERSAL="${PATTERN_TRAVERSAL:-${SCRIPT_DIR}/patterns_traversal.txt}"
PATTERN_RCE="${PATTERN_RCE:-${SCRIPT_DIR}/patterns_rce.txt}"
PATTERN_SENSITIVE="${PATTERN_SENSITIVE:-${SCRIPT_DIR}/patterns_sensitive.txt}"

# Interval alert untuk IP yang sudah diban tapi masih mencoba menyerang
REPEAT_INTERVAL="${BANNED_REPEAT_INTERVAL:-2}"

# Helper untuk memformat waktu log menjadi zona waktu lokal (WIB / Asia/Jakarta)
format_time() {
    local raw="$1"
    local tz="${TIMEZONE:-Asia/Jakarta}"
    if [[ -z "$raw" ]]; then
        TZ="$tz" date '+%Y-%m-%d %H:%M:%S %Z'
        return
    fi
    local parsed=$(echo "$raw" | sed 's|/|-|g; s|:| |')
    local formatted=$(TZ="$tz" date -d "$parsed" '+%Y-%m-%d %H:%M:%S %Z' 2>/dev/null)
    if [[ -n "$formatted" ]]; then
        echo "$formatted"
    else
        echo "$raw"
    fi
}

# Helper untuk eksekusi perintah root (Mendukung Systemd Root, Sudo Password, atau Passwordless)
run_as_root() {
    if [[ $EUID -eq 0 ]]; then
        "$@"
    elif [[ -n "$SUDO_PASSWORD" ]]; then
        echo "$SUDO_PASSWORD" | sudo -S "$@"
    else
        sudo "$@"
    fi
}

# Stream log Nginx (Mendukung multi-log & quiet mode)
stream_logs() {
    if [[ $EUID -eq 0 ]]; then
        tail -F -q -n 0 $TARGET_LOGS 2>/dev/null
    elif [[ -n "$SUDO_PASSWORD" ]]; then
        echo "$SUDO_PASSWORD" | sudo -S tail -F -q -n 0 $TARGET_LOGS 2>/dev/null
    else
        sudo tail -F -q -n 0 $TARGET_LOGS 2>/dev/null
    fi
}

# Membangun Regex per kategori
build_regex() {
    local file="$1"
    if [[ -f "$file" ]]; then
        grep -vE '^\s*#|^\s*$' "$file" | paste -sd '|' -
    fi
}

REGEX_SQLI=$(build_regex "$PATTERN_SQLI")
REGEX_XSS=$(build_regex "$PATTERN_XSS")
REGEX_TRAVERSAL=$(build_regex "$PATTERN_TRAVERSAL")
REGEX_RCE=$(build_regex "$PATTERN_RCE")
REGEX_SENSITIVE=$(build_regex "$PATTERN_SENSITIVE")

# Fungsi Kirim Notifikasi Telegram untuk Ban Baru
send_telegram() {
    local ip="$1"
    local category="$2"
    local logline="$3"
    local payload="$4"
    local domain="$5"
    local method="$6"
    local path_url="$7"
    local status_code="$8"
    local req_time="$9"
    
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        local text="🚨 <b>AUTO-BAN ALERT</b> 🚨

🛑 <b>IP Terblokir:</b> <code>$ip</code>
🕒 <b>Waktu:</b> $req_time
🌐 <b>Domain:</b> <code>$domain</code>
🎯 <b>Method & Path:</b> <code>$method $path_url</code>
📊 <b>Status Code:</b> <code>$status_code</code>
⏱️ <b>Durasi Ban:</b> ${BANTIME_DISPLAY:-7 Hari}
⚠️ <b>Kategori Serangan:</b> <b>$category</b>
🔍 <b>Payload Terdeteksi:</b> <code>$payload</code>

📝 <b>Log Pemicu:</b>
<code>$logline</code>"

        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" \
            --data-urlencode text="${text}" \
            -d parse_mode="HTML" > /dev/null 2>&1
    fi
}

# Fungsi Kirim Notifikasi Telegram untuk Percobaan Berulang dari IP yang Sudah di-Ban
send_telegram_repeat() {
    local ip="$1"
    local category="$2"
    local logline="$3"
    local payload="$4"
    local domain="$5"
    local method="$6"
    local path_url="$7"
    local status_code="$8"
    local attempt="$9"
    local req_time="${10}"
    
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        local text="🚫 <b>PERSISTENT ATTACK ALERT (IP SUDAH DIBLOKIR)</b> 🚫

🛑 <b>IP Penyerang:</b> <code>$ip</code> (Status: Aktif Terblokir)
🕒 <b>Waktu:</b> $req_time
🔢 <b>Percobaan Berulang:</b> Percobaan ke-$attempt
🌐 <b>Domain Target:</b> <code>$domain</code>
🎯 <b>Method & Path:</b> <code>$method $path_url</code>
📊 <b>Status Code:</b> <code>$status_code</code>
⏱️ <b>Status Ban:</b> Masih Terblokir via Fail2ban
⚠️ <b>Kategori Serangan:</b> <b>$category</b>
🔍 <b>Payload Terdeteksi:</b> <code>$payload</code>

📝 <b>Log Pemicu:</b>
<code>$logline</code>"

        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" \
            --data-urlencode text="${text}" \
            -d parse_mode="HTML" > /dev/null 2>&1
    fi
}

# Fungsi Kirim Notifikasi Telegram untuk Error HTTP 4xx & 5xx (Notif Only, Tanpa Ban)
send_http_error_telegram() {
    local ip="$1"
    local status_code="$2"
    local method="$3"
    local path_url="$4"
    local req_time="$5"
    local user_agent="$6"
    local domain="$7"
    
    local title="⚠️ NGINX 4xx ERROR DETECTED"
    if [[ "$status_code" =~ ^5 ]]; then
        title="🚨 NGINX 5xx ERROR DETECTED"
    fi
    
    local text="$title

<b>IP:</b> $ip
<b>Status HTTP:</b> $status_code
<b>Method:</b> $method
<b>Path:</b> $path_url
<b>Time:</b> $req_time
<b>User Agent:</b> $user_agent
<b>Domain:</b> $domain"

    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        curl -s -X POST "https://api.telegram.org/bot${TELEGRAM_BOT_TOKEN}/sendMessage" \
            -d chat_id="${TELEGRAM_CHAT_ID}" \
            --data-urlencode text="${text}" \
            -d parse_mode="HTML" > /dev/null 2>&1
    fi
}

# State pelacak
declare -A SENSITIVE_COUNT
declare -A SENSITIVE_TIME
declare -A BANNED_REPEAT_COUNT

# Fungsi Eksekusi Ban
ban_ip() {
    local ip="$1"
    local category="$2"
    local logline="$3"
    local payload="$4"
    local domain="$5"
    local method="$6"
    local path_url="$7"
    local status_code="$8"
    local req_time="$9"
    
    # Cek Whitelist IP
    local is_whitelisted=0
    for w_ip in $WHITELIST_IPS; do
        if [[ "$ip" == "$w_ip"* ]]; then
            is_whitelisted=1
            break
        fi
    done
    
    if [[ $is_whitelisted -eq 1 ]]; then
        echo "[-] IP $ip terdeteksi ($category), tapi masuk WHITELIST. (Abaikan)"
    else
        result=$(run_as_root fail2ban-client set "$JAIL_NAME" banip "$ip" 2>/dev/null)
        
        if [[ "$result" == "1" ]]; then
            echo "[!] BAN BARU: IP $ip | $category | Domain: $domain"
            BANNED_REPEAT_COUNT["$ip"]=0
            send_telegram "$ip" "$category" "$logline" "$payload" "$domain" "$method" "$path_url" "$status_code" "$req_time"
        elif [[ "$result" == "0" ]]; then
            BANNED_REPEAT_COUNT["$ip"]=$(( ${BANNED_REPEAT_COUNT["$ip"]:-0} + 1 ))
            local current_attempt=${BANNED_REPEAT_COUNT["$ip"]}
            
            echo "[*] IP $ip sudah dalam status ban. Percobaan pasca-ban ke-$current_attempt (Alert setiap $REPEAT_INTERVAL kali)"
            
            if (( current_attempt % REPEAT_INTERVAL == 0 )); then
                echo "[!] Mengirim notifikasi percobaan berulang ke-$current_attempt untuk IP $ip ke Telegram..."
                send_telegram_repeat "$ip" "$category" "$logline" "$payload" "$domain" "$method" "$path_url" "$status_code" "$current_attempt" "$req_time"
            fi
        else
            echo "[!] Gagal melakukan ban terhadap IP $ip."
        fi
    fi
}

echo "[*] Auto-Ban Bot berjalan dengan deteksi serangan dan monitoring error 4xx/5xx..."

stream_logs | while read -r line; do
    IP=$(echo "$line" | awk '{print $1}')
    
    # Validasi format IPv4
    if [[ ! "$IP" =~ ^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$ ]]; then
        continue
    fi
    
    # Ekstraksi Request (Method & Path)
    REQ=$(echo "$line" | grep -oP '"[A-Z]+ [^"]+ HTTP/[0-9.]+"' | tr -d '"')
    METHOD=$(echo "$REQ" | awk '{print $1}')
    PATH_URL=$(echo "$REQ" | awk '{print $2}')
    [[ -z "$METHOD" ]] && METHOD="-"
    [[ -z "$PATH_URL" ]] && PATH_URL="-"
    
    # Ekstraksi Status Code
    STATUS_CODE=$(echo "$line" | awk -F'"' '{print $3}' | awk '{print $1}')
    [[ -z "$STATUS_CODE" ]] && STATUS_CODE="-"
    
    # Ekstraksi Domain
    LAST_QUOTE=$(echo "$line" | awk -F'"' '{print $(NF-1)}')
    DOMAIN=""
    if [[ -n "$LAST_QUOTE" && "$LAST_QUOTE" != "-" && ! "$LAST_QUOTE" =~ [[:space:]] && "$LAST_QUOTE" =~ \. ]]; then
        DOMAIN="$LAST_QUOTE"
    fi
    
    if [[ -z "$DOMAIN" ]]; then
        REFERER_DOMAIN=$(echo "$line" | grep -oP 'https?://\K[^/"\s:]+' | head -n 1)
        if [[ -n "$REFERER_DOMAIN" ]]; then
            DOMAIN="$REFERER_DOMAIN"
        fi
    fi
    
    [[ -z "$DOMAIN" ]] && DOMAIN="Direct Access (No Host Header)"
    
    # Ekstraksi Timestamp & Format ke Waktu Lokal (WIB)
    RAW_TIME=$(echo "$line" | grep -oP '\[\K[^\]]+')
    REQ_TIME=$(format_time "$RAW_TIME")
    
    # Ekstraksi User Agent
    USER_AGENT=$(echo "$line" | awk -F'"' '{print $6}')
    [[ -z "$USER_AGENT" || "$USER_AGENT" == "-" ]] && USER_AGENT="-"

    # ==========================================================
    # 1. Kategori: SQL Injection (SQLi) -> INSTANT BAN
    # ==========================================================
    if [[ -n "$REGEX_SQLI" ]] && echo "$line" | grep -a -E -q -i "($REGEX_SQLI)"; then
        MATCHED=$(echo "$line" | grep -a -o -E -i "($REGEX_SQLI)" | head -n 1)
        ban_ip "$IP" "SQL Injection (SQLi)" "$line" "$MATCHED" "$DOMAIN" "$METHOD" "$PATH_URL" "$STATUS_CODE" "$REQ_TIME"
        continue
    fi
    
    # ==========================================================
    # 2. Kategori: Cross-Site Scripting (XSS) -> INSTANT BAN
    # ==========================================================
    if [[ -n "$REGEX_XSS" ]] && echo "$line" | grep -a -E -q -i "($REGEX_XSS)"; then
        MATCHED=$(echo "$line" | grep -a -o -E -i "($REGEX_XSS)" | head -n 1)
        ban_ip "$IP" "Cross-Site Scripting (XSS)" "$line" "$MATCHED" "$DOMAIN" "$METHOD" "$PATH_URL" "$STATUS_CODE" "$REQ_TIME"
        continue
    fi
    
    # ==========================================================
    # 3. Kategori: Path Traversal / LFI -> INSTANT BAN
    # ==========================================================
    if [[ -n "$REGEX_TRAVERSAL" ]] && echo "$line" | grep -a -E -q -i "($REGEX_TRAVERSAL)"; then
        MATCHED=$(echo "$line" | grep -a -o -E -i "($REGEX_TRAVERSAL)" | head -n 1)
        ban_ip "$IP" "Path Traversal / Local File Inclusion (LFI)" "$line" "$MATCHED" "$DOMAIN" "$METHOD" "$PATH_URL" "$STATUS_CODE" "$REQ_TIME"
        continue
    fi
    
    # ==========================================================
    # 4. Kategori: Remote Code Execution (RCE) -> INSTANT BAN
    # ==========================================================
    if [[ -n "$REGEX_RCE" ]] && echo "$line" | grep -a -E -q -i "($REGEX_RCE)"; then
        MATCHED=$(echo "$line" | grep -a -o -E -i "($REGEX_RCE)" | head -n 1)
        ban_ip "$IP" "Remote Code Execution (RCE)" "$line" "$MATCHED" "$DOMAIN" "$METHOD" "$PATH_URL" "$STATUS_CODE" "$REQ_TIME"
        continue
    fi
    
    # ==========================================================
    # 5. Kategori: Akses File Sensitif -> THRESHOLD BAN
    # ==========================================================
    if [[ -n "$REGEX_SENSITIVE" ]] && echo "$line" | grep -a -E -q -i "($REGEX_SENSITIVE)"; then
        MATCHED=$(echo "$line" | grep -a -o -E -i "($REGEX_SENSITIVE)" | head -n 1)
        now=$(date +%s)
        last_time=${SENSITIVE_TIME["$IP"]:-0}
        count=${SENSITIVE_COUNT["$IP"]:-0}
        
        diff=$((now - last_time))
        if [[ $diff -le $THRESHOLD_TIME ]]; then
            count=$((count + 1))
        else
            count=1
        fi
        
        SENSITIVE_TIME["$IP"]=$now
        SENSITIVE_COUNT["$IP"]=$count
        
        if [[ $count -ge $THRESHOLD_LIMIT ]]; then
            ban_ip "$IP" "Akses File Sensitif ($count kali dalam ${THRESHOLD_TIME} detik)" "$line" "$MATCHED" "$DOMAIN" "$METHOD" "$PATH_URL" "$STATUS_CODE" "$REQ_TIME"
            SENSITIVE_COUNT["$IP"]=0
            continue
        else
            echo "[*] Warning IP $IP: Mengakses file sensitif $MATCHED ($count/$THRESHOLD_LIMIT)"
        fi
    fi

    # ==========================================================
    # 6. Notifikasi HTTP Error (4xx & 5xx) - NOTIF ONLY (TANPA BAN)
    # ==========================================================
    if [[ "${NOTIFY_HTTP_ERRORS:-true}" == "true" ]]; then
        if [[ "$STATUS_CODE" =~ ^[45][0-9]{2}$ ]]; then
            echo "[*] HTTP Error terdeteksi: $STATUS_CODE | $METHOD $PATH_URL dari IP $IP (Notif Only)"
            send_http_error_telegram "$IP" "$STATUS_CODE" "$METHOD" "$PATH_URL" "$REQ_TIME" "$USER_AGENT" "$DOMAIN"
        fi
    fi
done
