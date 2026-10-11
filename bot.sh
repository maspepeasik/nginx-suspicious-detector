#!/bin/bash

# ==========================================================
# Auto-Ban Bot for Nginx via Fail2ban
# ==========================================================

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" &> /dev/null && pwd)"

CONFIG_FILE="${SCRIPT_DIR}/.env"
if [[ ! -f "$CONFIG_FILE" ]]; then echo "[!] Error: File .env tidak ditemukan! Silakan salin dari .env.example"; exit 1; fi
if [[ -f "$CONFIG_FILE" ]]; then
    source "$CONFIG_FILE"
else
    echo "[!] Error: File konfigurasi $CONFIG_FILE tidak ditemukan!"
    exit 1
fi

TARGET_LOGS="${LOG_FILES:-$LOG_FILE}"
[[ -z "$TARGET_LOGS" ]] && TARGET_LOGS="/var/log/nginx/access.log"

# Lokasi file pola berdasarkan kategori
PATTERN_SQLI="${PATTERN_SQLI:-${SCRIPT_DIR}/patterns_sqli.txt}"
PATTERN_XSS="${PATTERN_XSS:-${SCRIPT_DIR}/patterns_xss.txt}"
PATTERN_TRAVERSAL="${PATTERN_TRAVERSAL:-${SCRIPT_DIR}/patterns_traversal.txt}"
PATTERN_RCE="${PATTERN_RCE:-${SCRIPT_DIR}/patterns_rce.txt}"
PATTERN_SENSITIVE="${PATTERN_SENSITIVE:-${SCRIPT_DIR}/patterns_sensitive.txt}"

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

# Stream log Nginx
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

# Fungsi Kirim Notifikasi Telegram
send_telegram() {
    local ip="$1"
    local category="$2"
    local logline="$3"
    local payload="$4"
    local domain="$5"
    local method="$6"
    local path_url="$7"
    local status_code="$8"
    
    if [[ -n "$TELEGRAM_BOT_TOKEN" && -n "$TELEGRAM_CHAT_ID" ]]; then
        local text="🚨 <b>AUTO-BAN ALERT</b> 🚨

🛑 <b>IP Terblokir:</b> <code>$ip</code>
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
        echo "[!] BAN TRIGGERED: IP $ip | $category | Domain: $domain"
        
        result=$(run_as_root fail2ban-client set "$JAIL_NAME" banip "$ip" 2>/dev/null)
        
        if [[ "$result" == "1" ]]; then
            echo "[*] IP $ip berhasil diban."
            send_telegram "$ip" "$category" "$logline" "$payload" "$domain" "$method" "$path_url" "$status_code"
        elif [[ "$result" == "0" ]]; then
            echo "[*] IP $ip sudah dalam status ban."
        else
            echo "[!] Gagal melakukan ban terhadap IP $ip."
        fi
    fi
}

echo "[*] Auto-Ban Bot berjalan..."

# State untuk Threshold File Sensitif
declare -A SENSITIVE_COUNT
declare -A SENSITIVE_TIME

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
    # 1. Cek dari field host di akhir log (jika Nginx mencatat "$host")
    LAST_QUOTE=$(echo "$line" | awk -F'"' '{print $(NF-1)}')
    DOMAIN=""
    if [[ -n "$LAST_QUOTE" && "$LAST_QUOTE" != "-" && ! "$LAST_QUOTE" =~ [[:space:]] && "$LAST_QUOTE" =~ \. ]]; then
        DOMAIN="$LAST_QUOTE"
    fi
    
    # 2. Jika belum dapat, cek dari Referer
    if [[ -z "$DOMAIN" ]]; then
        REFERER_DOMAIN=$(echo "$line" | grep -oP 'https?://\K[^/"\s:]+' | head -n 1)
        if [[ -n "$REFERER_DOMAIN" ]]; then
            DOMAIN="$REFERER_DOMAIN"
        fi
    fi
    
    # 3. Fallback jika tidak ditemukan
    [[ -z "$DOMAIN" ]] && DOMAIN="Direct Access (No Host Header)"
    
    # ==========================================================
    # 1. Kategori: SQL Injection (SQLi) -> INSTANT BAN
    # ==========================================================
    if [[ -n "$REGEX_SQLI" ]] && echo "$line" | grep -a -E -q -i "($REGEX_SQLI)"; then
        MATCHED=$(echo "$line" | grep -a -o -E -i "($REGEX_SQLI)" | head -n 1)
        ban_ip "$IP" "SQL Injection (SQLi)" "$line" "$MATCHED" "$DOMAIN" "$METHOD" "$PATH_URL" "$STATUS_CODE"
        continue
    fi
    
    # ==========================================================
    # 2. Kategori: Cross-Site Scripting (XSS) -> INSTANT BAN
    # ==========================================================
    if [[ -n "$REGEX_XSS" ]] && echo "$line" | grep -a -E -q -i "($REGEX_XSS)"; then
        MATCHED=$(echo "$line" | grep -a -o -E -i "($REGEX_XSS)" | head -n 1)
        ban_ip "$IP" "Cross-Site Scripting (XSS)" "$line" "$MATCHED" "$DOMAIN" "$METHOD" "$PATH_URL" "$STATUS_CODE"
        continue
    fi
    
    # ==========================================================
    # 3. Kategori: Path Traversal / LFI -> INSTANT BAN
    # ==========================================================
    if [[ -n "$REGEX_TRAVERSAL" ]] && echo "$line" | grep -a -E -q -i "($REGEX_TRAVERSAL)"; then
        MATCHED=$(echo "$line" | grep -a -o -E -i "($REGEX_TRAVERSAL)" | head -n 1)
        ban_ip "$IP" "Path Traversal / Local File Inclusion (LFI)" "$line" "$MATCHED" "$DOMAIN" "$METHOD" "$PATH_URL" "$STATUS_CODE"
        continue
    fi
    
    # ==========================================================
    # 4. Kategori: Remote Code Execution (RCE) -> INSTANT BAN
    # ==========================================================
    if [[ -n "$REGEX_RCE" ]] && echo "$line" | grep -a -E -q -i "($REGEX_RCE)"; then
        MATCHED=$(echo "$line" | grep -a -o -E -i "($REGEX_RCE)" | head -n 1)
        ban_ip "$IP" "Remote Code Execution (RCE)" "$line" "$MATCHED" "$DOMAIN" "$METHOD" "$PATH_URL" "$STATUS_CODE"
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
            ban_ip "$IP" "Akses File Sensitif ($count kali dalam ${THRESHOLD_TIME} detik)" "$line" "$MATCHED" "$DOMAIN" "$METHOD" "$PATH_URL" "$STATUS_CODE"
            SENSITIVE_COUNT["$IP"]=0
        else
            echo "[*] Warning IP $IP: Mengakses file sensitif $MATCHED ($count/$THRESHOLD_LIMIT)"
        fi
    fi
done
