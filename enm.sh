#!/bin/bash

RESET='\033[0m'
DIM='\033[2m'
P2='\033[38;5;99m'
GRAY='\033[38;5;245m'
YELLOW='\033[38;5;221m'
RED='\033[38;5;203m'

log() { echo -e "$*" | tee -a "$LOGFILE"; }
info() { log " ${GRAY}$*${RESET}"; }
warn() { log " ${YELLOW}$*${RESET}"; }
err() { echo -e " ${RED}$*${RESET}"; }
ask() { echo -ne " $* "; }

section() {
  local line
  printf -v line '%54s' ''
  line="${line// /─}"
  log ""
  log "${P2} $*${RESET}"
  log "${P2}${line}${RESET}"
  log ""
}
step() {
  log ""
  log " ${P2}▸ $*${RESET}"
}

TARGET="${1:-}"
DOMAIN="${2:-}"

if [[ -z "$TARGET" ]]; then
  echo -e "${RED}usage: $0 <IP> [name]${RESET}"
  echo -e "${GRAY}Example: $0 10.10.11.100 connected${RESET}"
  exit 1
fi

if [[ -n "$DOMAIN" && "$DOMAIN" != *.* ]]; then
  DOMAIN="${DOMAIN}.htb"
fi

if ! [[ "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  echo -e "${RED}invalid IP: $TARGET${RESET}"
  exit 1
fi

LOGFILE="recon_${TARGET}.log"
: >"$LOGFILE"

for t in nmap ffuf; do
  if ! command -v "$t" &>/dev/null; then
    err "$t not found. Aborting."
    exit 1
  fi
done

# ── Port scan ──────────────────────────────────────────────────────────────────
section "port scan"

(ping -c 2 -W 2 "$TARGET" &>/dev/null || nmap -sn "$TARGET" 2>/dev/null | grep -q "Host is up") &
HOST_CHECK_PID=$!

nmap -sC -sV -F --open "$TARGET" 2>&1 | tee -a "$LOGFILE"

wait "$HOST_CHECK_PID" || {
  err "host $TARGET appears to be down or unreachable. Aborting."
  exit 1
}

OPEN_PORTS=$(grep -E '^[0-9]+/tcp.*open' "$LOGFILE" | awk -F/ '{print $1}' | tr '\n' ' ')

# ── /etc/hosts ─────────────────────────────────────────────────────────────────
if [[ -n "$DOMAIN" ]]; then
  section "/etc/hosts"
  if grep -qw "$TARGET" /etc/hosts 2>/dev/null; then
    warn "$TARGET already in /etc/hosts — skipping"
  elif grep -qw "$DOMAIN" /etc/hosts 2>/dev/null; then
    warn "$DOMAIN exists under a different IP"
    ask "replace with '$TARGET $DOMAIN'? [Y/n]"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
      sudo sed -i "\|${DOMAIN}|d" /etc/hosts
      printf '%s\t%s\n' "$TARGET" "$DOMAIN" | sudo tee -a /etc/hosts >/dev/null
      info "replaced → $TARGET $DOMAIN"
    fi
  else
    ask "add '$TARGET $DOMAIN' to /etc/hosts? [Y/n]"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
      printf '%s\t%s\n' "$TARGET" "$DOMAIN" | sudo tee -a /etc/hosts >/dev/null
      info "added → $TARGET $DOMAIN"
    fi
  fi
fi

# ── Service enumeration ────────────────────────────────────────────────────────
section "service enumeration"

WEB_TARGET="${DOMAIN:-$TARGET}"

SERVICES=0
if echo "$OPEN_PORTS" | grep -qw "21"; then
  SERVICES=$((SERVICES + 1))

  info "FTP — checking anonymous login"
  FTP_OUT=$(timeout 10 nmap -p 21 --script ftp-anon "$TARGET" 2>>"$LOGFILE" || true)
  if echo "$FTP_OUT" | grep -q "Anonymous FTP login allowed"; then
    warn "FTP anonymous login ALLOWED"
  else
    info "FTP anonymous login not allowed"
  fi
fi

if echo "$OPEN_PORTS" | grep -qwE "445|139"; then
  SERVICES=$((SERVICES + 1))
  info "SMB detected"

  if [[ -n "${HAS_TOOL[enum4linux - ng]:-}" ]]; then
    SMB_OUT=$(enum4linux-ng -A "$TARGET" 2>>"$LOGFILE" || true)
    echo "$SMB_OUT" >>"$LOGFILE"

    SMB_USERS=$(echo "$SMB_OUT" | grep -oP '(?<=user: )\S+' | tr '\n' ' ' || true)
    SMB_SHARES=$(echo "$SMB_OUT" | grep -oP '(?<=name: )\S+' | tr '\n' ' ' || true)

    [[ -n "$SMB_USERS" ]] && info "users: $SMB_USERS"
    [[ -n "$SMB_SHARES" ]] && info "shares: $SMB_SHARES"

  elif [[ -n "${HAS_TOOL[smbclient]:-}" ]]; then
    SMB_SHARES=$(smbclient -L "//$TARGET" -N 2>>"$LOGFILE" | awk '/Disk|IPC/{print $1}' | tr '\n' ' ' || true)
    [[ -n "$SMB_SHARES" ]] && info "shares: $SMB_SHARES"
  fi

  VULN_OUT=$(nmap -p 445 --script "smb-vuln*" "$TARGET" 2>>"$LOGFILE" || true)
  echo "$VULN_OUT" >>"$LOGFILE"
  VULNS=$(echo "$VULN_OUT" | grep -i "VULNERABLE" | sed 's/.*|//' | tr '\n' ' ' || true)
  [[ -n "$VULNS" ]] && warn "VULNERABLE: $VULNS"
fi

if echo "$OPEN_PORTS" | grep -qwE "389|636"; then
  SERVICES=$((SERVICES + 1))

  info "LDAP detected"
  LDAP_OUT=$(nmap -p 389 --script ldap-rootdse "$TARGET" 2>>"$LOGFILE" || true)
  echo "$LDAP_OUT" >>"$LOGFILE"
  LDAP_DN=$(echo "$LDAP_OUT" | grep -oP 'defaultNamingContext: \K.*' | head -1 || true)
  [[ -n "$LDAP_DN" ]] && info "DN: $LDAP_DN"
fi

if echo "$OPEN_PORTS" | grep -qwE "5985|5986"; then
  SERVICES=$((SERVICES + 1))
  warn "WinRM open — try evil-winrm after creds"
fi

[[ $SERVICES -eq 0 ]] && info "no enumerable services found"

# ── Web recon ──────────────────────────────────────────────────────────────────
RAW_WEB=$(grep -E '^[0-9]+/tcp.*open' "$LOGFILE" | grep -Ei 'http' | awk -F/ '{print $1}' | tr '\n' ' ')
WEB_PORTS=""

declare -A _SEEN
for _P in $RAW_WEB; do
  _S="http"
  [[ "$_P" == "443" ]] && _S="https"
  [[ -n "${_SEEN[$_S]:-}" ]] && continue
  [[ "$_P" == "80" ]] && echo "$RAW_WEB" | grep -qw "443" && continue
  _SEEN[$_S]=1
  WEB_PORTS="$WEB_PORTS $_P"
done

WEB_PORTS="${WEB_PORTS# }"

if [[ -n "$WEB_PORTS" ]]; then
  section "web recon — ports: $WEB_PORTS"

  DIR_WL="/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"
  DNS_WL="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  [[ ! -f "$DIR_WL" ]] && DIR_WL="/usr/share/wordlists/dirb/common.txt"
  [[ ! -f "$DNS_WL" ]] && DNS_WL="/usr/share/wordlists/dirb/common.txt"

  WEB_TARGET="${DOMAIN:-$TARGET}"

  for PORT in $WEB_PORTS; do
    SCHEME="http"
    [[ "$PORT" == "443" ]] && SCHEME="https"
    if [[ "$PORT" == "80" || "$PORT" == "443" ]]; then
      BASE_URL="${SCHEME}://${WEB_TARGET}"
    else
      BASE_URL="${SCHEME}://${WEB_TARGET}:${PORT}"
    fi

    INSECURE=""
    [[ "$SCHEME" == "https" ]] && INSECURE="-k"
    info "target: $BASE_URL"

    BS=$(curl -s -o /dev/null -w "%{size_download}" "${BASE_URL}/nonexistent8675309" $INSECURE 2>/dev/null || echo 0)
    BW=$(curl -s "${BASE_URL}/nonexistent8675309" $INSECURE 2>/dev/null | wc -w | tr -d ' ' || echo 0)
    info "baseline — size:${BS} words:${BW}"

    step "directories"
    ffuf -u "${BASE_URL}/FUZZ" -w "$DIR_WL" \
      -t 80 -fc 404,403 -fs "$BS" -fw "$BW" \
      $INSECURE -noninteractive 2>>"$LOGFILE" | tee -a "$LOGFILE"

    if [[ -n "$DOMAIN" ]]; then
      step "subdomains"
      SB=$(curl -s -o /dev/null -w "%{size_download}" "${SCHEME}://nonexistent8675309.${DOMAIN}" $INSECURE 2>/dev/null || echo 0)
      ffuf -u "${SCHEME}://FUZZ.${DOMAIN}" -w "$DNS_WL" \
        -t 20 -timeout 5 -fc 404,400 -fs "$SB" -fr \
        $INSECURE -noninteractive 2>>"$LOGFILE" | tee -a "$LOGFILE"

      step "vhosts"
      VB=$(curl -s -o /dev/null -w "%{size_download}" -H "Host: nonexistent8675309.${DOMAIN}" "${SCHEME}://${TARGET}" $INSECURE 2>/dev/null || echo 0)
      VW=$(curl -s -H "Host: nonexistent8675309.${DOMAIN}" "${SCHEME}://${TARGET}" $INSECURE 2>/dev/null | wc -w | tr -d ' ' || echo 0)
      ffuf -u "${SCHEME}://${TARGET}" -H "Host: FUZZ.${DOMAIN}" -w "$DNS_WL" \
        -t 15 -timeout 5 -fc 404,400 -fs "$VB" -fw "$VW" -fr \
        $INSECURE -noninteractive 2>>"$LOGFILE" | tee -a "$LOGFILE"
    fi
    log ""
  done
else
  warn "no web ports — skipping ffuf"
fi

log ""
log " ${DIM}Full log saved: $LOGFILE${RESET}"
log ""
