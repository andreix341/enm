#!/bin/bash

DIM='\033[2m'
P2='\033[38;5;99m'
GRAY='\033[38;5;245m'
YELLOW='\033[38;5;221m'
RED='\033[38;5;203m'
BLUE='[38;5;75m'
RESET='\033[0m'

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
}
subsection() {
  local line
  printf -v line '%40s' ''
  line="${line// /─}"
  log ""
  log " ${BLUE}$*${RESET}"
  log " ${BLUE}${line}${RESET}"
}

#/etc/hosts helper
add_host() {
  local host="$1"
  [[ -z "$host" ]] && return

  if grep -qw "$host" /etc/hosts 2>/dev/null; then
    info "$host already in /etc/hosts — skipping"

  elif grep -qP "^\s*${TARGET}\s" /etc/hosts 2>/dev/null; then
    ask "append '$host' to existing $TARGET line? [Y/n]"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
      sudo sed -i "/^\s*${TARGET}\s/s/$/ ${host}/" /etc/hosts
      info "appended → $host"
    fi

  else
    ask "add '$TARGET $host' to /etc/hosts? [Y/n]"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
      printf '%s\t%s\n' "$TARGET" "$host" | sudo tee -a /etc/hosts >/dev/null
      info "added → $TARGET $host"
    fi
  fi
}

# Argument parsing ------------------------------
TARGET=""
NAME=""
USER_ARG=""
PASS_ARG=""

usage() {
  echo -e "${RED}usage: $0 <IP> [-n name] [-u user] [-p password]${RESET}"
  echo -e "${GRAY}Example: $0 10.10.11.100 -n mybox -u admin -p 'P@ss1'${RESET}"
  exit 1
}

if [[ $# -lt 1 || "$1" == -* ]]; then
  usage
fi
TARGET="$1"
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
  -n)
    NAME="$2"
    shift 2
    ;;
  -u)
    USER_ARG="$2"
    shift 2
    ;;
  -p)
    PASS_ARG="$2"
    shift 2
    ;;
  *)
    err "unknown argument: $1"
    usage
    ;;
  esac
done

if ! [[ "$TARGET" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  err "invalid IP: $TARGET"
  exit 1
fi

DOMAIN=""
if [[ -n "$NAME" ]]; then
  if [[ "$NAME" == *.* ]]; then
    DOMAIN="$NAME"
  else
    DOMAIN="${NAME}.htb"
  fi
fi

LOGFILE="recon_${TARGET}.log"
: >"$LOGFILE"

for t in nmap ffuf; do
  if ! command -v "$t" &>/dev/null; then
    err "$t not found. Aborting."
    exit 1
  fi
done

# Port scan ------------------------------
section "port scan"

(ping -c 2 -W 2 "$TARGET" &>/dev/null || nmap -sn "$TARGET" 2>/dev/null | grep -q "Host is up") &
HOST_CHECK_PID=$!
nmap -sC -sV --top-ports 1000 --open "$TARGET" 2>&1 | tee -a "$LOGFILE"
wait "$HOST_CHECK_PID" || {
  err "host $TARGET appears to be down or unreachable. Aborting."
  exit 1
}
OPEN_PORTS=$(grep -E '^[0-9]+/tcp.*open' "$LOGFILE" | awk -F/ '{print $1}' | tr '\n' ' ')

# /etc/hosts ------------------------------
section "/etc/hosts"
[[ -n "$DOMAIN" ]] && add_host "$DOMAIN"

# Service enumeration ------------------------------
section "service enumeration"

if echo "$OPEN_PORTS" | grep -qwE "445|139"; then
  subsection "SMB"

  if command -v enum4linux-ng &>/dev/null; then
    ENUM_CREDS=""
    [[ -n "$USER_ARG" ]] && ENUM_CREDS="-u $USER_ARG"
    [[ -n "$PASS_ARG" ]] && ENUM_CREDS="$ENUM_CREDS -p $PASS_ARG"
    enum4linux-ng -A $ENUM_CREDS "$TARGET" 2>&1 | tee -a "$LOGFILE"

    VULN_OUT=$(nmap -p 445 --script "smb-vuln*" "$TARGET" 2>>"$LOGFILE" || true)
    echo "$VULN_OUT" >>"$LOGFILE"
    VULNS=$(echo "$VULN_OUT" | grep -i "VULNERABLE" | sed 's/.*|//' | tr '\n' ' ' || true)
    [[ -n "$VULNS" ]] && warn "VULNERABLE: $VULNS"
  else
    warn "enum4linux-ng not found — skipping"
  fi

else
  subsection "SMB"
  info "not detected"
fi

if echo "$OPEN_PORTS" | grep -qwE "389|636"; then
  subsection "LDAP"

  LDAP_OUT=$(nmap -p 389 --script ldap-rootdse "$TARGET" 2>>"$LOGFILE" || true)
  echo "$LDAP_OUT" >>"$LOGFILE"
  LDAP_DN=$(echo "$LDAP_OUT" | grep -oP 'defaultNamingContext: \K.*' | head -1 || true)
  [[ -n "$LDAP_DN" ]] && info "DN: $LDAP_DN"

  LDAP_FQDN=$(echo "$LDAP_OUT" | grep -oP 'dnsHostName: \K.*' | head -1 || true)
  LDAP_DOMAIN=$(echo "$LDAP_DN" | sed 's/DC=//g; s/,/./g' | tr '[:upper:]' '[:lower:]' || true)

  if [[ -n "$LDAP_FQDN" || -n "$LDAP_DOMAIN" ]]; then
    subsection "/etc/hosts - ldap discovered"
    [[ -n "$LDAP_DOMAIN" && "$LDAP_DOMAIN" != "$DOMAIN" ]] && add_host "$LDAP_DOMAIN"
    [[ -n "$LDAP_FQDN" && "$LDAP_FQDN" != "$DOMAIN" ]] && add_host "$LDAP_FQDN"
  fi

  if command -v ldapsearch &>/dev/null; then
    subsection "ldap - anonymous enumeration"

    info "naming contexts:"
    ldapsearch -x -H "ldap://${TARGET}" -s base namingContexts 2>>"$LOGFILE" |
      grep -v "^#\|^$\|^search\|^result\|^dn:" |
      tee -a "$LOGFILE"

    if [[ -n "$LDAP_DN" ]]; then
      info "users (sAMAccountName, cn, description):"
      ldapsearch -x -H "ldap://${TARGET}" -b "$LDAP_DN" \
        "(objectClass=person)" sAMAccountName cn description \
        2>>"$LOGFILE" |
        grep -v "^#\|^$\|^search\|^result\|^version" |
        tee -a "$LOGFILE"

      info "groups:"
      ldapsearch -x -H "ldap://${TARGET}" -b "$LDAP_DN" \
        "(objectClass=group)" cn member \
        2>>"$LOGFILE" |
        grep -v "^#\|^$\|^search\|^result\|^version" |
        tee -a "$LOGFILE"

      info "password policy:"
      ldapsearch -x -H "ldap://${TARGET}" -b "$LDAP_DN" \
        "(objectClass=domainDNS)" minPwdLength pwdHistoryLength lockoutThreshold \
        2>>"$LOGFILE" |
        grep -v "^#\|^$\|^search\|^result\|^version" |
        tee -a "$LOGFILE"
    fi
  else
    warn "ldapsearch not found - skipping anonymous enumeration"
  fi

  if [[ -n "$USER_ARG" && -n "$PASS_ARG" ]]; then
    if command -v ldapdomaindump &>/dev/null; then
      subsection "ldap - full dump (ldapdomaindump)"
      DUMP_DIR="ldap_dump_${TARGET}"
      mkdir -p "$DUMP_DIR"

      AUTH_URL="ldap://${TARGET}"

      if [[ -n "$DOMAIN" ]]; then
        NETBIOS_DOMAIN=$(echo "$DOMAIN" | cut -d. -f1 | tr '[:lower:]' '[:upper:]')
        BIND_DN="${NETBIOS_DOMAIN}\\${USER_ARG}"
      else
        BIND_DN="${USER_ARG}"
      fi

      ldapdomaindump \
        -u "$BIND_DN" \
        -p "$PASS_ARG" \
        --no-json --no-grep \
        -o "$DUMP_DIR" \
        "$AUTH_URL" \
        2>&1 | tee -a "$LOGFILE"

      if [[ -f "${DUMP_DIR}/domain_users.html" ]]; then
        info "dump saved to: $DUMP_DIR/"
        info "open ${DUMP_DIR}/domain_users.html in a browser for full output"
      fi

      if [[ -f "${DUMP_DIR}/domain_users_by_group.grep" ]]; then
        subsection "ldap — users with descriptions"
        grep -v "^#" "${DUMP_DIR}/domain_users_by_group.grep" |
          awk -F'\t' '$10 != "" {print $3, "|", $10}' |
          tee -a "$LOGFILE" || true
      fi

    else
      warn "ldapdomaindump not found - install with: pip install ldapdomaindump"
      warn "falling back to authenticated ldapsearch"

      if command -v ldapsearch &>/dev/null && [[ -n "$LDAP_DN" ]]; then
        BIND_DN="${USER_ARG}@${DOMAIN:-$TARGET}"
        subsection "ldap — authenticated ldapsearch"
        ldapsearch -x -H "ldap://${TARGET}" \
          -D "$BIND_DN" -w "$PASS_ARG" \
          -b "$LDAP_DN" \
          "(objectClass=person)" sAMAccountName cn memberOf description pwdLastSet \
          2>>"$LOGFILE" |
          grep -v "^#\|^$\|^search\|^result\|^version" |
          tee -a "$LOGFILE"
      fi
    fi
  fi
else
  subsection "LDAP"
  info "not detected"
fi

if echo "$OPEN_PORTS" | grep -qwE "5985|5986"; then
  subsection "WinRM"
  if [[ -n "$USER_ARG" ]]; then
    warn "WinRM detected, try:"
    warn "evil-winrm -i $TARGET -u '$USER_ARG' -p '$PASS_ARG'"
  else
    warn "try evil-winrm after creds"
  fi
else
  subsection "WinRM"
  info "not detected"
fi

# Web recon ------------------------------
section 'Web Recon'
WEB_BLOCKLIST="593 5985 5986 47001"

RAW_WEB=$(grep -E '^[0-9]+/tcp.*open' "$LOGFILE" |
  awk '$3 ~ /^https?$/' |
  awk -F/ '{print $1}' | tr '\n' ' ')
WEB_PORTS=""

declare -A _SEEN
for _P in $RAW_WEB; do
  _S="http"
  [[ "$_P" == "443" ]] && _S="https"

  if echo "$WEB_BLOCKLIST" | grep -qw "$_P"; then
    info "skipping port $_P (blocklisted — not a web app)"
    continue
  fi

  [[ -n "${_SEEN[$_S]:-}" ]] && continue
  [[ "$_P" == "80" ]] && echo "$RAW_WEB" | grep -qw "443" && continue
  _SEEN[$_S]=1
  WEB_PORTS="$WEB_PORTS $_P"
done

WEB_PORTS="${WEB_PORTS# }"

if [[ -n "$WEB_PORTS" ]]; then
  info "ports: $WEB_PORTS"
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

    BS=$(curl -s -o /dev/null -w "%{size_download}" "${BASE_URL}/nonexistent8675309" $INSECURE 2>/dev/null || echo 0)
    BW=$(curl -s "${BASE_URL}/nonexistent8675309" $INSECURE 2>/dev/null | wc -w | tr -d ' ' || echo 0)

    subsection "directories — ${BASE_URL}"
    info "baseline — size:${BS} words:${BW}"
    ffuf -u "${BASE_URL}/FUZZ" -w "$DIR_WL" \
      -t 80 -fc 404,403 -fs "$BS" -fw "$BW" \
      $INSECURE -noninteractive 2>>"$LOGFILE" | tee -a "$LOGFILE"

    if [[ -n "$DOMAIN" ]]; then
      subsection "subdomains (light) — ${DOMAIN}"
      SB=$(curl -s -o /dev/null -w "%{size_download}" "${SCHEME}://nonexistent8675309.${DOMAIN}" $INSECURE 2>/dev/null || echo 0)
      ffuf -u "${SCHEME}://FUZZ.${DOMAIN}" -w "$DNS_WL" \
        -t 20 -timeout 5 -fc 404,400 -fs "$SB" -fr \
        $INSECURE -noninteractive 2>>"$LOGFILE" | tee -a "$LOGFILE"

      subsection "vhosts (light) — ${DOMAIN}"
      VB=$(curl -s -o /dev/null -w "%{size_download}" -H "Host: nonexistent8675309.${DOMAIN}" "${SCHEME}://${TARGET}" $INSECURE 2>/dev/null || echo 0)
      VW=$(curl -s -H "Host: nonexistent8675309.${DOMAIN}" "${SCHEME}://${TARGET}" $INSECURE 2>/dev/null | wc -w | tr -d ' ' || echo 0)
      ffuf -u "${SCHEME}://${TARGET}" -H "Host: FUZZ.${DOMAIN}" -w "$DNS_WL" \
        -t 15 -timeout 5 -fc 404,400 -fs "$VB" -fw "$VW" -fr \
        $INSECURE -noninteractive 2>>"$LOGFILE" | tee -a "$LOGFILE"
    fi
  done
else
  warn "no web ports - skipping ffuf"
fi

log ""
log " ${DIM}Full log saved: $LOGFILE${RESET}"
log ""
