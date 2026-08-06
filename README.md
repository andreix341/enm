# enm

A script i made to quickly scan machines on HackTheBox.

---

### Tools

- **nmap** - port scanner
- **nxc (NetExec)** - SMB/LDAP/FTP recon & credential attacks
- **ffuf** - web fuzzing (directories, subdomains, vhosts)
- **wpscan** - WordPress scanning
- **evil-winrm** - WinRM login test

---

### Modules

- **nmap** - port scan with `-sC -sV --open --top-ports 1000` (add `-f` for full `-p-` scan), results cached & reused in `nmap_<IP>.txt`
- **smb** - banner grab, plus shares, users, local groups, logged-on users, RID brute & password policy with credentials (139/445)
- **ldap** - domain context, users & groups, admin count, trusted-for-delegation & password-not-required flags (389/636/3268/3269)
- **ftp** - banner + anonymous/authenticated listing (21)
- **creds** - credential dumping (SAM/LSA/DPAPI, NTDS, ntdsutil, lsassy, LAPS, gMSA, GPP, MSOL)
- **roasting** - Kerberoasting & AS-REP roasting (output saved to .txt)
- **web** - directory, subdomain & vhost fuzzing via `ffuf`, plus WordPress scan via `wpscan` (all open web ports, HTTPS supported)
- **winrm** - detection hint + auto `evil-winrm` login test (5985/5986)

On top of the modules, the script also manages **/etc/hosts** - automatically adds new entries, replaces or appends to old ones.

---

### Usage

```bash
enm <IP> [options]

  -n <name>      hostname for /etc/hosts (defaults to <name>.htb)
  -m <modules>   comma-separated list (default: all)
                 available: nmap,smb,ldap,ftp,creds,roasting,web,winrm
  -u <user>      username (enables authenticated enumeration)
  -p <pass>      password
  -f             full port scan (-p-) instead of top 1000

# Examples
enm 10.10.11.100 -n mybox
enm 10.10.11.100 -n mybox -u admin -p 'P@ss1'
enm 10.10.11.100 -n mybox -u admin -p 'P@ss1' -m smb,web
```

All output is logged to `recon_<IP>.log`.

---

### Installation

Install all required tools for your distro, then install the script.

**Kali**

```bash
apt update
apt install nmap seclists ffuf wpscan evil-winrm netexec
```

**BlackArch**

```bash
pacman -Syu nmap seclists ffuf wpscan evil-winrm netexec
```

**ParrotSec**

```bash
apt update
apt install nmap seclists ffuf wpscan evil-winrm netexec
```

**Install the script**

```bash
git clone https://github.com/yourusername/enm.git
cd enm

sudo cp enm.sh /usr/bin/enm
sudo chmod 755 /usr/bin/enm
```
