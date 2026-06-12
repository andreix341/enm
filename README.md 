# enm

A simple script i made to quickly scan machines on HackTheBox.

---

### Tools & scans

- **nmap** — fast port scan `-sC -sV -F --open` (top 100 ports)
- **SMB** — os info, shares, users & vuln scan via enum4linux-ng + nmap scripts (139/445)
- **LDAP** — domain context retrieval (389/636)
- **WinRM** — detection hint (5985/5986)
- **ffuf** — directory, subdomain & vhost fuzzing (all open web ports)

### Installation

```bash
# Install dependencies
sudo apt update
sudo apt install nmap ffuf seclists curl -y

# Clone and install
git clone https://github.com/yourusername/enm.git
cd enm

sudo cp enm.sh /usr/bin/enm
sudo chmod 755 /usr/bin/enm
```
