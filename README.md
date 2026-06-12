# enm

A simple script i made to quickly scan machines on HackTheBox.

---

### Tools & scans

- **nmap** — fast port scan `-sC -sV --top-ports 1000 --open` (top 1000 ports)
- **/etc/hosts** - automatically adds new entries and replaces / removes old ones
- **SMB** — os info, shares, users & vuln scan via enum4linux-ng + nmap scripts (139/445)
- **LDAP** — domain context retrieval (389/636)
- **WinRM** — detection hint (5985/5986)
- **ffuf** — directory, subdomain & vhost fuzzing (all open web ports)

### Usage 

```bash 
enm <IP> [name]

#Example 
enm 10.129.244.177 snapped
```

### Installation

```bash
# Install dependencies
sudo apt update
sudo apt install nmap ffuf enum4linux-ng seclists curl -y

# Clone and install
git clone https://github.com/yourusername/enm.git
cd enm

sudo cp enm.sh /usr/bin/enm
sudo chmod 755 /usr/bin/enm
```
