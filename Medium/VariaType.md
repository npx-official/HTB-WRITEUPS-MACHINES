# VariaType — HackTheBox Writeup  WIP

**Target:** `variatype.htb`
**OS:** Linux (Debian 12)
**Difficulty:** Medium
**Tech stack:** OpenSSH 9.2p1, nginx 1.22.1
**Status:**  *Recon stage only — initial access not yet documented.*

---

## 1. Reconnaissance

```bash
ping $TARGET -c1            # ttl=63  Linux
nmap -sS -p- -n -Pn --min-rate 5000 $TARGET -oN silent
nmap -sVC -p22,80 $TARGET -oN service
```

| Port | Service |
|------|---------|
| 22/tcp | OpenSSH 9.2p1 (Debian 12) |
| 80/tcp | nginx 1.22.1 — redirects to `http://variatype.htb/` |

Add `variatype.htb` to `/etc/hosts`.

---

## 2. Web + VHost Enumeration

```bash
ffuf -u "http://variatype.htb/FUZZ" \
     -w /usr/share/wordlists/seclists/Discovery/Web-Content/DirBuster-2007_directory-list-2.3-medium.txt \
     -recursion -recursion-depth 3

gobuster vhost -u http://variatype.htb \
  -w /usr/share/wordlists/seclists/Discovery/DNS/subdomains-top1million-5000.txt \
  --append-domain
# portal.variatype.htb  Status: 200 [Size: 2494]    admin portal
```

Add `portal.variatype.htb` to `/etc/hosts`.

### Deep recursive sweep (file extensions + recursion)

```bash
feroxbuster \
  -u http://variatype.htb \
  -w /usr/share/wordlists/seclists/Discovery/Web-Content/raft-medium-directories-lowercase.txt \
  -x php,py,ttf,designspace,git,log,json,txt,html,bak,old,backup,swp,sql,db,config \
  -d 4 -t 80 \
  -C 404,403 -s 200,204,301,302,307 \
  --redirects --force-recursion \
  -o ferox_completo.txt
```

The `.designspace` / `.ttf` extension hint suggests this is a font-management application — mass-fuzz for those plus standard web extensions.

---

## TODO

- [ ] Document the initial-access primitive once the portal entry point is identified.
- [ ] Extract whatever foothold technique pays off into `exploits/`.
- [ ] User  root chain.

---

## Related Notes
- [nmap](../../../tools/recon/nmap.md), [ffuf](../../../tools/fuzz/ffuf.md), [gobuster](../../../tools/fuzz/gobuster.md), [feroxbuster](../../../tools/fuzz/feroxbuster.md)
