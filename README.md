# anti-php2shell

Zero-dependency defense, vulnerability audit, and inoculation tool against PHP2Shell (CVE-2026-109618 and CVE-2026-109619).

---

## Masalah Operasional (The Real Problem)

Publikasi celah PHP2Shell (CVE-2026-109618 dan CVE-2026-109619) dengan skor CVSS 9.2 memungkinkan unauthenticated remote code execution (RCE) langsung pada core runtime PHP dari versi 5.4 hingga 8.5 melalui heap corruption pada modul `session.upload_progress`. Karena bug ini berada pada level binary runtime PHP (bukan composer dependency), dependabot dan audit SCA biasa tidak bisa mendeteksinya. Lebih buruk lagi, banyak server di production tidak bisa langsung di-reboot atau di-compile ulang seketika saat eksploitasi publik mulai membanjiri akses jaringan.

`anti-php2shell` dibangun dengan Python standard library murni (zero-dependency) agar dapat langsung di-drop ke server production, container Docker, atau pipeline CI/CD tanpa perlu `pip install`.

---

## Cara Kerja (Under the Hood)

1. **System & SAPI Auditor (`scan`):** Memeriksa binary PHP lokal, mengecek versi terhadap threshold patch resmi (8.2.35, 8.3.36, 8.4.27, 8.5.12), memetakan SAPI aktif (Apache mod_php, PHP-FPM, FrankenPHP), serta membaca status direktif `session.upload_progress.enabled` di seluruh `php.ini`.
2. **Active Inoculator & Virtual Patch Generator (`vaccine`):** Melakukan patching in-place yang aman dengan backup timestamp otomatis pada `php.ini` (`session.upload_progress.enabled = 0`), sekaligus men-generate virtual patch rules untuk Nginx, Apache (.htaccess), Caddy, dan Cloudflare WAF guna memblokir payload sebelum mencapai worker PHP.
3. **Forensic Log Hunter (`hunt`):** Memindai access log dan error log web server (Nginx/Apache/PHP-FPM) untuk mendeteksi signature serangan `PHP_SESSION_UPLOAD_PROGRESS` dan korelasi worker SIGSEGV (signal 11 / exit code 139) akibat memory corruption.
4. **Harmless Canary Probe (`check`):** Mengirimkan multipart probe non-destruktif untuk memverifikasi apakah filter WAF atau konfigurasi server sudah aktif memblokir vektor serangan tanpa merusak stabilitas server.

---

## Quickstart & Terminal Execution

### 1. Audit Kerentanan Server Lokal

```bash
$ python3 run.py scan

--- ANTI-PHP2SHELL SECURITY AUDIT ---
PHP Binary: /usr/bin/php
Detected Version: 8.3.6
Active SAPI(s): None detected
session.upload_progress: ENABLED (Dangerous)
Found php.ini files: 3
  - /etc/php/8.3/apache2/php.ini
  - /etc/php/8.3/cli/php.ini
  - /etc/php/8.3/fpm/php.ini

Audit Status: [HIGH RISK]
Details: PHP 8.3.6 vulnerable with session.upload_progress.enabled=1.
```

### 2. Inokulasi dan Export WAF Virtual Patch

```bash
$ python3 run.py vaccine --out-dir ./waf-rules

--- ANTI-PHP2SHELL ACTIVE INOCULATION ---
Generating WAF Virtual Patch rules in: ./waf-rules
  [GENERATED] Nginx: waf-rules/nginx_anti_php2shell.conf
  [GENERATED] Apache (.htaccess): waf-rules/apache_anti_php2shell.conf
  [GENERATED] Caddy: waf-rules/caddy_anti_php2shell.snippet
  [GENERATED] Cloudflare WAF Expression: waf-rules/cloudflare_waf_rule.txt

Reminder: Reload your web server or PHP-FPM service to activate changes.
```

### 3. Pindai Log Forensik untuk Deteksi Serangan

```bash
$ python3 run.py hunt --log /var/log/nginx/access.log

--- ANTI-PHP2SHELL FORENSIC LOG HUNTER ---
Inspecting target path: /var/log/nginx/access.log
Lines Scanned: 154,230
Incidents Detected: 4

[INCIDENTS DETECTED]

Breakdown by Category:
  - EXPLOIT_PROBE_UPLOAD_PROGRESS: 4

Top Suspect Source IPs:
  - 198.51.100.42: 4 attempts
```

### 4. Uji Verifikasi Endpoint (Canary Test)

```bash
$ python3 run.py check --url http://localhost/test.php

--- ANTI-PHP2SHELL CANARY VERIFIER ---
Probing: http://localhost/test.php
Result: [PROTECTED]
Server response code: HTTP 403
Status: HTTP 403 returned. WAF or virtual patch is successfully blocking PHP2Shell parameters.
```

---

## Struktur Proyek

```
anti-php2shell/
├── anti_php2shell/
│   ├── __init__.py           # Package marker dan version info
│   ├── checker.py            # Harmless canary HTTP probe
│   ├── cli.py                # Command-line interface dan subcommands
│   ├── hunter.py             # Log forensic analyzer dan SIGSEGV detector
│   ├── scanner.py            # SAPI, PHP binary dan php.ini auditor
│   └── vaccine.py            # INI patcher dan generator aturan WAF
├── tests/
│   ├── test_hunter.py        # Unit test analisis log dan pattern match
│   ├── test_scanner.py       # Unit test versi dan parser php.ini
│   └── test_vaccine.py       # Unit test inokulasi dan WAF exporter
├── waf-rules/                # Direktori output aturan WAF
├── run.py                    # Root CLI entrypoint
├── README.md                 # Dokumentasi operasional
└── .gitignore                # Filter git
```

---

## Menjalankan Unit Test

Unit test menggunakan modul `unittest` bawaan Python:

```bash
python3 -m unittest discover -s tests -v
```
