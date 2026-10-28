# 🛡️ OpenVPN Manager v4.4

A robust, production-grade OpenVPN installer and interactive TUI user manager for Linux. Extended with modern security hardening, rate limiting, abuse monitoring, and forensic JSON audit logging.

![License](https://img.shields.io/badge/license-MIT-blue.svg)
![Bash](https://img.shields.io/badge/language-Bash-4EAA25.svg)
![OS](https://img.shields.io/badge/OS-Ubuntu%20%7C%20Debian%20%7C%20RHEL%20%7C%20Fedora-orange.svg)

---

## ✨ Features

- 🖥️ **Interactive TUI:** Built-in `whiptail` interface for easy administration.
- 🔒 **Client Isolation:** `client-to-client` and `duplicate-cn` disabled by default.
- 🛡️ **Anti-Pivoting:** Automatic firewall blocks against local RFC1918 subnets (`10.0.0.0/8`, `172.16.0.0/12`, `192.168.0.0/16`) and cloud metadata IPs (`169.254.169.254`).
- ⚡ **DDoS & Flood Protection:** Rate-limiting SYN floods and connection spikes via `hashlimit`.
- 📊 **Forensic Audit Logging:** Real-time JSONL tracking (`/var/log/ovpn/audit.jsonl`) capturing client OS, versions, hardware IDs, real source IPs, and session durations.
- 🚨 **Bandwidth Abuse Monitor:** Automated per-CN bandwidth tracking with optional auto-ban triggering.
- 🔑 **Modern Cryptography:** AEAD Ciphers (`AES-256-GCM`, `CHACHA20-POLY1305`), `tls-crypt`, and hourly session key rotation (`reneg-sec 3600`).

---

## 🚀 Quick Start

Run the installer via terminal as `root`:

```bash
git clone [https://github.com/anti-ddos1337/openvpn-manager.git](https://github.com/anti-ddos1337/openvpn-manager.git)
cd openvpn-manager
sudo bash openvpn-manager.sh
