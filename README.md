# 🛡️ Kali Linux Advanced Security Hardening Framework

<div align="center">

```ascii
╔══════════════════════════════════════════════════════════════════╗
║                                                                  ║
║    ██╗  ██╗ █████╗ ██╗     ██╗    ██╗  ██╗ █████╗ ██████╗       ║
║    ██║ ██╔╝██╔══██╗██║     ██║    ██║  ██║██╔══██╗██╔══██╗      ║
║    █████╔╝ ███████║██║     ██║    ███████║███████║██████╔╝      ║
║    ██╔═██╗ ██╔══██║██║     ██║    ██╔══██║██╔══██║██╔══██╗      ║
║    ██║  ██╗██║  ██║███████╗██║    ██║  ██║██║  ██║██║  ██║      ║
║    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝      ║
║                                                                  ║
║                 ADVANCED SECURITY HARDENING                      ║
║                                                                  ║
╚══════════════════════════════════════════════════════════════════╝
```

[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![Shell](https://img.shields.io/badge/Shell-Bash-green.svg)](https://www.gnu.org/software/bash/)
[![Platform](https://img.shields.io/badge/Platform-Kali%20Linux-red.svg)](https://www.kali.org/)
[![Security](https://img.shields.io/badge/Security-Enterprise%20Grade-blue.svg)](#)
[![NSA](https://img.shields.io/badge/Compliance-NSA%20Guidelines-darkblue.svg)](#)

*Professional-grade security hardening framework implementing enterprise and government security standards*

</div>

## ⚠️ **CRITICAL WARNING**

> **🚨 EXPERIMENTAL SOFTWARE - USE AT YOUR OWN RISK**
>
> This script is **UNTESTED** and designed exclusively for **Kali Linux**. It implements aggressive security measures that may render your system inaccessible if misconfigured.
>
> **ONLY** execute on **DISPOSABLE VIRTUAL MACHINES** or **SECONDARY TEST SYSTEMS**.
>
> **DO NOT** run on production systems, primary workstations, or critical infrastructure.

## 🎯 Overview

This advanced security hardening framework transforms a standard Kali Linux installation into a fortress-grade secure system by implementing multiple layers of defense mechanisms. The script incorporates security standards and best practices derived from **NSA Security Configuration Guides** and **US Government hardening requirements**, providing a solid foundation for high-security environments.

## 🏛️ Government & NSA Compliance

This framework implements numerous security controls that align with:

- **NSA Security Configuration Guides (SCG)**
- **NIST Cybersecurity Framework**
- **DISA Security Technical Implementation Guides (STIG)**
- **Defense Information Systems Agency (DISA) hardening standards**
- **Federal Information Processing Standards (FIPS)**

While not implementing every possible control, this script provides a **robust security baseline** that meets or exceeds many government-mandated security requirements.

## 🔐 Security Features

### 🛡️ **Mandatory Access Control (MAC)**
- **AppArmor** enforcement with strict policy application
- Profile enforcement for all system applications
- Principle of least privilege implementation

### 🔑 **Identity & Access Management**
- **SSH hardening** with non-standard port configuration
- **Root access elimination** via SSH
- **Two-Factor Authentication (2FA)** framework setup
- **Complex password policies** with regular expiration
- **Key-based authentication** enforcement

### 📊 **Advanced Auditing & Monitoring**
- **System call auditing** with auditd
- **File system integrity monitoring** using AIDE
- **Centralized logging** infrastructure
- **Security event correlation** and alerting
- **Automated security assessments** with Lynis

### ⚙️ **Kernel-Level Hardening**
- **Address Space Layout Randomization (ASLR)** enforcement
- **Stack execution protection** activation
- **Network parameter hardening** (SYN cookies, IP forwarding controls)
- **Kernel pointer restriction** for information disclosure prevention
- **Process tracing limitations** via Yama LSM

### 🔥 **Network Security Controls**
- **Zero-trust firewall configuration** with UFW
- **Default-deny policies** for ingress and egress traffic
- **Intrusion prevention system** with Fail2Ban
- **Network protocol hardening** (IPv4/IPv6 security controls)
- **DDoS mitigation** techniques

### 🎯 **Attack Surface Reduction**
- **Unnecessary service elimination**
- **Network protocol disabling** (insecure protocols)
- **Kernel module blacklisting**
- **System resource access restrictions**

### 🔄 **Automated Security Maintenance**
- **Unattended security updates** configuration
- **Patch management** automation
- **Log rotation** and retention policies
- **System integrity verification** scheduling

## 🚀 Installation & Usage

### Prerequisites
- **Kali Linux** (latest version recommended)
- **Root privileges** required
- **Active internet connection** for package installation
- **Virtual Machine environment** (strongly recommended)

### Quick Start

```bash
# Clone the repository
git clone https://github.com/zar7real/kali-hardening-framework.git

# Navigate to directory
cd kali-hardening-framework

# Make script executable
chmod +x kali_hardening.sh

# Execute with root privileges
sudo ./kali_hardening.sh
```

## 📋 Implementation Details

<details>
<summary><strong>🔧 Technical Implementation Breakdown</strong></summary>

### Access Control
- **AppArmor profiles** enforced system-wide
- **SSH configuration** locked down with key-based auth only
- **User privilege escalation** controls via sudo policies
- **Service account restrictions** and isolation

### System Monitoring
- **Audit rules** for critical system events (file access, privilege escalation, network connections)
- **Real-time log analysis** with centralized collection
- **File integrity baselines** established and monitored
- **Process execution tracking** and anomaly detection

### Network Hardening
- **Iptables/UFW rules** implementing zero-trust architecture
- **Network stack hardening** via sysctl parameters
- **Protocol-level security** (TCP sequence randomization, ICMP restrictions)
- **Intrusion detection** with automated response capabilities

### Cryptographic Controls
- **Strong cipher enforcement** for SSH and system services
- **Secure random number generation** configuration
- **Certificate validation** hardening
- **Cryptographic protocol restrictions** (deprecated algorithm disabling)

</details>

## ⚡ Post-Execution Requirements

After successful execution, complete these **mandatory steps**:

### 🔐 **Two-Factor Authentication Setup**
```bash
# Switch to your user account
su - kali

# Configure Google Authenticator
google-authenticator
```

### 🛡️ **GRUB Bootloader Protection**
```bash
# Generate password hash
grub-mkpasswd-pbkdf2

# Add to GRUB configuration
echo "set superusers=\"admin\"" >> /etc/grub.d/40_custom
echo "password_pbkdf2 admin [YOUR_HASH_HERE]" >> /etc/grub.d/40_custom

# Regenerate GRUB configuration
update-grub
```

### 🔍 **SSH Access Verification**
⚠️ **Critical**: Test SSH access on **port 2222** before closing current session
```bash
# From another terminal/machine
ssh -p 2222 kali@your_kali_ip
```

## 📊 Security Assessment

The framework includes automated security scoring using **Lynis**, providing:
- **Hardening index** calculation
- **Security control verification**
- **Compliance gap analysis**
- **Remediation recommendations**

## 🎨 Visual Experience

The script features a modern CLI interface with:
- **Professional ASCII art banner**
- **Color-coded status indicators**
- **Progress tracking** with section separators
- **Comprehensive completion summary**
- **Real-time feedback** during execution

## 🔄 System Changes Summary

| Component | Changes Applied |
|-----------|----------------|
| **SSH** | Port 2222, Key-only auth, Root disabled |
| **Firewall** | Default-deny, Minimal services allowed |
| **Kernel** | ASLR, Stack protection, Network hardening |
| **Logging** | Centralized, Auditing enabled, Rotation configured |
| **Services** | Unnecessary services disabled, Core services hardened |
| **Updates** | Automated security patching enabled |
| **Monitoring** | File integrity, Process auditing, Intrusion detection |

## 🛠️ Compatibility

- **Operating System**: Kali Linux (all recent versions)
- **Architecture**: x86_64, ARM64
- **Environment**: Physical systems, Virtual machines, Containers
- **Dependencies**: Automatically installed during execution

## 📚 References & Standards

- [NSA Security Configuration Guides](https://www.nsa.gov/What-We-Do/Cybersecurity/Hardening-Guidance/Security-Configuration-Guides/)
- [NIST Cybersecurity Framework](https://www.nist.gov/cyberframework)
- [DISA Security Technical Implementation Guides](https://public.cyber.mil/stigs/)
- [CIS Critical Security Controls](https://www.cisecurity.org/controls/)
- [OWASP Security Guidelines](https://owasp.org/)

## ⚖️ Legal & Compliance

This framework helps achieve compliance with various security standards:
- **SOC 2 Type II** security controls
- **ISO 27001/27002** information security standards
- **PCI DSS** payment card industry requirements
- **HIPAA** healthcare information protection
- **FedRAMP** federal cloud security requirements

## 🤝 Contributing

Contributions are welcome! Please:
1. Fork the repository
2. Create a feature branch
3. Test thoroughly in isolated environments
4. Submit a pull request with detailed documentation

## 📜 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This software is provided "as is" without warranty. Users assume full responsibility for testing and validation in their specific environments. The authors are not liable for any system damage, data loss, or security incidents resulting from the use of this software.

---

<div align="center">

**🔒 Secure by Design • 🛡️ Defense in Depth • 🎯 Zero Trust Architecture**

*Building tomorrow's secure systems, today*

</div>
