#!/bin/bash

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
PURPLE='\033[0;35m'
CYAN='\033[0;36m'
WHITE='\033[1;37m'
NC='\033[0m'

BOLD='\033[1m'
DIM='\033[2m'

print_banner() {
    clear
    echo -e "${PURPLE}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║    ██╗  ██╗ █████╗ ██╗     ██╗    ██╗  ██╗ █████╗ ██████╗       ║"
    echo "║    ██║ ██╔╝██╔══██╗██║     ██║    ██║  ██║██╔══██╗██╔══██╗      ║"
    echo "║    █████╔╝ ███████║██║     ██║    ███████║███████║██████╔╝      ║"
    echo "║    ██╔═██╗ ██╔══██║██║     ██║    ██╔══██║██╔══██║██╔══██╗      ║"
    echo "║    ██║  ██╗██║  ██║███████╗██║    ██║  ██║██║  ██║██║  ██║      ║"
    echo "║    ╚═╝  ╚═╝╚═╝  ╚═╝╚══════╝╚═╝    ╚═╝  ╚═╝╚═╝  ╚═╝╚═╝  ╚═╝      ║"
    echo "║                                                                  ║"
    echo "║                 ADVANCED SECURITY HARDENING                      ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    echo -e "${DIM}${CYAN}>>> Professional Security Framework for Kali Linux${NC}"
    echo
    echo -e "${RED}${BOLD}⚠️  CRITICAL WARNING ⚠️${NC}"
    echo -e "${YELLOW}This script is UNTESTED and designed exclusively for Kali Linux${NC}"
    echo -e "${YELLOW}Execute ONLY on DISPOSABLE VMs or SECONDARY test systems${NC}"
    echo -e "${YELLOW}DO NOT run on production or primary workstations${NC}"
    echo -e "${RED}You assume full responsibility for any system damage${NC}"
    echo
    read -p "$(echo -e ${WHITE}Continue only if you understand the risks [y/N]: ${NC})" -n 1 -r
    echo
    if [[ ! $REPLY =~ ^[Yy]$ ]]; then
        echo -e "${RED}Operation cancelled by user${NC}"
        exit 1
    fi
    echo
}

print_status() {
    echo -e "${BLUE}${BOLD}[INFO]${NC} $1"
}

print_success() {
    echo -e "${GREEN}${BOLD}[✓]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}${BOLD}[!]${NC} $1"
}

print_error() {
    echo -e "${RED}${BOLD}[✗]${NC} $1"
}

print_section() {
    echo
    echo -e "${WHITE}${BOLD}▶ $1${NC}"
    echo -e "${DIM}${CYAN}────────────────────────────────────────────────────────────────${NC}"
}

check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

install_dependencies() {
    print_section "INSTALLING SECURITY DEPENDENCIES"
    
    apt update -qq
    apt install -y apparmor apparmor-utils auditd libpam-google-authenticator ufw fail2ban rkhunter chkrootkit lynis unattended-upgrades apt-listchanges needrestart rsyslog logrotate aide-common >/dev/null 2>&1
    
    print_success "Security packages installed"
}

configure_mac() {
    print_section "MANDATORY ACCESS CONTROL (MAC)"
    
    systemctl enable apparmor >/dev/null 2>&1
    systemctl start apparmor >/dev/null 2>&1
    aa-enforce /etc/apparmor.d/* >/dev/null 2>&1
    
    print_success "AppArmor enabled and enforced"
}

configure_ssh_security() {
    print_section "SSH SECURITY CONFIGURATION"
    
    cp /etc/ssh/sshd_config /etc/ssh/sshd_config.backup
    
    cat > /etc/ssh/sshd_config << 'EOF'
Port 2222
Protocol 2
PermitRootLogin no
PasswordAuthentication no
PubkeyAuthentication yes
AuthorizedKeysFile .ssh/authorized_keys
PermitEmptyPasswords no
ChallengeResponseAuthentication yes
UsePAM yes
X11Forwarding no
PrintMotd no
ClientAliveInterval 300
ClientAliveCountMax 2
MaxAuthTries 3
MaxStartups 2
LoginGraceTime 60
AllowUsers kali
EOF

    systemctl reload sshd >/dev/null 2>&1
    print_success "SSH hardened - Root access disabled, Port changed to 2222"
}

configure_2fa() {
    print_section "TWO-FACTOR AUTHENTICATION"
    
    echo "auth required pam_google_authenticator.so" >> /etc/pam.d/sshd
    
    sed -i 's/ChallengeResponseAuthentication no/ChallengeResponseAuthentication yes/g' /etc/ssh/sshd_config
    
    print_success "2FA framework configured"
    print_warning "Run 'google-authenticator' as user to setup 2FA"
}

configure_password_policy() {
    print_section "PASSWORD POLICY ENFORCEMENT"
    
    apt install -y libpam-pwquality >/dev/null 2>&1
    
    cat > /etc/security/pwquality.conf << 'EOF'
minlen = 14
minclass = 3
maxrepeat = 2
dcredit = -1
ucredit = -1
lcredit = -1
ocredit = -1
difok = 8
EOF

    cat >> /etc/login.defs << 'EOF'
PASS_MAX_DAYS 90
PASS_MIN_DAYS 7
PASS_WARN_AGE 14
EOF

    print_success "Strong password policy enforced"
}

configure_audit() {
    print_section "SYSTEM AUDITING"
    
    systemctl enable auditd >/dev/null 2>&1
    
    cat > /etc/audit/rules.d/audit.rules << 'EOF'
-D
-b 8192
-f 1
-w /etc/passwd -p wa -k identity
-w /etc/group -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/sudoers -p wa -k identity
-w /var/log/auth.log -p wa -k authentication
-w /var/log/secure -p wa -k authentication
-w /bin/su -p x -k privileged
-w /usr/bin/sudo -p x -k privileged
-w /etc/ssh/sshd_config -p wa -k sshd
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-w /etc/localtime -p wa -k time-change
EOF

    systemctl restart auditd >/dev/null 2>&1
    print_success "Advanced system auditing enabled"
}

configure_kernel_hardening() {
    print_section "KERNEL SECURITY HARDENING"
    
    cat > /etc/sysctl.d/99-security.conf << 'EOF'
kernel.randomize_va_space=2
kernel.exec-shield=1
kernel.dmesg_restrict=1
kernel.kptr_restrict=2
kernel.yama.ptrace_scope=1
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.tcp_syncookies=1
net.ipv4.ip_forward=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.conf.default.send_redirects=0
net.ipv4.conf.all.accept_source_route=0
net.ipv4.conf.default.accept_source_route=0
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.secure_redirects=0
net.ipv4.conf.default.secure_redirects=0
net.ipv4.conf.all.log_martians=1
net.ipv4.conf.default.log_martians=1
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv6.conf.all.accept_source_route=0
net.ipv6.conf.default.accept_source_route=0
net.ipv6.conf.all.accept_redirects=0
net.ipv6.conf.default.accept_redirects=0
fs.suid_dumpable=0
fs.protected_hardlinks=1
fs.protected_symlinks=1
EOF

    sysctl -p /etc/sysctl.d/99-security.conf >/dev/null 2>&1
    print_success "Kernel hardening parameters applied"
}

configure_firewall() {
    print_section "ADVANCED FIREWALL CONFIGURATION"
    
    ufw --force reset >/dev/null 2>&1
    ufw default deny incoming >/dev/null 2>&1
    ufw default deny outgoing >/dev/null 2>&1
    ufw default deny forward >/dev/null 2>&1
    
    ufw allow out 53 >/dev/null 2>&1
    ufw allow out 80 >/dev/null 2>&1
    ufw allow out 443 >/dev/null 2>&1
    ufw allow out 2222 >/dev/null 2>&1
    ufw allow in 2222 >/dev/null 2>&1
    
    ufw --force enable >/dev/null 2>&1
    
    print_success "Restrictive firewall configured"
}

configure_fail2ban() {
    print_section "INTRUSION PREVENTION SYSTEM"
    
    cat > /etc/fail2ban/jail.local << 'EOF'
[DEFAULT]
bantime = 3600
findtime = 600
maxretry = 3
backend = systemd

[sshd]
enabled = true
port = 2222
filter = sshd
logpath = /var/log/auth.log
maxretry = 3
bantime = 7200
EOF

    systemctl enable fail2ban >/dev/null 2>&1
    systemctl restart fail2ban >/dev/null 2>&1
    
    print_success "Fail2Ban configured for SSH protection"
}

disable_unnecessary_services() {
    print_section "SERVICE HARDENING"
    
    SERVICES_TO_DISABLE="bluetooth cups avahi-daemon nfs-common rpcbind"
    
    for service in $SERVICES_TO_DISABLE; do
        systemctl disable $service >/dev/null 2>&1
        systemctl stop $service >/dev/null 2>&1
    done
    
    print_success "Unnecessary services disabled"
}

configure_bootloader() {
    print_section "BOOTLOADER PROTECTION"
    
    print_warning "GRUB password protection requires manual configuration"
    print_status "Run: grub-mkpasswd-pbkdf2"
    print_status "Add password hash to /etc/grub.d/40_custom"
}

configure_logging() {
    print_section "CENTRALIZED LOGGING"
    
    cat > /etc/rsyslog.d/50-default.conf << 'EOF'
*.*;auth,authpriv.none /var/log/syslog
auth,authpriv.* /var/log/auth.log
kern.* /var/log/kern.log
mail.* /var/log/mail.log
user.* /var/log/user.log
*.emerg :omusrmsg:*
EOF

    cat > /etc/logrotate.d/rsyslog << 'EOF'
/var/log/syslog /var/log/auth.log /var/log/kern.log /var/log/mail.log /var/log/user.log {
    weekly
    rotate 52
    missingok
    notifempty
    compress
    delaycompress
    sharedscripts
    postrotate
        /usr/lib/rsyslog/rsyslog-rotate
    endscript
}
EOF

    systemctl restart rsyslog >/dev/null 2>&1
    print_success "Advanced logging configured"
}

configure_auto_updates() {
    print_section "AUTOMATED SECURITY UPDATES"
    
    cat > /etc/apt/apt.conf.d/20auto-upgrades << 'EOF'
APT::Periodic::Update-Package-Lists "1";
APT::Periodic::Download-Upgradeable-Packages "1";
APT::Periodic::AutocleanInterval "7";
APT::Periodic::Unattended-Upgrade "1";
EOF

    cat > /etc/apt/apt.conf.d/50unattended-upgrades << 'EOF'
Unattended-Upgrade::Allowed-Origins {
    "${distro_id}:${distro_codename}-security";
    "${distro_id} ESMApps:${distro_codename}-apps-security";
    "${distro_id} ESM:${distro_codename}-infra-security";
};
Unattended-Upgrade::AutoFixInterruptedDpkg "true";
Unattended-Upgrade::MinimalSteps "true";
Unattended-Upgrade::Remove-Unused-Dependencies "true";
Unattended-Upgrade::Automatic-Reboot "false";
EOF

    systemctl enable unattended-upgrades >/dev/null 2>&1
    print_success "Automatic security updates enabled"
}

configure_aide() {
    print_section "FILE INTEGRITY MONITORING"
    
    aideinit >/dev/null 2>&1
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db >/dev/null 2>&1
    
    cat > /etc/cron.daily/aide << 'EOF'
#!/bin/bash
/usr/bin/aide --check | /usr/bin/logger -t aide
EOF

    chmod +x /etc/cron.daily/aide
    print_success "AIDE file integrity monitoring configured"
}

run_security_scan() {
    print_section "SECURITY ASSESSMENT"
    
    lynis audit system --quiet >/dev/null 2>&1
    
    SCORE=$(grep "Hardening index" /var/log/lynis.log | tail -1 | awk '{print $4}' | sed 's/\[//' | sed 's/\]//')
    
    if [[ ! -z "$SCORE" ]]; then
        print_success "Security hardening score: $SCORE"
    else
        print_success "Security scan completed - Check /var/log/lynis.log"
    fi
}

print_completion() {
    echo
    echo -e "${GREEN}${BOLD}"
    echo "╔══════════════════════════════════════════════════════════════════╗"
    echo "║                                                                  ║"
    echo "║                    HARDENING COMPLETED                           ║"
    echo "║                                                                  ║"
    echo "║  ✓ Mandatory Access Control (AppArmor)                          ║"
    echo "║  ✓ SSH Security & 2FA Framework                                 ║"
    echo "║  ✓ Advanced System Auditing                                     ║"
    echo "║  ✓ Kernel Security Hardening                                    ║"
    echo "║  ✓ Restrictive Firewall Rules                                   ║"
    echo "║  ✓ Intrusion Prevention System                                  ║"
    echo "║  ✓ Service Hardening                                            ║"
    echo "║  ✓ Centralized Logging                                          ║"
    echo "║  ✓ Automated Security Updates                                   ║"
    echo "║  ✓ File Integrity Monitoring                                    ║"
    echo "║                                                                  ║"
    echo "╚══════════════════════════════════════════════════════════════════╝"
    echo -e "${NC}"
    
    echo -e "${YELLOW}${BOLD}IMPORTANT NEXT STEPS:${NC}"
    echo -e "${WHITE}• SSH port changed to 2222${NC}"
    echo -e "${WHITE}• Setup 2FA: run 'google-authenticator' as user${NC}"
    echo -e "${WHITE}• Configure GRUB password protection${NC}"
    echo -e "${WHITE}• Reboot system to apply all changes${NC}"
    echo -e "${WHITE}• Test SSH access before closing current session${NC}"
    echo
    echo -e "${DIM}${CYAN}System hardening completed successfully.${NC}"
}

main() {
    print_banner
    
    check_root
    
    install_dependencies
    configure_mac
    configure_ssh_security
    configure_2fa
    configure_password_policy
    configure_audit
    configure_kernel_hardening
    configure_firewall
    configure_fail2ban
    disable_unnecessary_services
    configure_bootloader
    configure_logging
    configure_auto_updates
    configure_aide
    run_security_scan
    
    print_completion
}

trap 'print_error "Script interrupted"; exit 1' INT TERM

main "$@"
