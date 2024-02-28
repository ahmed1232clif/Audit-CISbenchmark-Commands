#!/bin/bash

# CIS benchmark audit script for Linux hardening by Ahmed Shaikh 

# Output file for the audit report
REPORT_FILE="cis_audit_report.txt"

# Function to print section headers in the reportttsss
print_section_header() {
    echo "======================================================================" >> "$REPORT_FILE"
    echo "$1" >> "$REPORT_FILE"
    echo "======================================================================" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# execute command function thooooooo 
execute_command() {
    chapter=$1
    command=$2
    description=$3
    print_section_header "Chapter $chapter: $description"
    echo "Command: $command" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
    echo "Output:" >> "$REPORT_FILE"
    eval "$command" >> "$REPORT_FILE" 2>&1
    echo "" >> "$REPORT_FILE"
    echo "" >> "$REPORT_FILE"
}

# loaddingg parttt
display_loading() {
    chars="/-\|"
    while :; do
        for (( i=0; i<${#chars}; i++ )); do
            echo -en "${chars:$i:1}" "\r"
            sleep 0.01
        done
    done
}


# auditionssss boisss 
run_cis_audits() {

    # Total number of commands
    total_commands=224
    completed=0
    
    # 1.1.1.1 Ensure mounting of cramfs filesystems is disabled (Scored)
    execute_command "1.1.1.1" "modprobe -n -v cramfs"
    completed=$((completed+1))
    
    # 1.1.1.2 Ensure mounting of freevxfs filesystems is disabled (Scored)
    execute_command "1.1.1.2" "modprobe -n -v freevxfs"
    completed=$((completed+1))

    # 1.1.1.3 Ensure mounting of jffs2 filesystems is disabled (Scored)
    execute_command "1.1.1.3" "modprobe -n -v jffs2"
    completed=$((completed+1))
    
    # 1.1.1.4 Ensure mounting of hfs filesystems is disabled (Scored)
    execute_command "1.1.1.4" "modprobe -n -v hfs"
    completed=$((completed+1))
    
    # 1.1.1.5 Ensure mounting of hfsplus filesystems is disabled (Scored)
    execute_command "1.1.1.5" "modprobe -n -v hfsplus"
    completed=$((completed+1))
    
    # 1.1.1.6 Ensure mounting of squashfs filesystems is disabled (Scored)
    execute_command "1.1.1.6" "modprobe -n -v squashfs"
    completed=$((completed+1))
    
    # 1.1.1.7 Ensure mounting of udf filesystems is disabled (Scored)
    execute_command "1.1.1.7" "modprobe -n -v vfat"
    completed=$((completed+1))
    
    # 1.1.2 Ensure /tmp is configured (Scored)
    execute_command "1.1.2" "grep -E '\s/tmp\s' /etc/fstab | grep -E -v '^\s*#'"
    completed=$((completed+1))
    
    # 1.1.3 Ensure nodev option set on /tmp partition (Scored)
    execute_command "1.1.3" "mount | grep -E '\s/tmp\s' | grep -v nodev"
    completed=$((completed+1))
    
    # 1.1.4 Ensure nosuid option set on /tmp partition (Scored)
    execute_command "1.1.4" "mount | grep -E '\s/tmp\s' | grep -v nosuid"
    completed=$((completed+1))
    
    # 1.1.5 Ensure noexec option set on /tmp partition (Scored)
    execute_command "1.1.5" "mount | grep -E '\s/tmp\s' | grep -v noexec"
    completed=$((completed+1))
    
    # 1.1.6 Ensure separate partition exists for /var (Scored)
    execute_command "1.1.6" "mount | grep -E '\s/var\s'"
    completed=$((completed+1))
    
    # 1.1.7 Ensure separate partition exists for /var/tmp (Scored)
    execute_command "1.1.7" "mount | grep /var/tmp"
    completed=$((completed+1))
    
    # 1.1.8 Ensure nodev option set on /var/tmp partition (Scored)
    execute_command "1.1.8" "mount | grep -E '\s/var/tmp\s' | grep -v nodev"
    completed=$((completed+1))
    
    # 1.1.9 Ensure nosuid option set on /var/tmp partition (Scored)
    execute_command "1.1.9" "mount | grep -E '\s/var/tmp\s' | grep -v nosuid"
    completed=$((completed+1))
    
    # 1.1.10 Ensure noexec option set on /var/tmp partition (Scored)
    execute_command "1.1.10" "mount | grep -E '\s/var/tmp\s' | grep -v noexec"
    completed=$((completed+1))
    
    # 1.1.11 Ensure separate partition exists for /var/log (Scored)
    execute_command "1.1.11" "mount | grep /var/log"
    completed=$((completed+1))
    
    # 1.1.12 Ensure separate partition exists for /var/log/audit (Scored)
    execute_command "1.1.12" "mount | grep /var/log/audit"
    completed=$((completed+1))
    
    # 1.1.13 Ensure separate partition exists for /home (Scored)
    execute_command "1.1.13" "mount | grep /home"
    completed=$((completed+1))
    
    # 1.1.14 Ensure nodev option set on /home partition (Scored)
    execute_command "1.1.14" "mount | grep -E '\s/home\s' | grep -v nodev"
    completed=$((completed+1))
    
    # 1.1.15 Ensure nodev option set on /dev/shm partition (Scored)
    execute_command "1.1.15" "mount | grep -E '\s/dev/shm\s' | grep -v nodev"
    completed=$((completed+1))
    
    # 1.1.16 Ensure nosuid option set on /dev/shm partition (Scored)
    execute_command "1.1.16" "mount | grep -E '\s/dev/shm\s' | grep -v nosuid"
    completed=$((completed+1))
    
    # 1.1.17 Ensure noexec option set on /dev/shm partition (Scored)
    execute_command "1.1.17" "mount | grep -E '\s/dev/shm\s' | grep -v noexec"
    completed=$((completed+1))
    
    # 1.1.18,19,20 Ensure nodev option set on removable media partitions (Not Scored)
    execute_command "1.1.18,19,20" "mount"
    completed=$((completed+1))
    
    # 1.1.21 Ensure sticky bit is set on all world-writable directories (Scored)
    execute_command "1.1.21" "df --local -P | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -type d \( -perm -0002 -a ! -perm -1000 \) 2>/dev/null"
    completed=$((completed+1))
    
    # 1.1.22 Disable Automounting (Scored)
    execute_command "1.1.22" "systemctl is-enabled autofs"
    completed=$((completed+1))
    
    # 1.1.23 Disable USB Storage (Scored)
    execute_command "1.1.23" "lsmod | grep usb-storage"
    completed=$((completed+1))
    
    # 1.2.1 Ensure package manager repositories are configured (Not Scored)
    execute_command "1.2.1" "yum repo-list"
    completed=$((completed+1))
    
    # 1.2.2 Ensure GPG keys are configured (Not Scored)
    execute_command "1.2.2" "rpm -q gpg-pubkey --qf '%{name}-%{version}-%{release} --> %{summary}\n'"
    completed=$((completed+1))
    
    # 1.3.1 Ensure AIDE is installed (Scored)
    execute_command "1.3.1" "rpm -q aide"
    completed=$((completed+1))
    
    # 1.3.2 Ensure filesystem integrity is regularly checked (Scored)
    execute_command "1.3.2" " systemctl is-enabled aidcheck.timer"
    completed=$((completed+1))
    
    # 1.1.1.4 1.4.1 Ensure permissions on bootloader config are configured (Scored)
    execute_command "1.1.1.4,1.4.1" "stat /boot/grub2/grub.cfg"
    completed=$((completed+1))
    
    # 1.4.2 Ensure bootloader password is set (Scored)
    execute_command "1.4.2" "grep "^\s*password" /boot/grub/menu.lst"
    completed=$((completed+1))
    
    # 1.4.3 Ensure authentication required for single user mode (Scored)
    execute_command "1.4.3" "grep ^root:[*\!]: /etc/shadow"
    completed=$((completed+1))
    
    # 1.4.4 Ensure interactive boot is not enabled (Not Scored)
    execute_command "1.4.4" "grep \"^PROMPT_FOR_CONFIRM=\" /etc/sysconfig/boot"
    completed=$((completed+1))
    
    # 1.5.1 Ensure core dumps are restricted (Scored)
    execute_command "1.5.1" "grep \"hard core\" /etc/security/limits.conf /etc/security/limits.d/*"
    completed=$((completed+1))
    
    # 1.5.2 Ensure XD/NX support is enabled (Scored)
    execute_command "1.5.2" "journalctl | grep 'protection: active'"
    completed=$((completed+1))
    
    # 1.5.3 Ensure address space layout randomization (ASLR) is enabled (Scored)
    execute_command "1.5.3" "sysctl kernel.randomize_va_space"
    completed=$((completed+1))
    
    # 1.5.4 Ensure prelink is disabled (Scored)
    execute_command "1.5.4" "rpm -q prelink"
    completed=$((completed+1))
    
    # 1.6.1.1 Ensure SELinux or AppArmor are installed (Scored)
    execute_command "1.6.1.1" "rpm -q libselinux"
    completed=$((completed+1))
    
    # 1.6.2.1 Ensure SELinux is not disabled in bootloader configuration (Scored)
    execute_command "1.6.2.12" "grep \"^\\s*kernel\" /boot/grub/menu.lst"
    completed=$((completed+1))
    
    # 1.6.2.2 Ensure the SELinux state is enforcing (Scored)
    execute_command "1.6.2.22" "grep SELINUX=enforcing /etc/selinux/config"
    completed=$((completed+1))
    
    # 1.6.2.3 Ensure SELinux policy is configured (Scored)
    execute_command "1.6.2.3" "grep SELINUXTYPE=targeted /etc/selinux/config"
    completed=$((completed+1))
    
    # 1.6.2.4 Ensure SETroubleshoot is not installed (Scored)
    execute_command "1.6.2.4" "rpm -q setroubleshoot"
    completed=$((completed+1))
    
    # 1.6.2.5 Ensure the MCS Translation Service (mcstrans) is not installed (Scored)
    execute_command "1.6.2.5" "rpm -q mcstrans"
    completed=$((completed+1))
    
    # 1.6.2.6 Ensure no unconfined daemons exist (Scored)
    execute_command "1.6.2.6" "ps -eZ | grep -E \"initrc\" | grep -E -v -w \"tr|ps|grep|bash|awk\" | tr ':' ' ' | awk '{ print \$NF }'"
    completed=$((completed+1))

    # 1.6.3.1 Ensure AppArmor is not disabled in bootloader configuration (Scored)
    execute_command "1.6.3.1" "grep -R \"^chargen\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 1.6.3.2 Ensure all AppArmor Profiles are enforcing (Scored)
    execute_command "1.6.3.2" "apparmor_status"
    completed=$((completed+1))
    
    # 1.7.1.1 Ensure message of the day is configured properly (Scored)
    execute_command "1.7.1.1" "cat /etc/motd"
    completed=$((completed+1))
    
    # 1.7.1.2 Ensure local login warning banner is configured properly (Scored)
    execute_command "1.7.1.2" "cat /etc/issue"
    completed=$((completed+1))
    
    # 1.7.1.3 Ensure remote login warning banner is configured properly (Scored)
    execute_command "1.7.1.3" "cat /etc/issue.net"
    completed=$((completed+1))
    
    # 1.7.1.4 Ensure permissions on /etc/motd are configured (Scored)
    execute_command "1.7.1.4" "stat /etc/motd"
    completed=$((completed+1))
    
    # 1.7.1.5 Ensure permissions on /etc/issue are configured (Scored)
    execute_command "1.7.1.5" "stat /etc/issue"
    completed=$((completed+1))
    
    # 1.7.1.6 Ensure permissions on /etc/issue.net are configured (Scored)
    execute_command "1.7.1.6" "stat /etc/issue.net"
    completed=$((completed+1))

    # 1.7.2 Ensure GDM login banner is configured (Scored)
    execute_command "1.7.2" "cat /etc/gdm3/greeter.dconf-defaults"
    completed=$((completed+1))
    
    # 1.8 Ensure updates, patches, and additional security software are installed (Not Scored)
    execute_command "1.8" "yum check-update"
    completed=$((completed+1))
    
    # 2.1.1 Ensure chargen services are not enabled (Scored)
    execute_command "2.1.1" "grep -R \"^chargen\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.2 Ensure daytime services are not enabled (Scored)
    execute_command "2.1.2" "grep -R \"^daytime\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.3 Ensure discard services are not enabled (Scored)
    execute_command "2.1.3" "grep -R \"^discard\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.4 Ensure echo services are not enabled (Scored)
    execute_command "2.1.4" "grep -R \"^echo\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.5 Ensure time services are not enabled (Scored)
    execute_command "2.1.5" "grep -R \"^time\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.6 Ensure rsh server is not enabled (Scored)
    execute_command "2.1.6" "grep -R \"^shell\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.6 Ensure rsh server is not enabled (Scored)
    execute_command "2.1.6" "grep -R \"^login\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.6 Ensure rsh server is not enabled (Scored)
    execute_command "2.1.6" "grep -R \"^shell\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.6 Ensure rsh server is not enabled (Scored)
    execute_command "2.1.6" "grep -R \"^exec\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.7 Ensure talk server is not enabled (Scored)
    execute_command "2.1.7" "grep -R \"^talk\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.7 Ensure talk server is not enabled (Scored)
    execute_command "2.1.7" "grep -R \"^ntalk\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.8 Ensure telnet server is not enabled (Scored)
    execute_command "2.1.8" "grep -R \"^telnet\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.9 Ensure tftp server is not enabled (Scored)
    execute_command "2.1.9" "grep -R \"^tftp\" /etc/inetd.*"
    completed=$((completed+1))
    
    # 2.1.10 Ensure xinetd is not enabled (Scored)
    execute_command "2.1.10" "systemctl is-enabled xinetd"
    completed=$((completed+1))
    
    # 2.2.1.1 Ensure time synchronization is in use (Not Scored)
    execute_command "2.2.1.1" "rpm -q ntp"
    completed=$((completed+1))
    
    # 2.2.1.2 Ensure ntp is configured (Scored)
    execute_command "2.2.1.2" " grep \"^restrict\" /etc/ntp.conf"
    completed=$((completed+1))
    
    # 2.2.1.3 Ensure chrony is configured (Scored)
    execute_command "2.2.1.3" "grep -E \"^(server|pool)\" /etc/chrony.conf"
    completed=$((completed+1))
    
    # 2.2.1.4 Ensure systemd-timesyncd is configured (Scored)
    execute_command "2.2.1.4" "systemctl is-enabled systemd-timesyncd.service"
    completed=$((completed+1))
    
    # 2.2.2 Ensure X Window System is not installed (Scored)
    execute_command "2.2.2" "rpm -qa xorg-x11*"
    completed=$((completed+1))
    
    # 2.2.3 Ensure Avahi Server is not enabled (Scored)
    execute_command "2.2.3" "systemctl is-enabled avahi-daemon"
    completed=$((completed+1))
    
    # 2.2.4 Ensure CUPS is not enabled (Scored)
    execute_command "2.2.4" "systemctl is-enabled cups"
    completed=$((completed+1))
    
    # 2.2.5 Ensure DHCP Server is not enabled (Scored)
    execute_command "2.2.5"  "systemctl is-enabled dhcpd"
    completed=$((completed+1))
    
    # 2.2.7 Ensure NFS and RPC are not enabled (Scored)
    execute_command "2.2.7" "systemctl is-enabled nfs"
    completed=$((completed+1))
    
    # 2.2.8 Ensure DNS Server is not enabled (Scored)
    execute_command "2.2.8" "systemctl is-enabled named"
    completed=$((completed+1))
    
    # 2.2.9 Ensure FTP Server is not enabled (Scored)
    execute_command "2.2.9" "systemctl is-enabled vsftpd"
    completed=$((completed+1))
    
    # 2.2.10 Ensure HTTP server is not enabled (Scored)
    execute_command "2.2.10" "systemctl is-enabled httpd"
    completed=$((completed+1))
    
    # 2.2.11 Ensure IMAP and POP3 server is not enabled (Scored)
    execute_command "2.2.11" "systemctl is-enabled dovecot"
    completed=$((completed+1))
    
    # 2.2.12 Ensure Samba is not enabled (Scored)
    execute_command "2.2.12" " systemctl is-enabled smb"
    completed=$((completed+1))
    
    # 2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)
    execute_command "2.2.13" " systemctl is-enabled squid"
    completed=$((completed+1))
    
    # 2.2.14 Ensure SNMP Server is not enabled (Scored)
    execute_command "2.2.14" " systemctl is-enabled snmpd"
    completed=$((completed+1))
    
    # 2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored)
    execute_command "2.2.15" "ss -lntu | grep -E ':25\s' | grep -E -v '\s(127.0.0.1|::1):25\s'"
    completed=$((completed+1))
    
    # 2.2.16 Ensure rsync service is not enabled (Scored)
    execute_command "2.2.16" "systemctl is-enabled rsyncd"
    completed=$((completed+1))
    
    # 2.2.17 Ensure NIS Server is not enabled (Scored)
    execute_command "2.2.17" "systemctl is-enabled ypserv"
    completed=$((completed+1))
    
    # 2.3.1 Ensure NIS Client is not installed (Scored)
    execute_command "2.3.1" "rpm -q ypbind"
    completed=$((completed+1))
    
    # 2.3.2 Ensure rsh client is not installed (Scored)
    execute_command "2.3.2" "rpm -q rsh"
    completed=$((completed+1))
    
    # 2.3.3 Ensure talk client is not installed (Scored)
    execute_command "2.3.3" "rpm -q talk"
    completed=$((completed+1))
    
    # 2.3.4 Ensure telnet client is not installed (Scored)
    execute_command "2.3.4" "rpm -q telnet"
    completed=$((completed+1))
    
    # 2.3.5 Ensure LDAP client is not installed (Scored)
    execute_command "2.3.5" "rpm -q openldap-clients"
    completed=$((completed+1))
    
    # 3.1.1 Ensure IP forwarding is disabled (Scored)
    execute_command "3.1.1" "sysctl net.ipv4.ip_forward"
    completed=$((completed+1))
    
    # 3.1.2 Ensure packet redirect sending is disabled (Scored)
    execute_command "3.1.2" "sysctl net.ipv4.conf.all.send_redirects"
    completed=$((completed+1))
    
    # 3.2.1 Ensure source routed packets are not accepted (Scored)
    execute_command "3.2.1" "sysctl net.ipv4.conf.all.accept_source_route"
    completed=$((completed+1))
    
    # 3.2.2 Ensure ICMP redirects are not accepted (Scored)
    execute_command "3.2.2" "sysctl net.ipv4.conf.all.accept_redirects"
    completed=$((completed+1))
    
    # 3.2.3 Ensure secure ICMP redirects are not accepted (Scored)
    execute_command "3.2.3" "sysctl net.ipv4.conf.all.secure_redirects"
    completed=$((completed+1))
    
    # 3.2.4 Ensure suspicious packets are logged (Scored)
    execute_command "3.2.4" "sysctl net.ipv4.conf.all.log_martians"
    completed=$((completed+1))
    
    # 3.2.5 Ensure broadcast ICMP requests are ignored (Scored)
    execute_command "3.2.5" "sysctl net.ipv4.icmp_echo_ignore_broadcasts"
    completed=$((completed+1))
    
    # 3.2.6 Ensure bogus ICMP responses are ignored (Scored)
    execute_command "3.2.6" "sysctl net.ipv4.icmp_ignore_bogus_error_responses"
    completed=$((completed+1))
    
    # 3.2.7 Ensure Reverse Path Filtering is enabled (Scored)
    execute_command "3.2.7" "sysctl net.ipv4.conf.all.rp_filter"
    completed=$((completed+1))
    
    # 3.2.8 Ensure TCP SYN Cookies is enabled (Scored)
    execute_command "3.2.8" "sysctl net.ipv4.tcp_syncookies"
    completed=$((completed+1))
    
    # 3.2.9 Ensure IPv6 router advertisements are not accepted (Scored)
    execute_command "3.2.9" "sysctl net.ipv6.conf.all.accept_ra"
    completed=$((completed+1))
    
    # 3.3.1 Ensure TCP Wrappers is installed (Not Scored)
    execute_command "3.3.1" "rpm -q tcp_wrappers"
    completed=$((completed+1))
    
    # 3.3.2 Ensure /etc/hosts.allow is configured (Not Scored)
    execute_command "3.3.2" " cat /etc/hosts.allow"
    completed=$((completed+1))
    
    # 3.3.3 Ensure /etc/hosts.deny is configured (Not Scored)
    execute_command "3.3.3" "cat /etc/hosts.deny"
    completed=$((completed+1))
    
    # 3.3.4 Ensure permissions on /etc/hosts.allow are configured (Scored)
    execute_command "3.3.4" "stat /etc/hosts.allow"
    completed=$((completed+1))
    
    # 3.3.5 Ensure permissions on /etc/hosts.deny are configured (Scored)
    execute_command "3.3.5" "stat /etc/hosts.deny"
    completed=$((completed+1))
    
    # 3.4.1 Ensure DCCP is disabled (Scored)
    execute_command "3.4.1" "lsmod | grep dccp"
    completed=$((completed+1))
    
    # 3.4.2 Ensure SCTP is disabled (Scored)
    execute_command "3.4.2" "lsmod | grep sctp"
    completed=$((completed+1))
    
    # 3.4.3 Ensure RDS is disabled (Scored)
    execute_command "3.4.3" "lsmod | grep rds"
    completed=$((completed+1))
    
    # 3.4.4 Ensure TIPC is disabled (Scored)
    execute_command "3.4.4" "lsmod | grep tipc"
    completed=$((completed+1))
    
    # 3.5.1.1 Ensure IPv6 default deny firewall policy (Scored)
    execute_command "3.5.1.1" "grep \"^\s*linux\" /boot/grub2/grub.cfg | grep -v ipv6.disable=1"
    completed=$((completed+1))
    
    # 3.5.1.2 Ensure IPv6 loopback traffic is configured (Scored)
    execute_command "3.5.1.2" "grep \"^\s*linux\" /boot/grub2/grub.cfg | grep -v ipv6.disable=1"
    completed=$((completed+1))
    
    # 3.5.1.3 Ensure IPv6 outbound and established connections are configured (Not Scored)
    execute_command "3.5.1.3" "grep \"^\s*linux\" /boot/grub2/grub.cfg | grep -v ipv6.disable=1"
    completed=$((completed+1))
    
    # 3.5.1.4 Ensure IPv6 firewall rules exist for all open ports (Not Scored)
    execute_command "3.5.1.4" "ss -6tuln"
    completed=$((completed+1))
    
    # 3.5.2.1 Ensure default deny firewall policy (Scored)
    execute_command "3.5.2.1" "iptables -L"
    completed=$((completed+1))
    
    # 3.5.2.2 Ensure loopback traffic is configured (Scored)
    execute_command "3.5.2.2" "iptables -L INPUT -v -n"
    completed=$((completed+1))
    
    # 3.5.2.3 Ensure outbound and established connections are configured (Not Scored)
    execute_command "3.5.2.3" "iptables -L -v -n"
    completed=$((completed+1))
    
    # 3.5.2.4 Ensure firewall rules exist for all open ports (Scored)
    execute_command "3.5.2.4" "ss -4tuln"
    completed=$((completed+1))
    
    # 3.5.3 Ensure iptables is installed (Scored)
    execute_command "3.5.3" "rpm -q iptables"
    completed=$((completed+1))
    
    # 3.6 Ensure wireless interfaces are disabled (Not Scored)
    execute_command "3.6" "ip link show up"
    completed=$((completed+1))
    
    # 3.7 Disable IPv6 (Not Scored)
    execute_command "3.7" "grep \"^\\s*linux\" /boot/grub2/grub.cfg | grep -v ipv6.disabled=1"
    completed=$((completed+1))
    
    # 4.1.1.1 Ensure audit log storage size is configured (Scored)
    execute_command "4.1.1.1" "grep max_log_file /etc/audit/auditd.conf"
    completed=$((completed+1))
    
    # 4.1.1.2 Ensure system is disabled when audit logs are full (Scored)
    execute_command "4.1.1.2" "grep space_left_action /etc/audit/auditd.conf"
    completed=$((completed+1))
    
    # 4.1.1.3 Ensure audit logs are not automatically deleted (Scored)
    execute_command "4.1.1.3" "grep max_log_file_action /etc/audit/auditd.conf"
    completed=$((completed+1))
    
    # 4.1.2 Ensure auditd is installed (Scored)
    execute_command "4.1.2" "rpm -q audit audit-libs"
    completed=$((completed+1))
    
    # 4.1.3 Ensure auditd service is enabled (Scored)
    execute_command "4.1.3" "systemctl is-enabled auditd"
    completed=$((completed+1))
    
    # 4.1.4 Ensure auditing for processes that start prior to auditd is enabled (Scored)
    execute_command "4.1.4" "grep \"^\s*linux\" /boot/grub2/grub.cfg"
    completed=$((completed+1))
    
    # 4.1.5 Ensure events that modify date and time information are collected (Scored)
    execute_command "4.1.5" "grep time-change /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.6 Ensure events that modify user/group information are collected (Scored)
    execute_command "4.1.6" "grep identity /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.7 Ensure events that modify the system's network environment are collected (Scored)
    execute_command "4.1.7" "grep system-locale /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.8 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
    execute_command "4.1.8" "grep MAC-policy /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.9 Ensure login and logout events are collected (Scored)
    execute_command "4.1.9" "grep logins /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.10 Ensure session initiation information is collected (Scored)
    execute_command "4.1.10" "grep -E '(session|logins)' /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.11 Ensure discretionary access control permission modification events are collected (Scored)
    execute_command "4.1.11" "grep perm_mod /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.12 Ensure unsuccessful unauthorized file access attempts are collected (Scored)
    execute_command "4.1.12" "grep access /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.13 Ensure use of privileged commands is collected (Scored)
    execute_command "4.1.13" "find /<partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print \"-a always,exit -F path=\" \$1 \" -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged\" }'"
    completed=$((completed+1))
    
    # 4.1.14 Ensure successful file system mounts are collected (Scored)
    execute_command "4.1.14" "grep mounts /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.15 Ensure file deletion events by users are collected (Scored)
    execute_command "4.1.15" "grep delete /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.16 Ensure changes to system administration scope (sudoers) is collected (Scored)
    execute_command "4.1.16" "grep scope /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.17 Ensure system administrator actions (sudolog) are collected (Scored)
    execute_command "4.1.17" "grep actions /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.18 Ensure kernel module loading and unloading is collected (Scored)
    execute_command "4.1.18" "grep modules /etc/audit/rules.d/*.rules"
    completed=$((completed+1))
    
    # 4.1.19 Ensure the audit configuration is immutable (Scored)
    execute_command "4.1.19" "grep \"^\\s*[^#]\" /etc/audit/rules.d/*.rules | tail -1"
    completed=$((completed+1))
    
    # 4.2.1.1 Ensure rsyslog is installed (Scored)
    execute_command "4.2.1.1" "rpm -q rsyslog"
    completed=$((completed+1))
    
    # 4.2.1.2 Ensure rsyslog Service is enabled (Scored)
    execute_command "4.2.1.2" "chkconfig --list rsyslog"
    completed=$((completed+1))
    
    # 4.2.1.3 Ensure logging is configured (Not Scored)
    execute_command "4.2.1.3" "ls -l /var/log/"
    completed=$((completed+1))
    
    # 4.2.1.4 Ensure rsyslog default file permissions configured (Scored)
    execute_command "4.2.1.4" "grep ^\$FileCreateMode /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
    completed=$((completed+1))
    
    # 4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host (Scored)
    execute_command "4.2.1.5" "grep \"^*.*[^I][^I]*@\" /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
    completed=$((completed+1))
    
    # 4.2.1.6 Ensure remote rsyslog messages are only accepted on designated log hosts. (Not Scored
    execute_command "4.2.1.6" "grep '\$ModLoad imtcp' /etc/rsyslog.conf /etc/rsyslog.d/*.conf"
    completed=$((completed+1))
    
    # 4.2.2 Configure journald & 4.2.2.1 Ensure journald is configured to send logs to rsyslog (Scored)
    execute_command "4.2.2" "grep -e ForwardToSyslog /etc/systemd/journald.conf"
    completed=$((completed+1))
    
    # 4.2.2.2 Ensure journald is configured to compress large log files (Scored)
    execute_command "4.2.2.2" "grep -e Compress /etc/systemd/journald.conf"
    completed=$((completed+1))
    
    # 4.2.2.3 Ensure journald is configured to write logfiles to persistent disk (Scored)
    execute_command "4.2.2.3" "grep -e Storage /etc/systemd/journald.conf"
    completed=$((completed+1))
    
    # 4.2.3 Ensure permissions on all logfiles are configured (Scored)
    execute_command "4.2.3" "find /var/log -type f -ls"
    completed=$((completed+1))
    
    # 4.3 Ensure logrotate is configured (Not Scored)
    execute_command "4.3" "cat /etc/logrotate.conf"
    completed=$((completed+1))
    
    # 5.1.1 Ensure cron daemon is enabled (Scored)
    execute_command "5.1.1" "systemctl is-enabled crond"
    completed=$((completed+1))
    
    # 5.1.2 Ensure permissions on /etc/crontab are configured (Scored)
    execute_command "5.1.2" "systemctl is-enabled crond"
    completed=$((completed+1))
    
    # 5.1.3 Ensure permissions on /etc/cron.hourly are configured (Scored)
    execute_command "5.1.3" "stat /etc/cron.hourly"
    completed=$((completed+1))
    
    # 5.1.4 Ensure permissions on /etc/cron.daily are configured (Scored)
    execute_command "5.1.4" "stat /etc/cron.daily"
    completed=$((completed+1))
    
    # 5.1.5 Ensure permissions on /etc/cron.weekly are configured (Scored)
    execute_command "5.1.5" "stat /etc/cron.weekly"
    completed=$((completed+1))
    
    # 5.1.6 Ensure permissions on /etc/cron.monthly are configured (Scored)
    execute_command "5.1.6" "stat /etc/cron.monthly"
    completed=$((completed+1))
    
    # 5.1.7 Ensure permissions on /etc/cron.d are configured (Scored)
    execute_command "5.1.7" "stat /etc/cron.d"
    completed=$((completed+1))
    
    # 5.1.8 Ensure at/cron is restricted to authorized users (Scored)
    execute_command "5.1.8" "stat /etc/cron"
    completed=$((completed+1))
    
    # 5.1.8 Ensure at/cron is restricted to authorized users (Scored)
    execute_command "5.1.8" "stat /etc/cron.allow"
    completed=$((completed+1))
    
    # 5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)
    execute_command "5.2.1" "stat /etc/ssh/sshd_config"
    completed=$((completed+1))
    
    # 5.2.2 Ensure permissions on SSH private host key files are configured (Scored)
    execute_command "5.2.2" "find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec stat {} \;"
    completed=$((completed+1))
    
    # 5.2.3 Ensure permissions on SSH public host key files are configured (Scored)
    execute_command "5.2.3" "find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec stat {} \;"
    completed=$((completed+1))
    
    # 5.2.4 Ensure SSH Protocol is set to 2 (Scored)
    execute_command "5.2.4" "grep ^Protocol /etc/ssh/sshd_config"
    completed=$((completed+1))
    
    # 5.2.5 Ensure SSH LogLevel is appropriate (Scored)
    execute_command "5.2.5" "sshd -T | grep loglevel"
    completed=$((completed+1))
    
    # 5.2.6 Ensure SSH X11 forwarding is disabled (Scored)
    execute_command "5.2.6" "sshd -T | grep x11forwarding "
    completed=$((completed+1))
    
    # 5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)
    execute_command "5.2.7" "sshd -T | grep maxauthtries"
    completed=$((completed+1))
    
    # 5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)
    execute_command "5.2.8" "sshd -T | grep ignorerhosts"
    completed=$((completed+1))
    
    # 5.2.9 Ensure SSH HostbasedAuthentication is disabled (Scored)
    execute_command "5.2.9" "sshd -T | grep hostbasedauthentication"
    completed=$((completed+1))
    
    # 5.2.10 Ensure SSH root login is disabled (Scored)
    execute_command "5.2.10" "sshd -T | grep permitrootlogin"
    completed=$((completed+1))
    
    # 5.2.11 Ensure SSH PermitEmptyPasswords is disabled (Scored)
    execute_command "5.2.11" "sshd -T | grep permitemptypasswords"
    completed=$((completed+1))
    
    # 5.2.12 Ensure SSH PermitUserEnvironment is disabled (Scored)
    execute_command "5.2.12" "sshd -T | grep permituserenvironment"
    completed=$((completed+1))
    
    # 5.2.13 Ensure only strong Ciphers are used (Scored)
    execute_command " 5.2.13" "sshd -T | grep ciphers"
    completed=$((completed+1))

    # 5.2.14 Ensure only strong MAC algorithms are used (Scored)
    execute_command "5.2.14" "sshd -T | grep -i \"MACs\""
    completed=$((completed+1))
    
    # 5.2.15 Ensure only strong Key Exchange algorithms are used (Scored)
    execute_command "5.2.15" " sshd -T | grep kexalgorithms"
    completed=$((completed+1))
    
    # 5.2.16 Ensure SSH Idle Timeout Interval is configured (Scored)
    execute_command "5.2.16" "sshd -T | grep clientaliveinterval "
    completed=$((completed+1))
    
    # 5.2.17 Ensure SSH LoginGraceTime is set to one minute or less (Scored)
    execute_command "5.2.17" "sshd -T | grep logingracetime"
    completed=$((completed+1))
    
    # 5.2.18 Ensure SSH access is limited (Scored)
    execute_command " 5.2.18" "sshd -T | grep allowusers "
    completed=$((completed+1))
    
    # 5.2.18 Ensure SSH access is limited (Scored)
    execute_command "5.2.18" "sshd -T | grep allowgroups "
    completed=$((completed+1))
    
    # 5.2.18 Ensure SSH access is limited (Scored)
    execute_command "5.2.18" "sshd -T | grep denyusers "
    completed=$((completed+1))
    
    # 5.2.18 Ensure SSH access is limited (Scored)
    execute_command "5.2.18" "sshd -T | grep denygroups "
    completed=$((completed+1))

    # 5.2.19 Ensure SSH warning banner is configured (Scored)
    execute_command "5.2.19" "sshd -T | grep banner"
    completed=$((completed+1))
    
    # 5.2.20 Ensure SSH PAM is enabled (Scored)
    execute_command "5.2.2" " sshd -T | grep -i usepam"
    completed=$((completed+1))
    
    # 5.2.21 Ensure SSH AllowTcpForwarding is disabled (Scored)
    execute_command "5.2.21" "sshd -T | grep -i allowtcpforwarding"
    completed=$((completed+1))
    
    # 5.2.22 Ensure SSH MaxStartups is configured (Scored)
    execute_command "5.2.22" "sshd -T | grep -i maxstartups"
    completed=$((completed+1))
    
    # 5.2.23 Ensure SSH MaxSessions is set to 4 or less (Scored)
    execute_command "5.2.23" "sshd -T | grep -i maxsessions"
    completed=$((completed+1))

    # 5.3.1 Ensure password creation requirements are configured (Scored) and 5.3.2 Ensure lockout for failed password attempts is configured (Not Scored) and 5.3.3 Ensure password reuse is limited (Not Scored) Ensure password hashing algorithm is SHA-512 (Not Scored)
    execute_command "5.3.1, 5.3.2, 5.3.3" "cat /etc/pam.d/common-auth"  
    completed=$((completed+1))

    execute_command "5.3.1, 5.3.2, 5.3.3" "cat /etc/pam.d/password-auth"
    completed=$((completed+1))

    execute_command "5.3.1, 5.3.2, 5.3.3" "cat /etc/pam.d/system-auth"
    completed=$((completed+1))
    
    # 5.4.1.1 Ensure password expiration is 365 days or less (Scored)
    execute_command "5.4.1.1" "grep PASS_MAX_DAYS /etc/login.defs "
    completed=$((completed+1))
    
    # 5.4.1.2 Ensure minimum days between password changes is 7 or more (Scored)
    execute_command "5.4.1.2" "grep PASS_MIN_DAYS /etc/login.defs"
    completed=$((completed+1))

    # 5.4.1.3 Ensure password expiration warning days is 7 or more (Scored)
    execute_command "5.4.1.3" "grep PASS_WARN_AGE /etc/login.defs"
    completed=$((completed+1))
    
    # 5.4.1.4 Ensure inactive password lock is 30 days or less (Scored)
    execute_command "5.4.1.4" "useradd -D | grep INACTIVE"
    completed=$((completed+1))
    
    # 5.4.1.5 Ensure all users last password change date is in the past (Scored)
    execute_command "5.4.1.5" "for usr in \$(cut -d: -f1 /etc/shadow); do [[ \$(chage --list \$usr | grep '^Last password change' | cut -d: -f2) > \$(date) ]] && echo \"\$usr : \$(chage --list \$usr | grep '^Last password change' | cut -d: -f2)\"; done"
    completed=$((completed+1))
    
    # 5.4.2 Ensure system accounts are secured (Scored)
    execute_command "5.4.2" "awk -F: '\$1!=\"root\" && \$1!=\"sync\" && \$1!=\"shutdown\" && \$1!=\"halt\" && \$1!~/^\+/ && \$3<UID_MIN && \$7!=\"$(which nologin)\" && \$7!=\"/bin/false\" {print}' UID_MIN=\$(awk '/^\\s*UID_MIN/{print \$2}' /etc/login.defs) /etc/passwd"
    completed=$((completed+1))
    
    # 5.4.3 Ensure default group for the root account is GID 0 (Scored)
    execute_command "5.4.3" "grep \"^root:\" /etc/passwd | cut -f4 -d:"
    completed=$((completed+1))
    
    # 5.4.4 Ensure default user umask is 027 or more restrictive (Scored)
    execute_command "5.4.4" "grep \"umask\" /etc/bashrc"
    completed=$((completed+1))
    
    # 5.4.5 Ensure default user shell timeout is 900 seconds or less (Scored)
    execute_command "5.4.5" "grep \"^TMOUT\" /etc/bashrc"
    completed=$((completed+1))

    # 5.5 Ensure root login is restricted to system console (Not Scored)
    execute_command "5.5" "cat /etc/securetty"
    completed=$((completed+1))

    # 5.6 Ensure access to the su command is restricted (Scored)
    execute_command "5.6" "grep pam_wheel.so /etc/pam.d/su"
    completed=$((completed+1))
    
    # 6.1.2 Ensure permissions on /etc/passwd are configured (Scored)
    execute_command "6.1.2" "stat /etc/passwd "
    completed=$((completed+1))
    
    # 6.1.3 Ensure permissions on /etc/shadow are configured (Scored)
    execute_command "6.1.3" "stat /etc/shadow"
    completed=$((completed+1))

    # 6.1.4 Ensure permissions on /etc/group are configured (Scored)
    execute_command "6.1.4" "stat /etc/group "
    completed=$((completed+1))

    # 6.1.5 Ensure permissions on /etc/gshadow are configured (Scored)
    execute_command "6.1.5" "stat /etc/gshadow"
    completed=$((completed+1))

    # 6.1.6 Ensure permissions on /etc/passwd- are configured (Scored)
    execute_command "6.1.6" "stat /etc/passwd"
    completed=$((completed+1))
    
    # 6.1.7 Ensure permissions on /etc/shadow- are configured (Scored)
    execute_command "6.1.7" " stat /etc/shadow"
    completed=$((completed+1))

    # 6.1.8 Ensure permissions on /etc/group- are configured (Scored)
    execute_command "6.1.8" "stat /etc/group"
    completed=$((completed+1))

    # 6.1.9 Ensure permissions on /etc/gshadow- are configured (Scored)
    execute_command "6.1.9" "stat /etc/gshadow"
    completed=$((completed+1))

    # 6.1.10 Ensure no world writable files exist (Scored)
    execute_command "6.1.10" "find <partition> -xdev -type f -perm -0002"
    completed=$((completed+1))
    
    # 6.1.11 Ensure no unowned files or directories exist (Scored)
    execute_command "6.1.11" "df --local -P | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -nouser"
    completed=$((completed+1))

    # 6.1.12 Ensure no ungrouped files or directories exist (Scored)
    execute_command "6.1.12" " df --local -P | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -nogroup"
    completed=$((completed+1))

    # 6.1.13 Audit SUID executables (Not Scored)
    execute_command "6.1.13" "df --local -P | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -type f -perm -4000"
    completed=$((completed+1))

    # 6.1.14 Audit SGID executables (Not Scored)
    execute_command "6.1.14" "df --local -P | awk '{if (NR!=1) print \$6}' | xargs -I '{}' find '{}' -xdev -type f -perm -2000"
    completed=$((completed+1))
    
    # 6.2.1 Ensure password fields are not empty (Scored)
    execute_command "6.2.1" "awk -F: '(\$2 == \"\" ) { print \$1 \" does not have a password \"}' /etc/shadow"
    completed=$((completed+1))

    # 6.2.2 Ensure no legacy "+" entries exist in /etc/passwd (Scored)
    execute_command "6.2.2" "grep '^+:' /etc/passwd"
    completed=$((completed+1))

    # 6.2.3 Ensure no legacy "+" entries exist in /etc/shadow (Scored)
    execute_command "6.2.3" "grep '^+:' /etc/shadow"
    completed=$((completed+1))
    
    # 6.2.4 Ensure no legacy "+" entries exist in /etc/group (Scored)
    execute_command "6.2.4" "grep '^+:' /etc/group"
    completed=$((completed+1))

    # 6.2.5 Ensure root is the only UID 0 account (Scored)
    execute_command "6.2.5" "awk -F: '(\$3 == 0) { print \$1 }' /etc/passwd"
    completed=$((completed+1))

    # Print completion message
    echo "------------------------------------------------------"
    echo "Audit completed. Total commands executed: $completed"
    echo "------------------------------------------------------"

}

# Main function to run all audits
main() {
    # Clear existing report file
    > "$REPORT_FILE"
    
    # Start the loading indicator
    echo -n "     Running audits: "
    display_loading &

    # Save the PID of the loading indicator process
    LOADING_PID=$!

    # Run CIS benchmark audits
    run_cis_audits

    # Stop the loading indicator by killing its process
    kill $LOADING_PID >/dev/null 2>&1

    echo "Audit report generated: $REPORT_FILE"
}

# ending partttt
display_loading() {
    chars="/-\|"
    count=0
    while :; do
        echo -en "${chars:$count:1}" "\r"
        ((count = (count + 1) % ${#chars}))
        sleep 0.1
    done
}

# Run the main function
main