#!/bin/bash

# tel-it-security-automation :- Ansible roles for automated security hardening.  
# Copyright (c) 2020 Maximilian Hertstein, [...] Deutsche Telekom AG 
# contact: devsecops@telekom.de 
# This file is distributed under the conditions of the Apache-2.0 license. 
# For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.

# -----------------------------------------------------------------------------
# Deutsche Telekom IT GmbH (DevSecOps Team)
# Script for Compliance Check - Linux OS for Servers (3.65, v1.4, 01.07.2020)
# Version: 1.1
# Date: 27.07.2020 
# -----------------------------------------------------------------------------
TEST_NAME="linux"

# -----------------------------------------------------------------------------
# Check if script is executed directly
# -----------------------------------------------------------------------------

if [ ! "$1" ]; then 
  # =========================================================================
  # Direct execution of script
  # =========================================================================

  # Check if script is started with root privileges
  if [ "$EUID" -ne 0 ]; then
    echo "Start script as root!";
    exit 1
  fi
  
  # Linux identification if script is not started from start_testing.sh script.
  OS=$(awk -F\= '/^ID=/ {print $2}' /etc/os-release | tr -d '"')
  OS_VERSION=$(awk -F\" '/^VERSION_ID=/ {print $2}' /etc/os-release)
  MAJOR_VERSION=$(echo $OS_VERSION | awk -F\. '{print $1}')
  if [ "$OS" == "amzn" ] || [ "$OS" == "rhel" ] || [ "$OS" == "centos" ]; then
    OS_MAIN_DISTRO="REDHAT";
    PACKAGE="rpm -qa";
  elif [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ]; then
    OS_MAIN_DISTRO="DEBIAN";
    PACKAGE="apt list --installed";
  elif [ "$OS" == "sles" ]; then
    OS_MAIN_DISTRO="SUSE";
    PACKAGE="rpm -qa";
  else
    echo "Linux $OS not suppoted!";
    exit 1
  fi

  # Dummy function to avoid error if script is executed directly
  write_to_soc () 
    { 
      echo >/dev/null
    };
  
else
  # =========================================================================
  # Started from 'start_testing.sh' script
  # =========================================================================

  # ---------------------------------------------------------------------------
  # Create output SoC file
  # ---------------------------------------------------------------------------
 
  # Function is part of script 'start_testing.sh'
  soc_outputfile "$TEST_NAME"

  # ---------------------------------------------------------------------------
  # Test case specific pre-checks
  # ---------------------------------------------------------------------------

  # ---------------------------------------------------------------------------
  # Define and load input file with custom variables
  # ---------------------------------------------------------------------------
  INPUT_VARS_FILE="vars_custom_$TEST_NAME.sh"
  read_variables $INPUT_VARS_FILE
fi 

# -----------------------------------------------------------------------------
# Linux distro specific variables
# -----------------------------------------------------------------------------

NOLOGIN_PATH_REDHAT="/sbin/nologin";
NOLOGIN_PATH_DEBIAN="/usr/sbin/nologin";
NOLOGIN_PATH_SUSE="/sbin/nologin";
NOLOGIN_PATH="NOLOGIN_PATH_$OS_MAIN_DISTRO";

AUDIT_DAEMON_REDHAT="audit";
AUDIT_DAEMON_DEBIAN="auditd";
AUDIT_DAEMON_SUSE="audit";
AUDIT_DAEMON="AUDIT_DAEMON_$OS_MAIN_DISTRO";

RSYSLOG_CONF_REDHAT="/etc/rsyslog.conf";
RSYSLOG_CONF_DEBIAN="/etc/rsyslog.d/50-default.conf";
RSYSLOG_CONF_SUSE="/etc/rsyslog.d/remote.conf";
RSYSLOG_CONF="RSYSLOG_CONF_$OS_MAIN_DISTRO";

FILE_GRUB_REDHAT="/boot/grub2/grub.cfg";
FILE_GRUB_DEBIAN="/boot/grub/grub.cfg";
FILE_GRUB_SUSE="/boot/grub2/grub.cfg";
FILE_GRUB="FILE_GRUB_$OS_MAIN_DISTRO";

MAC_SOLUTION_REDHAT="selinux";
MAC_SOLUTION_DEBIAN="apparmor";
MAC_SOLUTION_SUSE="apparmor";
MAC_SOLUTION="MAC_SOLUTION_$OS_MAIN_DISTRO";

# -----------------------------------------------------------------------------
# Variables for test cases
# -----------------------------------------------------------------------------

# NOTE!
# Variables marked wit '# default' can be overwritten by customer in input file
# with custom variables. Change of all othe variables has effect on security
# compliance!

# Req 1: Unused services and protocols must be deactivated.
if [ ! "$TCP_PORTS" ]; then TCP_PORTS=""; fi  # default
if [ ! "$UDP_PORTS" ]; then UDP_PORTS=""; fi  # default

# Req 2: The reachability of services must be restricted.
FIREWALL_SOLUTION="iptables"
UBUNTU_IPTABLES_TOOLS="iptables-persistent"
REDHAT_IPTABLES_TOOLS="iptables-services"

# Req 3: Unused software must not be installed or must be uninstalled.
CLIENTS="rsh-redone-client rsh-client talk telnet ldap-utilsi \
inetutils-telnet rsh ypbind"
SERVERS="openbsd-inetd inetutils-inetd xinetd xserver-xorg-core vsftpd \
nfs-kernel-server ftpd dovecot-core dovecot-pop3d dovecot-imapd nis \
isc-dhcp-server avahi-daemon snmpd avahi telnet-server talk-server \
tftp-server rsh-server yp-tools inetd atftp yast2-tftp-server avahi-dnsconfd \
rsh-server inetutils-telnetd friendly-recovery avahi-dnsconfd avahi-ui-utils \
tftpd-hpa iscsi.service"

# Req 4: Dedicated partitions must be used for growing content that can influence 
#        the availability of the system.
if [ ! "$PARTITIONS" ]; then PARTITIONS="/tmp /var"; fi  # default

# Req 5: Parameters nodev, nosuid and noexec must be set for partitions where 
#        this is applicable.
PART_TMP="nodev,nosuid";
PART_VARTMP="nodev,nosuid,noexec";
PART_DEVSHM="nodev,nosuid,noexec";
PART_HOME="nodev";

# Req 10: Passwords must be protected with an appropriate hashing function.
LOGINDEFS_FILE="/etc/login.defs";
ENCRYPT_METH="SHA512";
MIN_RNDS="640000";
MAX_RNDS="640000";

# Req 11: The default user umask must be 027 or more restrictive.
UMASK="027";

# Req 12: Not needed SUID and SGID bits must be removed from executables.
SUID_FILES="/bin/ping /sbin/pam_timestamp_check /sbin/unix_chkpwd /usr/bin/at \
 /usr/bin/gpasswd /usr/bin/locate /usr/bin/newgrp /usr/bin/passwd /bin/ping6 \
 /usr/bin/ssh-agent /usr/sbin/lockdev /sbin/mount.nfs /sbin/umount.nfs \
 /usr/sbin/sendmail.sendmail /usr/bin/expiry /usr/libexec/utempter/utempter \
 /usr/bin/traceroute6.iputils /sbin/mount.nfs4 /sbin/umount.nfs4 /usr/bin/crontab \
 /usr/bin/wall /usr/bin/write /usr/bin/screen /usr/bin/mlocate /usr/bin/chage \
 /usr/bin/chfn /usr/bin/chsh /bin/fusermount /usr/bin/pkexec /usr/bin/sudo \
 /usr/bin/sudoedit /usr/sbin/postdrop /usr/sbin/postqueue /usr/sbin/suexec \
 /usr/sbin/ccreds_validate /usr/lib/dbus-1.0/dbus-daemon-launch-helper \
 /usr/lib/policykit-1/polkit-agent-helper-1"

# Req 13: Core dumps must be disabled.
LIMITS_CONF_FILE="/etc/security/limits.conf"
DUMPS="soft hard"
SUID_DUMPABLE="fs.suid_dumpable 0"

# Req 14: Protection against buffer overflows must be enabled.
RANDOM_VA_SPACE="kernel.randomize_va_space 2"

# Req 15: IPv4 protocol stack must be securely configured.
IPV4_1="net.ipv4.ip_forward 0"
IPV4_2="net.ipv4.conf.all.accept_redirects 0"
IPV4_3="net.ipv4.conf.default.accept_redirects 0"
IPV4_4="net.ipv4.conf.all.secure_redirects 1"
IPV4_5="net.ipv4.conf.default.secure_redirects 1"
IPV4_6="net.ipv4.conf.all.send_redirects 0"
IPV4_7="net.ipv4.conf.default.send_redirects 0"
IPV4_8="net.ipv4.conf.all.accept_source_route 0"
IPV4_9="net.ipv4.conf.default.accept_source_route 0"
IPV4_10="net.ipv4.conf.all.log_martians 1"
IPV4_11="net.ipv4.conf.default.log_martians 1"
IPV4_12="net.ipv4.icmp_echo_ignore_broadcasts 1"
IPV4_13="net.ipv4.icmp_ignore_bogus_error_responses 1"
IPV4_14="net.ipv4.conf.all.rp_filter 1"
IPV4_15="net.ipv4.conf.default.rp_filter 1"
IPV4_16="net.ipv4.tcp_syncookies 1"
IPV4_17="net.ipv4.icmp_ratelimit 100"
IPV4_18="net.ipv4.icmp_ratemask 88089"
IPV4_19="net.ipv4.tcp_timestamps 0"
IPV4_20="net.ipv4.conf.all.arp_ignore 2"
IPV4_21="net.ipv4.conf.all.arp_announce 2"
IPV4_22="net.ipv4.conf.all.arp_notify 0"
IPV4_23="net.ipv4.conf.all.arp_accept 0"

# Req 16: IPv6 protocol stack must be securely configured.
NO_V6=0
if [ "$IPV6_CHECK" == "OFF" ]; then NO_V6=1; fi
IPV6_1="net.ipv6.conf.all.disable_ipv6 $NO_V6"
IPV6_2="net.ipv6.conf.default.disable_ipv6 $NO_V6"
IPV6_3="net.ipv6.conf.all.forwarding 0"
IPV6_4="net.ipv6.conf.default.forwarding 0"
IPV6_5="net.ipv6.conf.all.accept_redirects 0"
IPV6_6="net.ipv6.conf.default.accept_redirects 0"
IPV6_7="net.ipv6.conf.all.accept_source_route 0"
IPV6_8="net.ipv6.conf.default.accept_source_route 0"
IPV6_9="net.ipv6.conf.all.accept_ra 0"
IPV6_10="net.ipv6.conf.default.accept_ra 0"
IPV6_11="net.ipv6.conf.all.accept_ra_rtr_pref 0"
IPV6_12="net.ipv6.conf.default.accept_ra_rtr_pref 0"
IPV6_13="net.ipv6.conf.all.accept_ra_pinfo 0"
IPV6_14="net.ipv6.conf.default.accept_ra_pinfo 0"
IPV6_15="net.ipv6.conf.all.accept_ra_defrtr 0"
IPV6_16="net.ipv6.conf.default.accept_ra_defrtr 0"
IPV6_17="net.ipv6.conf.all.router_solicitations 0"
IPV6_18="net.ipv6.conf.default.router_solicitations 0"
IPV6_19="net.ipv6.conf.all.dad_transmits 0"
IPV6_20="net.ipv6.conf.default.dad_transmits 0"
IPV6_21="net.ipv6.conf.all.autoconf 0"
IPV6_22="net.ipv6.conf.default.autoconf 0"

# Req 29: Log rotation for logfiles must be configured.
LOG_ROTATE_FILE="/etc/logrotate.conf"
LOG_ROTATE_TIME="weekly"
LOG_ROTATE_COUNT="4"
LOG_ROTATE_MAXSIZE="10M"

# Req 30: System time must be synchronized against a reference time source.
if [ ! "$TIMEZONE" ]; then TIMEZONE="Europe/Berlin"; fi   # default
NTP_SOFTWARE="chrony ntp"

# Req 31: Auditd service must be used to log security relevant events. 
MAX_LOG_FILE="10"
MAX_NUM_LOGS="5"
MAX_LOG_FILE_ACTION="ROTATE"

# Req 32: System events must be logged.
SYS_EVENTS_1="-a always,exit -F arch=b64 -S execve -F path=/sbin/reboot"
SYS_EVENTS_2="-a always,exit -F arch=b64 -S execve -F path=/sbin/poweroff"
SYS_EVENTS_3="-a always,exit -F arch=b64 -S execve -F path=/sbin/shutdow"
SYS_EVENTS_4="-w /etc/at.allow"
SYS_EVENTS_5="-w /etc/at.deny"
SYS_EVENTS_6="-w /var/spool/at"
SYS_EVENTS_7="-w /etc/crontab"
SYS_EVENTS_8="-w /etc/anacrontab"
SYS_EVENTS_9="-w /etc/cron.allow"
SYS_EVENTS_10="-w /etc/cron.deny"
SYS_EVENTS_11="-w /etc/cron.d"
SYS_EVENTS_12="-w /etc/cron.hourly"
SYS_EVENTS_13="-w /etc/cron.daily"
SYS_EVENTS_14="-w /etc/cron.weekly"
SYS_EVENTS_15="-w /etc/cron.monthly"
SYS_EVENTS_16="-a always,exit -F arch=b64 -S adjtimex,settimeofday -F key=time-change"
SYS_EVENTS_17="-a always,exit -F arch=b64 -S clock_settime -F key=time-change"
SYS_EVENTS_18="-w /etc/localtime -p wa -k time-change"
SYS_EVENTS_19="-a always,exit -F arch=b64 -S mount -F auid>=1000 -F auid!=-1 -F key=mounts"
SYS_EVENTS_20="-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=-1 -F key=export"
SYS_EVENTS_21="-w /sbin/insmod -p x -k modules"
SYS_EVENTS_22="-w /sbin/rmmod -p x -k modules"
SYS_EVENTS_23="-w /sbin/modprobe -p x -k modules"
SYS_EVENTS_24="-a always,exit -F arch=b64 -S init_module,delete_module -F key=modules"
SYS_EVENTS_REDHAT1="-w /usr/bin/rpm -p x -k software_mgmt"
SYS_EVENTS_REDHAT2="-w /usr/bin/yum -p x -k software_mgmt"
SYS_EVENTS_SUSE1="-w /usr/bin/rpm -p x -k software_mgmt"
SYS_EVENTS_SUSE2="-w /usr/bin/zypper -p x -k software_mgmt"
SYS_EVENTS_DEBIAN1="-w /usr/bin/dpkg -p x -k software_mgmt"
SYS_EVENTS_DEBIAN2="-w /usr/bin/apt-add-repository -p x -k software_mgmt"
SYS_EVENTS_DEBIAN3="-w /usr/bin/apt-get -p x -k software_mgmt"
SYS_EVENTS_DEBIAN4="-w /usr/bin/aptitude -p x -k software_mgmt"

# Req 33: Access and Authentication events must be logged.
ACCESS_EVENTS_1="-w /var/log/lastlog -p wa -k logins"
ACCESS_EVENTS_2="-w /etc/shadow -p wa -k identity"
ACCESS_EVENTS_3="-w /etc/gshadow -p wa -k identity"
ACCESS_EVENTS_4="-w /etc/security/opasswd -p wa -k identity"
ACCESS_EVENTS_5="-w /etc/sudoers -p wa -k scope"
ACCESS_EVENTS_6="-w /etc/sudoers.d" # -p wa -k scope (problem with Ubuntu 16.04)
ACCESS_EVENTS_7="-w /var/log/sudo.log -p wa -k actions"
ACCESS_EVENTS_8="-a always,exit -F arch=b64 -S chmod,fchmod,fchmodat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
ACCESS_EVENTS_9="-a always,exit -F arch=b64 -S chown,fchown,lchown,fchownat -F auid>=1000 -F auid!=-1 -F key=perm_mod"
ACCESS_EVENTS_10="-a always,exit -F arch=b64 -S setxattr,lsetxattr,fsetxattr,removexattr,lremovexattr,fremovexattr -F auid>=1000 -F auid!=-1 -F key=perm_mod"
ACCESS_EVENTS_REDHAT1="-w /var/run/faillock/ -p wa -k logins"
ACCESS_EVENTS_REDHAT2="-w /etc/selinux/ -p wa -k MAC-policy"
ACCESS_EVENTS_SUSE1="-w /var/log/faillog -p wa -k logins"
ACCESS_EVENTS_SUSE2="-w /etc/apparmor/ -p wa -k MAC-policy"
ACCESS_EVENTS_SUSE3="-w /etc/apparmor.d/ -p wa -k MAC-policy"
ACCESS_EVENTS_DEBIAN1="-w /var/log/faillog -p wa -k logins"
ACCESS_EVENTS_DEBIAN2="-w /var/log/tallylog -p wa -k logins"
ACCESS_EVENTS_DEBIAN3="-w /etc/apparmor/ -p wa -k MAC-policy"
ACCESS_EVENTS_DEBIAN4="-w /etc/apparmor.d/ -p wa -k MAC-policy"

# Req 34: Account and Group Management events must be logged.
ACC_GRP_MGMT_EVENTS_1="-w /etc/passwd -p wa -k identity"
ACC_GRP_MGMT_EVENTS_2="-w /etc/group -p wa -k identity"

# Req 35: Configuration Change events must be logged.
CHANGE_EVENTS_1="-w /var/log/audit/audit.log"
CHANGE_EVENTS_2="-w /var/log/audit/audit\[1-4\].log"
CHANGE_EVENTS_3="-w /etc/syslog"
CHANGE_EVENTS_4="-w /etc/rsyslog.conf"
CHANGE_EVENTS_5="-w /etc/rsyslog.d/conf"
CHANGE_EVENTS_6="-w /etc/audit/auditd.conf -p wa"
CHANGE_EVENTS_7="-w /etc/audit/audit.rules -p wa"
CHANGE_EVENTS_8="-a always,exit -F arch=b64 -S sethostname,setdomainname -F key=system-locale"
CHANGE_EVENTS_9="-w /etc/issue -p wa -k system-locale"
CHANGE_EVENTS_10="-w /etc/issue.net -p wa -k system-locale"
CHANGE_EVENTS_11="-w /etc/hosts -p wa -k system-locale"
CHANGE_EVENTS_12="-w /etc/network? -p wa -k system-locale"
CHANGE_EVENTS_13="-w /etc/networks -p wa -k system-locale"
CHANGE_EVENTS_14="-w /etc/pam.d"
CHANGE_EVENTS_15="-w /etc/nsswitch.conf"
CHANGE_EVENTS_16="-w /etc/ssh/sshd_config"
CHANGE_EVENTS_17="-w /etc/sysctl.conf"
CHANGE_EVENTS_18="-w /etc/modprobe.conf"
CHANGE_EVENTS_19="-w /etc/profile.d"
CHANGE_EVENTS_20="-w /etc/profile"
CHANGE_EVENTS_21="-w /etc/shells"
CHANGE_EVENTS_REDHAT1="-w /var/log/messages"
CHANGE_EVENTS_REDHAT2="-w /etc/sysconfig/network -p wa -k system-locale"
CHANGE_EVENTS_REDHAT3="-w /etc/sysconfig/network-scripts -p wa -k system-locale"
CHANGE_EVENTS_SUSE1="-w /var/log/messages"
CHANGE_EVENTS_SUSE2="-w /etc/sysconfig/network -p wa -k system-locale"
CHANGE_EVENTS_SUSE3="-w /etc/sysconfig/network-scripts -p wa -k system-locale"
CHANGE_EVENTS_DEBIAN1="-w /var/log/auth.log"
CHANGE_EVENTS_DEBIAN2="-w /var/log/system.log"
CHANGE_EVENTS_DEBIAN3="-w /etc/network/interfaces -p wa -k system-locale"

# Req 37: Security relevant logging data must be send to an external
#         system direct after their creation.
if [ ! "$SYSLOG_TYPE" ]; then SYSLOG_TYPE="rsyslog"; fi   # default
# Note! syslog-ng not supported in this version

# Req 42: If PAM is used, it needs to be reconfigured to use strong salted
#         password hash functions while doing many calculation rounds to protect
#         passwords.
PAM_ENRYPT_METHOD="sha512"
PAM_ROUNDS="640000"

# Req 43: If PAM is used, password rules must be configured for PAM to
#         force the use of passwords with a minimum length of 12 characters
#         and a combination of three out of the following categories: upper
#         cases, lower case, numbers and special characters.
PAM_PASSWORD_LENGTH="12"
PAM_CHAR_CLASSES="3"

# Req 44: If PAM is used, a protection against brute force and dictionary
#         attacks that hinder password guessing must be configured in PAM.
PAM_FAILED_LOGIN_ATTEMPS="5"
PAM_UNLOCK_TIME="600"

# Req 45: If PAM is used , PAM must be configured that motd did not contain any sensitive data.
PAM_FILES_MOTD="login sshd"

# Req 46: If iptables is used, policies for loopback traffic must be configured.
IPTABLES_RULE_LOOP_1="-A INPUT -i lo -j ACCEPT"
IPTABLES_RULE_LOOP_2="-A OUTPUT -o lo -j ACCEPT"
IPTABLES_RULE_LOOP_3="-A INPUT -s 127.0.0.0/8 -j DROP"
IP6TABLES_RULE_LOOP_3="-A INPUT -s ::1/128 -j DROP"

# Req 47: If iptables is used, policies for outbound and established 
#         connections must be configured.
IPTABLES_RULE_OUT_1="-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT"
IPTABLES_RULE_OUT_2="-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT"
IPTABLES_RULE_OUT_3="-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT"
IPTABLES_RULE_OUT_4="-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT"
IPTABLES_RULE_OUT_5="-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT"
IPTABLES_RULE_OUT_6="-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT"

# Req 48: If iptables is used, policies must exist for all ports in 
#         listening state.
IPTABLES_RULE_TCP="-A INPUT -p tcp -m state --state NEW -m tcp --dport"
IPTABLES_RULE_UDP="-A INPUT -p udp -m state --state NEW -m udp --dport"
IPTABLES_RULE_ICMP="-A INPUT -p icmp -m state --state NEW,RELATED,ESTABLISHED -m icmp --icmp-type 8 -j ACCEPT"
IP6TABLES_RULE_ICMP="-A INPUT -p ipv6-icmp -m state --state NEW,RELATED,ESTABLISHED -m icmp6 --icmpv6-type 128 -j ACCEPT"

# Req 49: If iptables is used, the default policy for tables INPUT and FORWARD
#         must be configured to drop all traffic.
IPTABLES_RULE_DROP_1="-P INPUT DROP"
IPTABLES_RULE_DROP_2="-P FORWARD DROP"
IPTABLES_RULE_DROP_3="-P OUTPUT DROP"

# Req 50: If a system has Internet facing services or is a virtualization
#         host, a MAC solution must be used to restrict these services
#         respectively guest VMs.
MAC_TOOLS_REDHAT="libselinux"
MAC_TOOLS_SUSE="libapparmor1 apparmor-profiles apparmor-utils apparmor-parser \
yast2-apparmor apparmor-docs audit"
MAC_TOOLS_DEBIAN="apparmor apparmor-utils"
MAC_TOOLS="MAC_TOOLS_$OS_MAIN_DISTRO"

# Req 52: If SELinux is used, its state must be enforced.
# Req 53: If SELinux is used, the policy must be configured.
FILE_SELINUX="/etc/selinux/config"

# Req 54: If SELinux is used, SETroubleshoot and MCS Translation Service 
#         must not be installed.
SELINUX_SOFTWARE="setroubleshoot mcstrans"

# Req 66: Permissions of security relevant configuration files must have 
#         the distribution default values or more restrictive.
# /etc/passwd
FILE_SET_REDHAT1="644 root root"
FILE_SET_SUSE1="644 root root"
FILE_SET_UBUNTU161="644 root root"
FILE_SET_UBUNTU181="644 root root"
FILE_SET_UBUNTU201="644 root root"
# /etc/passwd-
FILE_SET_REDHAT2="644 root root"
FILE_SET_SUSE2="644 root root"
FILE_SET_UBUNTU162="644 root root"
FILE_SET_UBUNTU182="644 root root"
FILE_SET_UBUNTU202="644 root root"
# /etc/shadow
FILE_SET_REDHAT3="0 root root"
FILE_SET_SUSE3="640 root shadow"
FILE_SET_UBUNTU163="640 root shadow"
FILE_SET_UBUNTU183="640 root shadow"
FILE_SET_UBUNTU203="640 root shadow"
# /etc/shadow-
FILE_SET_REDHAT4="0 root root"
FILE_SET_SUSE4="640 root shadow"
FILE_SET_UBUNTU164="600 root root"
FILE_SET_UBUNTU184="640 root shadow"
FILE_SET_UBUNTU204="640 root shadow"
# /etc/group
FILE_SET_REDHAT5="644 root root"
FILE_SET_SUSE5="644 root root"
FILE_SET_UBUNTU165="644 root root"
FILE_SET_UBUNTU185="644 root root"
FILE_SET_UBUNTU205="644 root root"
# /etc/group-
FILE_SET_REDHAT6="644 root root"
FILE_SET_SUSE6="644 root root"
FILE_SET_UBUNTU166="600 root root"
FILE_SET_UBUNTU186="644 root root"
FILE_SET_UBUNTU206="644 root root"
# grub.cfg
FILE_SET_REDHAT7="644 root root"
FILE_SET_SUSE7="600 root root"
FILE_SET_UBUNTU167="444 root root"
FILE_SET_UBUNTU187="444 root root"
FILE_SET_UBUNTU207="444 root root"
# /etc/sysctl.conf
FILE_SET_REDHAT8="644 root root"
FILE_SET_SUSE8="644 root root"
FILE_SET_UBUNTU168="644 root root"
FILE_SET_UBUNTU188="644 root root"
FILE_SET_UBUNTU208="644 root root"
# /etc/ssh/sshd_config
FILE_SET_REDHAT9="600 root root"
FILE_SET_SUSE9="640 root root"
FILE_SET_UBUNTU169="644 root root"
FILE_SET_UBUNTU189="644 root root"
FILE_SET_UBUNTU209="644 root root"
# /etc/gshadow
FILE_SET_REDHAT10="0 root root"
FILE_SET_UBUNTU1610="640 root shadow"
FILE_SET_UBUNTU1810="640 root shadow"
FILE_SET_UBUNTU2010="640 root shadow"
# /etc/gshadow-
FILE_SET_REDHAT11="0 root root"
FILE_SET_UBUNTU1611="600 root root"
FILE_SET_UBUNTU1811="640 root shadow"
FILE_SET_UBUNTU2011="640 root shadow"

# -----------------------------------------------------------------------------
# Help functions
# -----------------------------------------------------------------------------

# Initiate test cases
initiate_test () {
  let "REQ_NR++";
  REQ="REQ$REQ_NR"
  REMARK="REMARK_$REQ_NR"
  TXT=
  FAIL=0
  PASS=0
  SKIP=0

  echo -e "\n++ Req $REQ_NR: $REQ_TXT"
}

# Test case numbering 
add_zero () {
  TEST_NUM=
  if [ $1 -lt 10 ]; then
    TEST_NUM="0";
  fi
  echo $TEST_NUM
}

# -----------------------------------------------------------------------------
# Test cases
# -----------------------------------------------------------------------------
# Function 'write_to_soc' is part of script 'start_testing.sh'

echo -e "\n==============================================================================="
echo " Compliance Checks - Linux OS for Servers (3.65)"
echo "==============================================================================="
echo -e "Start testing ..."
REQ_NR=0

# Req 1: Unused services and protocols must be deactivated.
REQ_TXT="Unused services and protocols must be deactivated."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  ERR_MSG1="Found open TCP ports:"
  CHK_TCP=$(ss -nlt 2>/dev/null | awk '($1 == "LISTEN" && $4 !~ /127\.0\.0\.[0-9]{1,4}/ && $4 !~ /\[?::[0-9]{1,4}\]?:/) {print $4}' | sed 's/.*://' | sort -nu)

  if [ -z "$CHK_TCP" ]; then
    let PASS=$PASS+1;
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check open tcp ports:\e[1;32m PASSED\e[0m";
  else
    for CHK in $CHK_TCP; do
      if [ "$CHK" != "$(echo $TCP_PORTS | grep -ow "$CHK")" ]; then
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check open tcp ports:\e[1;31m FAILED\e[0m (found port $CHK)";
        ERR_MSG1="$ERR_MSG1 $CHK,";
        let FAIL=$FAIL+1;
        ERR=1;
      else
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check open tcp port $CHK (port defined as allowed):\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      fi
    done  
  fi
  
  # Test 2/2
  NUM=1
  ERR_MSG2="Found open UDP ports:"
  CHK_UDP=$(ss -nlu 2>/dev/null | awk '($1 == "UNCONN" && $4 !~ /127\.0\.0\.[0-9]{1,4}/ && $4 !~ /\[?::[0-9]{1,4}\]?:/) {print $4}' | sed 's/.*://' | sort -nu)

  if [ -z "$CHK_UDP" ]; then
    let PASS=$PASS+1;
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check open udp ports:\e[1;32m PASSED\e[0m";
  else
    for CHK in $CHK_UDP; do
      if [ "$CHK" != "$(echo $UDP_PORTS | grep -ow "$CHK")" ]; then
        if [ "$CHK" -gt "1024" ]; then
          CHK_RSYSLOG="$(ss -ulpn | grep $CHK | grep rsyslog | wc -l)"
          if [ "$CHK_RSYSLOG" -eq "0" ]; then
            echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check open udp ports:\e[1;31m FAILED\e[0m (found port $CHK)";
            echo -e "\t\e[33mNOTE!\e[0m High UDP ports are apear sometimes only temporary.\n\t      Check port manual if it is permanent open."
            ERR_MSG2="$ERR_MSG2 $CHK,"
            let FAIL=$FAIL+1;
            # ERR=1; We don't trigger exit 1 for UDP high ports as they are sometime 
            #        appear only temporary.
          else
            echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check open udp port $CHK (needed for rsyslog):\e[1;32m PASSED\e[0m";
            let PASS=$PASS+1;
          fi
        else
          echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check open udp ports:\e[1;31m FAILED\e[0m (found port $CHK)";
          ERR_MSG2="$ERR_MSG2 $CHK,"
          let FAIL=$FAIL+1;
          ERR=1;
        fi
      else
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check open udp port $CHK (user defined allowed port):\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      fi
    done
  fi
  TXT="$ERR_MSG1 $ERR_MSG2"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 2: The reachability of services must be restricted.
REQ_TXT="The reachability of services must be restricted."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  $FIREWALL_SOLUTION -V &>/dev/null
  if [ $? -ne 0 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check firewall solution ($FIREWALL_SOLUTION):\e[1;31m FAILED\e[0m (not present)";
    ERR_MSG="$FIREWALL_SOLUTION not found."
    let FAIL=$FAIL+1;
    ERR=1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check firewall solution ($FIREWALL_SOLUTION):\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  fi
  
  # Test 2/2
  MATCH=1;
  if [ "$OS" == "ubuntu" ]; then
    if [ "$($PACKAGE 2>/dev/null | grep -ow $UBUNTU_IPTABLES_TOOLS | wc -l)" -eq "0" ]; then
      MATCH=0;
    fi
  elif [ "$OS" == "amzn" ] || [ "$OS" == "rhel" ] || [ "$OS" == "centos" ]; then
    if [ "$MAJOR_VERSION" != "8" ]; then
      if [ "$($PACKAGE 2>/dev/null | grep -ow $REDHAT_IPTABLES_TOOLS | wc -l)" -eq "0" ]; then
        MATCH=0;
      fi
    fi
  fi

  if [ "$MATCH" -eq "0" ]; then
    echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if iptable tools installed:\e[1;31m FAILED\e[0m (not present)";
    ERR_MSG="$ERR_MSG $FIREWALL_SOLUTION tool for persistant rules not found."
    let FAIL=$FAIL+1;
    ERR=1;
  else
    echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if iptable tools installed:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 3: Unused software must not be installed or must be uninstalled.
REQ_TXT="Unused software must not be installed or must be uninstalled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  ERR_MSG1="server(s):";
  for CHK in $SERVERS; do
    if [ "$($PACKAGE 2>/dev/null | grep -ow $CHK | wc -l)" -ne "0" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check unused server ($CHK):\e[1;31m FAILED\e[0m (present)";
      ERR_MSG1="$ERR_MSG1 $CHK";
      let FAIL=$FAIL+1;
      ERR=1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check unused server ($CHK):\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    fi
  done

  # Test 2/2
  NUM=1
  ERR_MSG2="client(s):";
  for CHK in $CLIENTS; do
    if [ "$($PACKAGE 2>/dev/null | grep -ow $CHK | wc -l)" -ne "0" ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check unused client ($CHK):\e[1;31m FAILED\e[0m (present)";
      ERR_MSG2="$ERR_MSG2 $CHK";
      let FAIL=$FAIL+1;
      ERR=1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check unused client ($CHK):\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    fi
  done
  TXT="Not allowed $ERR_MSG1, $ERR_MSG2"  
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 4: Dedicated partitions must be used for growing content that can influence 
#        the availability of the system.
REQ_TXT="Dedicated partitions must be used for growing content that can\n   influence the availability of the system."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  ERR_MSG="Partition(s) not found:"
  NUM=1
  for CHK in $PARTITIONS; do
    if [ "$( grep " $CHK" /etc/fstab 2>/dev/null | awk '!/none/' | wc -l)" -eq "0" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check needed partition ($CHK):\e[1;31m FAILED\e[0m (not found)";
      ERR_MSG="$ERR_MSG $CHK,";
      let FAIL=$FAIL+1;
      ERR=1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check needed partition ($CHK):\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    fi
  done
  TXT="$ERR_MSG";
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 5: Parameters nodev, nosuid and noexec must be set for partitions where 
#        this is applicable.
REQ_TXT="Parameters nodev, nosuid and noexec must be set for partitions\n   where this is applicable."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  ERR_MSG="Config missing for partition(s):"
  NUM=1
  if [ -z "$PARTITIONS" ]; then
    echo -e "   [Test -.--] Check partition parameters: SKIPPED"
    echo -e "\t\e[33mNOTE!\e[0m No partitions defined. Requirement set to N/A."
    ERR_MSG="no partitions defined";
    SKIP=1;  
  else
    for CHK in $PARTITIONS; do
      PART_SEC=""
      PARTITION=$(grep " $CHK" /etc/fstab 2>/dev/null | awk '!/none/')
      if [ ! -z "$PARTITION" ]; then
        if [ "$CHK" == "/tmp" ]; then
          PART_SEC="$PART_TMP";
        elif [ "$CHK" == "/var/tmp" ]; then
          PART_SEC="$PART_VARTMP";
        elif [ "$CHK" == "/dev/shm" ]; then
          PART_SEC="$PART_DEVSHM";
        elif [ "$CHK" == "/home" ]; then
          PART_SEC="$PART_HOME";
        fi
        if [ ! -z "$PART_SEC" ]; then
          if [ "$(echo $PARTITION | grep -o $PART_SEC 2>/dev/null | wc -l)" -eq "0" ]; then
            echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check partition parameter ($CHK):\e[1;31m FAILED\e[0m (not found)";
            ERR_MSG="$ERR_MSG $CHK $PART_SEC,"
            let FAIL=$FAIL+1;
            ERR=1;
          else
            echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check partition parameters ($CHK):\e[1;32m PASSED\e[0m";
            let PASS=$PASS+1;
          fi
        fi
      else
        echo -e "   [Test -.--] Check partition parameters: SKIPPED"
        echo -e "\t\e[33mNOTE!\e[0m Partitions $CHK not found."
        ERR_MSG="$ERR_MSG partition $CHK did not exist";
        SKIP=1;
      fi
    done
  fi
  TXT="$ERR_MSG";
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 6: Automounting must be disabled.
REQ_TXT="Automounting must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ "$($PACKAGE 2>/dev/null | grep -ow autofs | wc -l)" -ne "0" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if autofs is installed:\e[1;31m FAILED\e[0m (present)";
    ERR_MSG="AUtomounting (autofs) is enabled"
    let FAIL=$FAIL+1;
    ERR=1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if autofs is installed:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 7: The use of at/cron must be restricted to authorized users.
REQ_TXT="The use of at/cron must be restricted to authorized users."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  NUM1=1
  NUM2=1
  NUM3=1
  for CHK in at cron; do
    # Test 1/3
    if [ -f "/etc/$CHK.deny" ]; then
      echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check for $CHK.deny file:\e[1;31m FAILED\e[0m (present)";
      ERR_MSG="$ERR_MSG $CHK.deny found,"
      let FAIL=$FAIL+1;
      ERR=1;
    else
      echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check for $CHK.deny file:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    fi

    # Test 2/3
    if [ -f "/etc/$CHK.allow" ]; then
      if [ "$(stat -L -c "%a %u %g" /etc/$CHK.allow | grep -o ".00 0 0")" != "" ]; then
        echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check for $CHK.allow file:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      else
        echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check for $CHK.allow file:\e[1;31m FAILED\e[0m (wrong permissions)";
        ERR_MSG="$ERR_MSG $CHK wrong permissions,"
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    else
      echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check for $CHK.allow file:\e[1;31m FAILED\e[0m (absent)";
      ERR_MSG="$ERR_MSG $CHK file absent,"
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  
    # Test 3/3
    FILE="/etc/$CHK.allow"
    if [ -f "$FILE" ]; then
      if [ "$(grep 'root' $FILE)" != "root" ]; then
        echo -e "   [Test 3.$(add_zero $NUM3)$(((NUM3++)))] Check for root in $FILE file:\e[1;31m FAILED\e[0m (not found)";
        ERR_MSG="$ERR_MSG $FILE root not found,"
        let FAIL=$FAIL+1;
        ERR=1;
      else
        if [ "$(cat $FILE | wc -l)" != "1" ]; then
          echo -e "   [Test 3.$(add_zero $NUM3)$(((NUM3++)))] Check for entries in $FILE file:\e[1;31m FAILED\e[0m (to many users)";          
          ERR_MSG="$ERR_MSG $FILE to many users"
          let FAIL=$FAIL+1;
          ERR=1;
        else
          echo -e "   [Test 3.$(add_zero $NUM3)$(((NUM3++)))] Check for users in $CHK.allow file:\e[1;32m PASSED\e[0m";
          let PASS=$PASS+1;
        fi
      fi
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 8: Sticky bit must be set on all world-writable directories.
REQ_TXT="Sticky bit must be set on all world-writable directories."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  ERR_MSG="Found world-writable dir wihout sticky bit:"
  SRCH=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 \! -perm -1000 2>/dev/null)
  CHK=$(echo "$SRCH" | wc -w)

  if [ "$CHK" -eq "0" ]; then
    let PASS=$PASS+1;
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check for world-writable directory for sticky bit:\e[1;32m PASSED\e[0m";
  else
    for DIR in $SRCH; do
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check for world-writable directory for sticky bit:\e[1;31m FAILED\e[0m (found $DIR)";
      ERR_MSG="$ERR_MSG $DIR, "
    done
    let FAIL=$FAIL+1;
    ERR=1;
  fi
  TXT="$ERR_MSG";
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 9: No regular files that are world writable must exist.
REQ_TXT="No regular files that are world writable must exist."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  ERR_MSG="Found world writable files:"
  SRCH="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null)"
  if [ -z "$SRCH" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check for world-writable files:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    for FILE in $SRCH; do
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check for world-writable files:\e[1;31m FAILED\e[0m (found $FILE)";
      ERR_MSG="$ERR_MSG $FILE,"
    done
    let FAIL=$FAIL+1;
    ERR=1;
  fi
  TXT="$ERR_MSG";
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 10: Passwords must be protected with an appropriate hashing function.
REQ_TXT="Passwords must be protected with an appropriate hashing function."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  NUM=1
  # Test 1/3
  CHK_ENCRYPT_METH="$(awk '/^ENCRYPT_METHOD / {print $2}' $LOGINDEFS_FILE)";
  if [ "$CHK_ENCRYPT_METH" == "$ENCRYPT_METH" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check password encryption method:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check password encryption method:\e[1;31m FAILED\e[0m (wrong value $CHK_ENCRYPT_METH)";
    ERR_MSG="Encryption method is: $CHK_ENCRYPT_METH,"
    let FAIL=$FAIL+1;
    ERR=1;
  fi

  # Test 2/3
  CHK_MIN_RNDS="$(awk '/^SHA_CRYPT_MIN_ROUNDS / {print $2}' $LOGINDEFS_FILE)";
  if [ "$CHK_MIN_RNDS" == "$MIN_RNDS" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check password encryption min rounds:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check password encryption min rounds:\e[1;31m FAILED\e[0m (wrong value $CHK_MIN_RNDS)";
    ERR_MSG="$ERR_MSG Min rounds value is: $CHK_MIN_RNDS,"
    let FAIL=$FAIL+1;
    ERR=1;
  fi

  # Test 3/3
  CHK_MAX_RNDS="$(awk '/^SHA_CRYPT_MAX_ROUNDS / {print $2}' $LOGINDEFS_FILE)";
   if [ "$CHK_MIN_RNDS" == "$MAX_RNDS" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check password encryption max rounds:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check password encryption max rounds:\e[1;31m FAILED\e[0m (wrong value $CHK_MAX_RNDS)";
    ERR_MSG="$ERR_MSG Max rounds value is: $CHK_MAX_RNDS"
    let FAIL=$FAIL+1;
    ERR=1;
  fi
  TXT="$ERR_MSG";
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 11: The default user umask must be 027 or more restrictive.
REQ_TXT="The default user umask must be 027 or more restrictive."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  CHK_UMASK="$(awk '/^UMASK/ {print $2}' $LOGINDEFS_FILE)";
  if [ "$CHK_UMASK" == "$UMASK" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check default umask:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
  else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check default umask:\e[1;31m FAILED\e[0m (wrong umask $CHK_UMASK)";
      ERR_MSG="Umask value is: $CHK_UMASK"
      let FAIL=$FAIL+1;
      ERR=1;
  fi
  TXT="$ERR_MSG";
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 12: Not needed SUID and SGID bits must be removed from executables.
REQ_TXT="Not needed SUID and SGID bits must be removed from executables."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  ERR_MSG="File with SUID found:"
  CHK_FILES=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f \( -perm -4000 -o -perm -2000 \) -print)

  for CHK in $CHK_FILES; do
    if [ "$CHK" != "$(echo $SUID_FILES | grep -ow "$CHK")" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check file $CHK for not allowed SUID bit:\e[1;31m FAILED\e[0m (SUID set for $CHK)";
      ERR_MSG="$ERR_MSG $CHK,";
      let FAIL=$FAIL+1;
      ERR=1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check file $CHK for not allowed SUID bit:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    fi
  done
  TXT="$ERR_MSG";
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# -----------------------------------------------------------------------------
# Function for Req. 13-16
# -----------------------------------------------------------------------------
config_sysctl () {
  PAR=$(echo "$1" | awk '{print $1}');
  VALUE=$(echo "$1" | awk '{print $2}');

  # Test 1
  SYSCTL=$(sysctl $PAR | awk '{print $3}' | tr -d ' ');
  if [ "$SYSCTL" == "$VALUE" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$NUM] Check if $PAR is $VALUE:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$NUM] Check if $PAR is $VALUE:\e[1;31m FAILED\e[0m (value: $SYSCTL)";
    ERR_MSG="$ERR_MSG $PAR:$SYSCTL not set,"
    let FAIL=$FAIL+1;
    ERR=1;
  fi

  
  # Test 2
  SYSCTL_CONF="/etc/sysctl.conf"
  CHK_FILES="$(grep "^[[:blank:]]*[^#]" $SYSCTL_CONF| grep -h "$PAR[ ]*=[ ]*")"
  if [ -n "$CHK_FILES" ]; then
    CHK_VALUE="$(echo $CHK_FILES | awk -F\= '{print $2}' | tr -d ' ')"
    if [ "$CHK_VALUE" == "$VALUE" ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$NUM] Check $PAR for correct value $VALUE:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$NUM] Check $PAR for correct value $VALUE:\e[1;31m FAILED\e[0m (value $CHK_VALUE)";
      ERR_MSG="$ERR_MSG wrong value $PAR:$CHK_VALUE"
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  else
    echo -e "   [Test 2.$(add_zero $NUM)$NUM] Check $PAR is in config:\e[1;31m FAILED\e[0m (absent)";
    ERR_MSG="$ERR_MSG, $PAR entry not found in config"
    let FAIL=$FAIL+1;
    ERR=1;
  fi
}

# Req 13: Core dumps must be disabled.
REQ_TXT="Core dumps must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then
  NUM=1

  # Test 1/4 & 2/4
  config_sysctl "$SUID_DUMPABLE"
  
  # Test 3/4
  for CHK in $DUMPS; do
    if [ -z "$(ls -A $LIMITS_CONF_FILE)" ]; then
      echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if core dump is disaled:\e[1;31m FAILED\e[0m (config file $LIMITS_CONF_FILE not found)";
      ERR_MSG="Config file $LIMITS_CONF_FILE not found";
      let FAIL=$FAIL+1;
      ERR=1;
    else
      if [ $(grep -i "$CHK core 0" $LIMITS_CONF_FILE | wc -l) -eq 1 ]; then
        echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if core dump ($CHK) is disabled:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      else
        echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if core dump ($CHK) is disabled:\e[1;31m FAILED\e[0m ($CHK core)";
        ERR_MSG="$CHK dumps are enabled";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 14: Protection against buffer overflows must be enabled.
REQ_TXT="Protection against buffer overflows must be enabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then
  NUM=1

  # Test 1/3 & 2/3
  config_sysctl "$RANDOM_VA_SPACE"
    
  # Test 3/3
  CHK_NX=$(dmesg | awk -F' ' '{if ($3 == "NX") print $7}')
  if [ "$CHK_NX" == "active" ]; then
      echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if NX/XD is enabled:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
  else
      echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if NX/XD is enabled:\e[1;31m FAILED\e[0m ($CHK_NX)";
      ERR_MSG="$ERR_MSG NX/XD disabled"
      let FAIL=$FAIL+1;
      ERR=1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 15: IPv4 protocol stack must be securely configured.
REQ_TXT="IPv4 protocol stack must be securely configured."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then
  NUM=1
  CNT=1
  IPV4=IPV4_$CNT

  while [ $CNT -lt 24 ]; do
    # Test 1/2 & 2/2
    config_sysctl "${!IPV4}"
    let CNT++;
    let NUM++;
    IPV4=IPV4_$CNT;
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 16: IPv6 protocol stack must be securely configured.
REQ_TXT="IPv6 protocol stack must be securely configured."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then
  NUM=1
  CNT=1
  IPV6=IPV6_$CNT

if [ $(sysctl net.ipv6.conf.all.disable_ipv6 | awk '{print $3}') -eq 0 ] && \
   [ $(sysctl net.ipv6.conf.default.disable_ipv6 | awk '{print $3}') -eq 0 ]; then
    while [ $CNT -lt 23 ]; do
      # Test 1/2 & 2/2
      config_sysctl "${!IPV6}";
      let CNT++;
      let NUM++;
      IPV6=IPV6_$CNT;
    done
  else
    echo -e "   [Test 2.1] Check IPv6 in config: n/a (disabled)";
    SKIP=1;
    TXT="IPv6 is disabled";   
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 17: Emerged vulnerabilities in software and hardware of a system must be 
#         fixed or protected against misuse.
REQ_TXT="Emerged vulnerabilities in software and hardware of a system must be\n   fixed or protected against misuse."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  UPDATE_ERR=0

  # Test 1/1
  NUM=1
  if [ "$OS_MAIN_DISTRO" == "DEBIAN" ]; then
    apt update &>/dev/null
    if [ $(apt list --upgradable 2>/dev/null | wc -l) -gt 1 ]; then 
      UPDATE_ERR=1; 
    fi
  elif [ "$OS_MAIN_DISTRO" == "REDHAT" ]; then
    if [ $(yum check-update 2>/dev/null | grep "updates$" | wc -l) -ne 0 ]; then 
      UPDATE_ERR=1; 
    fi
  elif [ "$OS_MAIN_DISTRO" == "SUSE" ]; then
    zypper refresh -s &>/dev/null
    if [ $(zypper list-updates 2>/dev/null | grep "No updates found." | wc -l) -ne 1 ]; then 
      UPDATE_ERR=1; 
    fi
  fi

  if [ $UPDATE_ERR -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if system is up-to-date:\e[1;31m FAILED\e[0m (updates missing)";
    ERR_MSG="System is not up-to-date"
    let FAIL=$FAIL+1;
    ERR=1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if system is up-to-date:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 18: GPG Check for repository server must be activated and corresponding keys 
#         for trustable repositories must be configured.
REQ_TXT="GPG Check for repository server must be activated and corresponding keys\n   for trustable repositories must be configured."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  GPG_ERR=0

  # Test 1/1
  NUM=1
  if [ "$OS_MAIN_DISTRO" == "DEBIAN" ]; then
    if [ $(grep "trusted=yes" /etc/apt/sources.list | wc -l) -ne 0 ]; then 
      GPG_ERR=1;
    fi
  elif [ "$OS_MAIN_DISTRO" == "REDHAT" ]; then
    if [ $(awk -F\= '/^gpgcheck=/ {print $2}' /etc/yum.conf) -ne 1 ]; then 
      GPG_ERR=1; 
    fi
    for CHK_REPOS in $(ls /etc/yum.repos.d); do
      if [ "$(grep "enabled=1" /etc/yum.repos.d/$CHK_REPOS)" ]; then
        if [ ! "$(grep "gpgcheck=1" /etc/yum.repos.d/$CHK_REPOS)" ]; then
          GPG_ERR=1; 
        fi
      fi
    done
  elif [ "$OS_MAIN_DISTRO" == "SUSE" ]; then
    CHK=$(awk -F\= '/^gpgcheck=/ {print $2}' /etc/zypp/zypp.conf)
    CHK2=$(zypper repos -E | grep -i yes | awk -F'|' '{print $5}' | sort -u | wc -l)
    if [ -z $CHK ]; then
      if [ $CHK2 -ne 1 ]; then GPG_ERR=1; fi
    else
      if [ $CHK -ne 1 ]; then GPG_ERR=1; fi
    fi
  fi

  if [ $GPG_ERR -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if use of trusted repos is enabled:\e[1;31m FAILED\e[0m (gpg check disabled)";
    ERR_MSG="Use of trusted repos (gpgcheck check) is not enabled";
    let FAIL=$FAIL+1;
    ERR=1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if use of trusted repos is enabled:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 19: User accounts must be used that allow unambiguous identification of the user.
REMARK="REMARK_$REQ_NR"
REQ_TXT="User accounts must be used that allow unambiguous identification of the user."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  ACCOUNTS=$(awk -v var="${!NOLOGIN_PATH}" -F':' '{ if ( $3 >= 1000 && $7 != var && $7 != "/bin/false") print $1 }' /etc/passwd)
  for USER in $ALLOWED_USERS; do
    ACCOUNTS=$(echo "$ACCOUNTS" | sed -e "s/$USER//g")
  done

  if [ -z "$ACCOUNTS" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check local user accounts:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    ERR_MSG="Found user(s):"
    for FOUND_ACCOUNT in $ACCOUNTS; do
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check local user accounts:\e[1;31m FAILED\e[0m (found account $FOUND_ACCOUNT)"
      ERR_MSG="$ERR_MSG $FOUND_ACCOUNT,"
      let FAIL=$FAIL+1;
      ERR=1;
    done
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 20: System accounts must be non-login.
REQ_TXT="System accounts must be non-login."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

    # Test 1/1
    NUM=1
    CHK=$(awk -F':' '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7=="/bin/bash") {print $1}' /etc/passwd)

    if [ -z "$CHK" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check system accounts if non-login:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      ERR_MSG="Found login system account(s):";
      for FOUND_ACCOUNT in $CHK; do
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check system accounts if non-login:\e[1;31m FAILED\e[0m (found account $FOUND_ACCOUNT)";
        ERR_MSG="$ERR_MSG $FOUND_ACCOUNT,";
        let FAIL=$FAIL+1;
        ERR=1;
      done
    fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 21: User accounts must be protected against unauthorized use by at least
#         one authentication attribute.
REQ_TXT="User accounts must be protected against unauthorized use by at least\n   one authentication attribute."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  CHK=$(awk -F":" '($2 == "" && $2 != "!" && $2 !="*") {print $1}' /etc/shadow)

  if [ -z "$CHK" ]; then
    let PASS=$PASS+1;
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check accounts in /etc/shadow:\e[1;32m PASSED\e[0m";
  else
    ERR_MSG="Found account(s) without password: ";
    for FOUND_USER in $CHK; do 
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check accounts in /etc/shadow:\e[1;31m FAILED\e[0m ($FOUND_USER has no password)";
      ERR_MSG="$ERR_MSG $FOUND_USER,";
      let FAIL=$FAIL+1;
      ERR=1;
    done
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 22: User accounts with extensive rights must be protected with two 
#         authentication attributes.
REQ_TXT="User accounts with extensive rights must be protected with two\n   authentication attributes."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  SSH_CONFIG="/etc/ssh/sshd_config"
  CHK_SSH="$(ps -A | grep -ow 'sshd*$' | wc -l)"

  if [ $CHK_SSH -ne 0 ]; then
    # Test 1/2
    PUB_KEY_AUTH=yes
    NUM=1
    if [ $(grep -i "^PubkeyAuthentication $PUB_KEY_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if SSH PubkeyAuthentication is $PUB_KEY_AUTH:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if SSH PubkeyAuthentication is $PUB_KEY_AUTH:\e[1;31m FAILED\e[0m (disabled)";
      ERR_MSG="SSH public key authentication is disabled";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 2/2
    NUM=1
    PASS_AUTH=no
    if [ $(grep -i "^PasswordAuthentication $PASS_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if SSH PasswordAuthentication is $PASS_AUTH:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if SSH PasswordAuthentication is $PASS_AUTH:\e[1;31m FAILED\e[0m (enabled)";
      ERR_MSG="$ERR_MSG SSH password authentication is enabled";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  TXT="$ERR_MSG"
  else
    echo -e "   [Test -.--] Check for SSH as management service: SKIPPED"
    echo -e "\t\e[33mNOTE!\e[0m SSH not enabled. Perform manual checks for management services!"
    SKIP=1;
    TXT="SSH service not enabled. Perform manual checks for managemet servives.";
  fi
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 23: The system must be connected to a central system for user administration.
REQ_TXT="The system must be connected to a central system for user\n   administration."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Not implemented! Manual Check necessary!
  echo -e "   [Test -.--] Check if system for central authentication is configured: SKIPPED"
  echo -e "\t\e[33mNOTE!\e[0m Automated testing not implemented: Check manual!"
  ERR_MSG="Not implemented! Depends on your used solution (LDAP, Kerberos etc.)."
  TXT="$ERR_MSG"
  SKIP=1;
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 24: Authentication must be used for single user mode.
REQ_TXT="Authentication must be used for single user mode."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  MODE_ERR=0

  # Test 1/1
  NUM=1
  if [ "$OS_MAIN_DISTRO" == "DEBIAN" ]; then
    CHK=$(awk -F":" '($1 == "root" && $2 == "[!*]") {print $1}' /etc/shadow)
    if [ ! -z  "$CHK" ]; then MODE_ERR=1; fi
  elif [ "$OS_MAIN_DISTRO" == "REDHAT" ] || \
       [ "$OS_MAIN_DISTRO" == "SUSE" ]; then
    CHK="ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\""
    if [ "$CHK" != "`grep ^ExecStart= /usr/lib/systemd/system/rescue.service`" ] && \
       [ "$CHK" != "`grep ^ExecStart= /usr/lib/systemd/system/emergency.service`" ]; then
      MODE_ERR=1;
    fi
  fi

  if [ $MODE_ERR = 0 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check single user mode:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check single user mode:\e[1;31m FAILED\e[0m (not activated)"
    ERR_MSG="Single user mode authentivation disabled";
    let FAIL=$FAIL+1;
    ERR=1;
  fi 
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 25: The management of the operating system must be done via a dedicated management network.
REQ_TXT="The management of the operating system must be done via a\n   dedicated management network."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Not implemented! Manual Check necessary!
  echo -e "   [Test -.--] Check management interface: SKIPPED"
  echo -e "\t\e[33mNOTE!\e[0m Automated testing not implemented: Check manual!"
  ERR_MSG="Not implemented! Check manual (Note: not needed for VMs on cloud)."
  TXT="$ERR_MSG"
  SKIP=1;
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 26: Management services must be bound to the management network.
REQ_TXT="Management services must be bound to the management network."  
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Not implemented! Manual Check necessary!
  echo -e "   [Test -.--] Check interface used for services: SKIPPED"
  echo -e "\t\e[33mNOTE!\e[0m Automated testing not implemented: Check manual!"
  ERR_MSG="Not implemented! Check manual (Note: not needed for VMs on cloud)."
  TXT="$ERR_MSG"
  SKIP=1;
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 27: Encrypted protocols must be used for management access to administrate 
#         the operating system.
REQ_TXT="Encrypted protocols must be used for management access to administrate\n   the operating system."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  CHK_SSH="$(ps -A | grep -ow 'sshd*$' | wc -l)"
  if [ $CHK_SSH -ne 0 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if SSH deamon is running:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if SSH deamon is running:\e[1;31m FAILED\e[0m (no process found)"
    ERR_MSG="SSH service not enabled. Perform manual checks for managemet servives.";
    let FAIL=$FAIL+1;
    ERR=1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 28: Auditing must be enabled at boot by setting a kernel parameter.
REQ_TXT="Auditing must be enabled at boot by setting a kernel parameter." 
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  ORG_IFS=$IFS;
  IFS=$'\n';

  for CHK_BOOT in $(grep "^\s*linux" ${!FILE_GRUB}); do
    if [ -n "$(echo $CHK_BOOT | grep "audit=1")" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if audit is present in grub.conf:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if audit is present in grub.conf:\e[1;31m FAILED\e[0m (found line without audit)"
      ERR_MSG="found line without audit in ${!FILE_GRUB}";
      let FAIL=$FAIL+1;
      ERR=1;
    fi;
  done;

  # Test 2/2
  for CHK_DEFAULT in $(grep -E "GRUB_CMDLINE_LINUX[_DEFAULT]?" /etc/default/grub); do
    if [ -n "$(echo $CHK_DEFAULT | grep "audit=1")" ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if audit is present in /etc/default/grub:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if audit is present in /etc/default/grub:\e[1;31m FAILED\e[0m (found line without audit enabled)"
      ERR_MSG="found line without audit in /etc/default/grub";
      let FAIL=$FAIL+1;
      ERR=1;
    fi;
  done;
  IFS=$ORG_IFS;
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 29: Log rotation for logfiles must be configured.
REQ_TXT="Log rotation for logfiles must be configured."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

    # Test 1/3
    NUM=1
    CHK=$(grep "[[:space:]]$LOG_ROTATE_TIME" $LOG_ROTATE_FILE)

    if [ -z "$CHK" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if logrotate time is set to $LOG_ROTATE_TIME:\e[1;31m FAILED\e[0m (wrong setting)";
      ERR_MSG="wrong logrotate time,";
      let FAIL=$FAIL+1;
      ERR=1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if logrotate time is set to $LOG_ROTATE_TIME:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    fi

    # Test 2/3
    NUM=1
    CHK_LINES_TOTAL=$(awk '/^[[:space:]]*rotate/' $LOG_ROTATE_FILE | wc -l)
    CHK_LINES=$(grep "rotate $LOG_ROTATE_COUNT" $LOG_ROTATE_FILE | wc -l)

    if [ $CHK_LINES -eq 0 ] || [ $CHK_LINES_TOTAL -ne $CHK_LINES ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if logrotate count is set to $LOG_ROTATE_COUNT:\e[1;31m FAILED\e[0m (wrong setting)";
      ERR_MSG="$ERR_MSG wrong logrotate count,";
      let FAIL=$FAIL+1;
      ERR=1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if logrotate count is set to $LOG_ROTATE_COUNT:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    fi

    # Test 3/3
    NUM=1
    CHK_LINES_TOTAL=$(awk '/^[[:space:]]*maxsize/' $LOG_ROTATE_FILE | wc -l)
    CHK_LINES=$(grep "maxsize $LOG_ROTATE_MAXSIZE" $LOG_ROTATE_FILE | wc -l)

   if [ $CHK_LINES -eq 0 ] || [ $CHK_LINES_TOTAL -ne $CHK_LINES ]; then
      echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if logrotate size is set to $LOG_ROTATE_MAXSIZE:\e[1;31m FAILED\e[0m (wrong setting)";
      ERR_MSG="$ERR_MSG wront logrotate file size";
      let FAIL=$FAIL+1;
      ERR=1;
    else
      echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if logrotate size is set to $LOG_ROTATE_MAXSIZE:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"


# Req 30: System time must be synchronized against a reference time source.
REQ_TXT="System time must be synchronized against a reference time source."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/3
  NUM=1
  for CHK in $NTP_SOFTWARE; do
    if [ "$($PACKAGE 2>/dev/null | grep -ow $CHK | wc -l)" -gt "0" ]; then
      ERR_CHK=0;
      break;
    else
      ERR_CHK=1;
    fi
  done

  if [ $ERR_CHK -eq 0 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if $CHK is installed:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if $CHK is installed:\e[1;31m FAILED\e[0m ($CHK not found)";
    ERR_MSG="no NTP service installed,";
    let FAIL=$FAIL+1;
    ERR=1;
  fi

  # Test 2/3
  NUM=1
  if [ "$(timedatectl | grep "synchronized: yes" | wc -l)" -eq "1" ]; then
    echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if time is synchronized:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if time is synchronized:\e[1;31m FAILED\e[0m (not synchronized)";
    ERR_MSG="$ERR_MSG time is not synchronized,";
    let FAIL=$FAIL+1;
    #ERR=1;
  fi

  # Test 3/3
  NUM=1
  if [ "$(timedatectl | grep -ow "$TIMEZONE" | wc -l)" -eq "1" ]; then
    echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if timezone is $TIMEZONE:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if timezone is $TIMEZONE:\e[1;31m FAILED\e[0m (wrong timezone)";
    ERR_MSG="$ERR_MSG timezone is not correct";
    let FAIL=$FAIL+1;
    ERR=1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 31: Auditd service must be used to log security relevant events. 
REQ_TXT="Auditd service must be used to log security relevant events."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/5
  NUM=1
  if [ "$($PACKAGE 2>/dev/null | grep -ow ${!AUDIT_DAEMON} | wc -l)" -eq "0" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if ${!AUDIT_DAEMON} is installed:\e[1;31m FAILED\e[0m (not present)";
    ERR_MSG="${!AUDIT_DAEMON} is not installed,";
    let FAIL=$FAIL+1;
    ERR=1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if ${!AUDIT_DAEMON} is installed:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  fi

  # Test 2/5
  NUM=1
  if [ "$(auditctl -s | awk -F"[ =]" '/enable/ {print $2}')" -ne "0" ]; then
    echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if ${!AUDIT_DAEMON} is enabled:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if ${!AUDIT_DAEMON} is enabled:\e[1;31m FAILED\e[0m (not enabled)";
    ERR_MSG="$ERR_MSG ${!AUDIT_DAEMON} is not enabled,";    
    let FAIL=$FAIL+1;
    ERR=1;
  fi

  # Test 3/5
  NUM=1
  if [ "$(grep -P "max_log_file\s+=\s+$MAX_LOG_FILE" /etc/audit/auditd.conf | wc -l)" -eq "0" ]; then
    echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check config if max size of logfiles is $MAX_LOG_FILE:\e[1;31m FAILED\e[0m (wrong value)";
    ERR_MSG="$ERR_MSG max_log_file is not $MAX_LOG_FILE,";    
    let FAIL=$FAIL+1;
    ERR=1;
  else
    let PASS=$PASS+1;
    echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check config if max size of logfiles is $MAX_LOG_FILE:\e[1;32m PASSED\e[0m";
  fi

  # Test 4/5
  NUM=1
  if [ "$(grep -P "num_logs\s+=\s+$MAX_NUM_LOGS" /etc/audit/auditd.conf | wc -l)" -eq "0" ]; then
    echo -e "   [Test 4.$(add_zero $NUM)$(((NUM++)))] Check config if number of logfiles is $MAX_NUM_LOGS:\e[1;31m FAILED\e[0m (wrong value)";
    ERR_MSG="$ERR_MSG num_logs is not $MAX_NUM_LOGS,";    
    let FAIL=$FAIL+1;
    ERR=1;
  else
    echo -e "   [Test 4.$(add_zero $NUM)$(((NUM++)))] Check config if number of logfiles is $MAX_NUM_LOGS:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  fi

  # Test 5/5
  NUM=1
  if [ "$(grep -P "max_log_file_action\s+=\s+$MAX_LOG_FILE_ACTION" /etc/audit/auditd.conf | wc -l)" -eq "0" ]; then
    echo -e "   [Test 5.$(add_zero $NUM)$(((NUM++)))] Check config if logfile action is $MAX_LOG_FILE_ACTION:\e[1;31m FAILED\e[0m (wrong value)";
    ERR_MSG="$ERR_MSG max_log_file_action is not $MAX_LOG_FILE_ACTION";    
    let FAIL=$FAIL+1;
    ERR=1;
  else
    echo -e "   [Test 5.$(add_zero $NUM)$(((NUM++)))] Check config if logfile action is $MAX_LOG_FILE_ACTION:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 32: System events must be logged.
REQ_TXT="System events must be logged."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  CNT=1
  SYS_EVENTS=SYS_EVENTS_$CNT

  # Test 1/2
  NUM=1
  ERR_MSG="Events missing:";
  while [ $CNT -lt 100 ]; do
    if [ -n "${!SYS_EVENTS}" ]; then
      SYS_EVENTS_NEW=$(echo ${!SYS_EVENTS} | sed 's/^.//' | sed 's/ -/ \\-/g')
      if [ "$(auditctl -l | grep -E "$SYS_EVENTS_NEW" | wc -l)" -eq "0" ]; then
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check auditd for system events:\e[1;31m FAILED\e[0m (event missing: ${!SYS_EVENTS})";
        ERR_MSG="$ERR_MSG ${!SYS_EVENTS},";
        let FAIL=$FAIL+1;
        ERR=1;
      else
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check auditd for system events:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
        #let NUM++;
      fi
      let CNT++;
      SYS_EVENTS=SYS_EVENTS_$CNT;
    else
      CNT=100;
    fi
  done

  # Test 2/2
  NUM=1
  CNT=1
  SYS_EVENTS_OS=SYS_EVENTS_$OS_MAIN_DISTRO$CNT

  while [ $CNT -lt 100 ]; do
    SYS_EVENTS_OS_NEW=$(echo ${!SYS_EVENTS_OS} | sed 's/^.//' | sed 's/ -/ \\-/g')
    if [ -n "${!SYS_EVENTS_OS}" ]; then
      if [ "$(auditctl -l | grep -E "$SYS_EVENTS_OS_NEW" | wc -l)" -eq "0" ]; then
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check auditd for OS specific system events:\e[1;31m FAILED\e[0m (event missing: ${!SYS_EVENTS_OS})";
        ERR_MSG="$ERR_MSG ${!SYS_EVENTS_OS},";
        let FAIL=$FAIL+1;
        ERR=1;
      else
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check auditd for OS specific system events:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      fi
      let CNT++;
      SYS_EVENTS_OS=SYS_EVENTS_$OS_MAIN_DISTRO$CNT;
    else
      CNT=100;
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 33: Access and Authentication events must be logged.
REQ_TXT="Access and Authentication events must be logged."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  CNT=1
  ACCESS_EVENTS=ACCESS_EVENTS_$CNT

  # Test 1/3
  NUM=1
  ERR_MSG="Events missing:";
  while [ $CNT -lt 100 ]; do
    if [ -n "${!ACCESS_EVENTS}" ]; then
      ACCESS_EVENTS_NEW=$(echo ${!ACCESS_EVENTS} | sed 's/^.//' | sed 's/ -/ \\-/g')
      if [ "$(auditctl -l | grep -E "$ACCESS_EVENTS_NEW" | wc -l)" -eq "0" ]; then
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check auditd for account events:\e[1;31m FAILED\e[0m (event missing: ${!ACCESS_EVENTS})";
        ERR_MSG="$ERR_MSG ${!ACCESS_EVENTS},";
        let FAIL=$FAIL+1;
        ERR=1;
      else
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check auditd for account events:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      fi
      let CNT++;
      ACCESS_EVENTS=ACCESS_EVENTS_$CNT;
    else
      CNT=100;
    fi
  done

  # Test 2/3
  NUM=1
  CNT=1
  ACCESS_EVENTS_OS=ACCESS_EVENTS_$OS_MAIN_DISTRO$CNT

  while [ $CNT -lt 100 ]; do
    ACCESS_EVENTS_OS_NEW=$(echo ${!SYS_EVENTS_OS} | sed 's/^.//' | sed 's/ -/ \\-/g')
    if [ -n "${!ACCESS_EVENTS_OS}" ]; then
      if [ "$(auditctl -l | grep -E "$ACCESS_EVENTS_OS_NEW" | wc -l)" -eq "0" ]; then
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check auditd for OS specific account events:\e[1;31m FAILED\e[0m (event missing: ${!ACCESS_EVENTS_OS})";
        ERR_MSG="$ERR_MSG ${!ACCESS_EVENTS_OS},";
        let FAIL=$FAIL+1;
        ERR=1;
      else
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check auditd for OS specific account events:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      fi
      let CNT++;
      ACCESS_EVENTS_OS=ACCESS_EVENTS_$OS_MAIN_DISTRO$CNT;
    else
      CNT=100;
    fi
  done

  # Test 3/3
  NUM=1
  PRIV_COMMAND="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f \( -perm -4000 -o -perm -2000 \) -print 2>/dev/null)"

  for CHK in $PRIV_COMMAND; do
    EVENT="-a always,exit -S all -F path=$CHK -F perm=x -F auid>=1000 -F auid!=-1 -F key=privileged"
    EVENT_NEW=$(echo $EVENT | sed 's/^.//' | sed 's/ -/ \\-/g')
    if [ "$(auditctl -l | grep -E "$EVENT_NEW" | wc -l)" -eq "0" ]; then
      echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check auditd for events for priviledged command $CHK:\e[1;31m FAILED\e[0m (event missing)";
      ERR_MSG="$ERR_MSG $EVENT,";
      let FAIL=$FAIL+1;
      ERR=1;
    else
      echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check auditd for events for priviledged command $CHK:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 34: Account and Group Management events must be logged.
REQ_TXT="Account and Group Management events must be logged."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  CNT=1
  ACC_GRP_MGMT_EVENTS=ACC_GRP_MGMT_EVENTS_$CNT

  # Test 1/1
  NUM=1
  ERR_MSG="Events missing:";
  while [ $CNT -lt 100 ]; do
    if [ -n "${!ACC_GRP_MGMT_EVENTS}" ]; then
      ACC_GRP_MGMT_EVENTS_NEW=$(echo ${!ACC_GRP_MGMT_EVENTS} | sed 's/^.//' | sed 's/ -/ \\-/g')
      if [ "$(auditctl -l | grep -E "$ACC_GRP_MGMT_EVENTS_NEW" | wc -l)" -eq "0" ]; then
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check auditd for account mgmt events:\e[1;31m FAILED\e[0m (event missing: ${!ACC_GRP_MGMT_EVENTS})";
        ERR_MSG="$ERR_MSG ${!ACC_GRP_MGMT_EVENTS},";
        let FAIL=$FAIL+1;
        ERR=1;
      else
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check auditd for account mgmt events:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      fi
      let CNT++;
      ACC_GRP_MGMT_EVENTS=ACC_GRP_MGMT_EVENTS_$CNT;
    else
      CNT=100;
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 35: Configuration Change events must be logged.
REQ_TXT="Configuration Change events must be logged."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  CNT=1
  CHANGE_EVENTS=CHANGE_EVENTS_$CNT

  # Test 1/2
  NUM=1
  ERR_MSG="Events missing:";
  while [ $CNT -lt 100 ]; do
    if [ -n "${!CHANGE_EVENTS}" ]; then
      CHANGE_EVENTS_NEW=$(echo ${!CHANGE_EVENTS} | sed 's/^.//' | sed 's/ -/ \\-/g')
      if [ "$(auditctl -l | grep -E "$CHANGE_EVENTS_NEW" | wc -l)" -eq "0" ]; then
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check auditd for change events:\e[1;31m FAILED\e[0m (event missing: ${!CHANGE_EVENTS})";
        ERR_MSG="$ERR_MSG ${!CHANGE_EVENTS},";
        let FAIL=$FAIL+1;
        ERR=1;
      else
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check auditd for change events:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      fi
      let CNT++;
      CHANGE_EVENTS=CHANGE_EVENTS_$CNT;
    else
      CNT=100;
    fi
  done

  # Test 2/2
  NUM=1
  CNT=1
  CHANGE_EVENTS_OS=CHANGE_EVENTS_$OS_MAIN_DISTRO$CNT

  while [ $CNT -lt 100 ]; do
    CHANGE_EVENTS_OS_NEW=$(echo ${!CHANGE_EVENTS_OS} | sed 's/^.//' | sed 's/ -/ \\-/g')
    if [ -n "${!CHANGE_EVENTS_OS}" ]; then
      if [ "$(auditctl -l | grep -E "$CHANGE_EVENTS_OS_NEW" | wc -l)" -eq "0" ]; then
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check auditd for OS specific change events:\e[1;31m FAILED\e[0m (event missing: ${!CHANGE_EVENTS_OS})";
        ERR_MSG="$ERR_MSG ${!CHANGE_EVENTS_OS},";
        let FAIL=$FAIL+1;
        ERR=1;
      else
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check auditd for OS specific change events:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      fi
      let CNT++;
      CHANGE_EVENTS_OS=CHANGE_EVENTS_$OS_MAIN_DISTRO$CNT;
    else
      CNT=100;
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 36: Auditd configuration must be immutable.
REQ_TXT="Auditd configuration must be immutable."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  if [ $OS == "ubuntu" ] && [ "$MAJOR_VERSION" -eq "16" ]; then
    CONFIG_FILE="/etc/audit/audit.rules";
  else
    CONFIG_FILE="/etc/audit/rules.d/audit.rules";
  fi

  # Test 1/1
  NUM=1
  if [ "$(grep "\-e 2" $CONFIG_FILE | wc -l)" -eq "0" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check auditd config is immutable:\e[1;31m FAILED\e[0m (entry '-e 2' not found)";
    ERR_MSG="auditd config is not immutable";
    let FAIL=$FAIL+1;
    ERR=1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check auditd config is immutable:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 37: Security relevant logging data must be send to an external
#         system direct after their creation.
REQ_TXT="Security relevant logging data must be send to an external\n   system direct after their creation."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ "$SYSLOG_TYPE" == "rsyslog" ]; then
    CHK=$(ps -A | grep $SYSLOG_TYPE)
    if [ -z "$CHK" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check $SYSLOG_TYPE is installed and running:\e[1;31m FAILED\e[0m ($SYSLOG_TYPE not running)";
      ERR_MSG="$SYSLOG_TYPE not installed/running";
      let FAIL=$FAIL+1;
      ERR=1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check $SYSLOG_TYPE is installed and running:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    fi
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check $SYSLOG_TYPE is installed and running:\e[1;31m FAILED\e[0m ($SYSLOG_TYPE not supported! Check manual.)";
    ERR_MSG="$SYSLOG_TYPE not supported! Check manual";
    let FAIL=$FAIL+1;
    ERR=1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 38: If RSyslog is used, the default permission of 640 or more 
#         restrictive for logfiles must be configured.
REQ_TXT="If RSyslog is used, the default permission of 640 or more\n   restrictive for logfiles must be configured."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  if [ "$SYSLOG_TYPE" == "rsyslog" ]; then
    ERR_MSG="${!RSYSLOG_CONF}:"
    # Test 1/3
    NUM=1
    PRIV=$(stat -c %a ${!RSYSLOG_CONF})
    if [ "$PRIV" -le "640" ]; then 
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if priviledges of ${!RSYSLOG_CONF} is 640 or less:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if priviledges of ${!RSYSLOG_CONF} is 640 or less:\e[1;31m FAILED\e[0m (is $PRIV)";
      ERR_MSG="$ERR_MSG wrong priviledges ($PRIV),";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
    # Test 2/3
    NUM=1
    USER=$(stat -c '%U' ${!RSYSLOG_CONF})
    if [ "$USER" == "root" ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if owner of ${!RSYSLOG_CONF} is root:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if owner of ${!RSYSLOG_CONF} is root:\e[1;31m FAILED\e[0m (owner is $USER)";
      ERR_MSG="$ERR_MSG wrong user ($USER),";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
    # Test 3/3
    NUM=1
    GROUP=$(stat -c '%G' ${!RSYSLOG_CONF})
    if [ "$GROUP" == "root" ]; then
      echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if group of ${!RSYSLOG_CONF} is root:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if group of ${!RSYSLOG_CONF} is root:\e[1;31m FAILED\e[0m (group is $GROUP)";
      ERR_MSG="$ERR_MSG wrong group ($GROUP)";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  else
    echo -e "   [Test -.--] Check file permission, owner and group of ${!RSYSLOG_CONF}: n/a (rsyslog not used)";
    SKIP=1;
    ERR_MSG="Rsyslog not used";
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 39: If RSyslog is used, at least one central logging server must be configured.
REQ_TXT="If RSyslog is used, at least one central logging server must be\n   configured."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ "$SYSLOG_TYPE" == "rsyslog" ]; then
    if [ "$(rsyslogd -N1 &>/dev/null && echo $?)" -eq "0" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check $SYSLOG_TYPE configuration:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check $SYSLOG_TYPE configuration:\e[1;31m FAILED\e[0m (error(s) found)";
      ERR_MSG="Central logging did not work";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  else
    echo -e "   [Test -.--] Check $SYSLOG_TYPE configuration: n/a (rsyslog not used)";
    SKIP=1;
    ERR_MSG="Rsyslog not used";
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 40: If Syslog-NG is used, the default permission of 640 or more 
#         restrictive for logfiles must be configured.
REQ_TXT="If Syslog-NG is used, the default permission of 640 or more\n   restrictive for logfiles must be configured."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  if [ "$SYSLOG_TYPE" == "syslog-ng" ]; then
    echo -e "   [Test -.--] Check file permission, owner and group for syslog-ng:\e[1;31m FAILED\e[0m (hardening not implemented yet!)"
    ERR_MSG="Automated hardening not implemented!"
    let FAIL=$FAIL+1;
    ERR=1;
  else
    echo -e "   [Test -.--] Check file permission, owner and group for syslog-ng: SKIPPED"
    echo -e "\t\e[33mNOTE!\e[0m Automated testing not implemented: Check manual!"
    ERR_MSG="Syslog-ng not used";
    SKIP=1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 41: If Syslog-NG is used, at least one central logging server must be configured.
REQ_TXT="If Syslog-NG is used, at least one central logging server must be\n   configured."
initiate_test

PAM_FILES_REDHAT="password-auth system-auth";
PAM_FILES_SUSE="common-password";
PAM_FILES_DEBIAN="common-password";
PAM_FILES_OS="PAM_FILES_$OS_MAIN_DISTRO";

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  if [ "$SYSLOG_TYPE" == "syslog-ng" ]; then
    echo -e "   [Test -.--] Check syslog-ng configuration:\e[1;31m FAILED\e[0m (hardening not implemented yet!)"
    ERR_MSG="Automated hardening not implemented!"
    let FAIL=$FAIL+1;
    ERR=1;
  else
    echo -e "   [Test -.--] Check syslog-ng configuration: SKIPPED"
    echo -e "\t\e[33mNOTE!\e[0m Automated testing not implemented: Check manual!"
    ERR_MSG="Syslog-ng not used";
    SKIP=1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 42: If PAM is used, it needs to be reconfigured to use strong salted 
#         password hash functions while doing many calculation rounds to protect 
#         passwords.
REQ_TXT="If PAM is used, it needs to be reconfigured to use strong salted\n   password hash functions while doing many calculation rounds to protect\n   passwords."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  PAM_FILES_REDHAT="password-auth system-auth";
  PAM_FILES_SUSE="common-password";
  PAM_FILES_DEBIAN="common-password";
  PAM_FILES_OS="PAM_FILES_$OS_MAIN_DISTRO";
  
  NUM1=1;
  NUM2=1;
  ERR_MSG="wrong PAM configuration:";

  for CHK in ${!PAM_FILES_OS}; do
    # Test 1/2
    SEARCH_METHOD="$(grep -e 'pam_unix.so' /etc/pam.d/$CHK | grep $PAM_ENRYPT_METHOD | wc -l)"
    if [ $SEARCH_METHOD -eq 1 ]; then
      echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) encryption method ($PAM_ENRYPT_METHOD) for password hashing:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) encryption method ($PAM_ENRYPT_METHOD) for password hashing:\e[1;31m FAILED\e[0m (wrong value)"
      ERR_MSG="$ERR_MSG encryption method in /etc/pam.d/$CHK,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 2/2
    
    SEARCH_ROUNDS="$(grep -e 'pam_unix.so' /etc/pam.d/$CHK | grep rounds=$PAM_ROUNDS | wc -l)"
    if [ $SEARCH_ROUNDS -eq 1 ]; then
      echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) for rounds ($PAM_ROUNDS) for password hashing:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) for rounds ($PAM_ROUNDS) for password hashing:\e[1;31m FAILED\e[0m (wrong value)"
      ERR_MSG="$ERR_MSG rounds in /etc/pam.d/$CHK,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi

write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 43: If PAM is used, password rules must be configured for PAM to 
#         force the use of passwords with a minimum length of 12 characters 
#         and a combination of three out of the following categories: upper 
#         cases, lower case, numbers and special characters.
REQ_TXT="If PAM is used, password rules must be configured for PAM to\n   force the use of passwords with a minimum length of 12 characters\n   and a combination of three out of the following categories: upper\n   cases, lower case, numbers and special characters."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  PAM_MODULE_SUSE="pam_cracklib.so";
  PAM_MODULE_DEBIAN="pam_pwquality.so";
  PAM_MODULE_OS="PAM_MODULE_$OS_MAIN_DISTRO";

  NUM1=1
  NUM2=1
  ERR_MSG="wrong PAM configuration:";

  for CHK in ${!PAM_FILES_OS}; do
    if [ "$OS_MAIN_DISTRO" == "REDHAT" ]; then
      
      # Test 1/2 (RedHat)
      SEARCH_PASS_LEN="$(awk -F\= '/minlen/ {print $2}' /etc/security/pwquality.conf | tr -d " ")"
      if [ $SEARCH_PASS_LEN -ge $PAM_PASSWORD_LENGTH ]; then
        echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check pam (/etc/security/pwquality.conf) password length ($PAM_PASSWORD_LENGTH):\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      else
        echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check pam (/etc/security/pwquality.conf) password length ($PAM_PASSWORD_LENGTH):\e[1;31m FAILED\e[0m (wrong value)"
        ERR_MSG="$ERR_MSG password length in /etc/security/pwquality.conf,";
        let FAIL=$FAIL+1;
        ERR=1;
      fi

      #Test 2/2 (RedHat)
      SEARCH_MINCLASS="$(grep "minclass *= *$PAM_CHAR_CLASSES" /etc/security/pwquality.conf | wc -l)"
      if [ $SEARCH_MINCLASS -eq 1 ]; then
        echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check pam (/etc/security/pwquality.conf) allowed character classes ($PAM_CHAR_CLASSES) for passwords:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      else
        echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check pam (/etc/security/pwquality.conf) allowed character classes  ($PAM_CHAR_CLASSES) for passwords:\e[1;31m FAILED\e[0m (wrong value)"
        ERR_MSG="$ERR_MSG password classes in /etc/security/pwquality.conf,";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    else
    
      # Test 1/2 (Suse + Ubuntu)
      SEARCH_PASS_LEN="$(grep -e ${!PAM_MODULE_OS} /etc/pam.d/$CHK | grep "minlen=$PAM_PASSWORD_LENGTH" | wc -l)"
      if [ $SEARCH_PASS_LEN -eq 1 ]; then
        echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) password length ($PAM_PASSWORD_LENGTH):\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      else
        echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) password length ($PAM_PASSWORD_LENGTH):\e[1;31m FAILED\e[0m (wrong value)"
        ERR_MSG="$ERR_MSG password length in /etc/pam.d/$CHK,";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
      
      # Test 2/2 (Suse + Ubuntu)
      SEARCH_MINCLASS="$(grep -e ${!PAM_MODULE_OS} /etc/pam.d/$CHK | grep "minclass=$PAM_CHAR_CLASSES" | wc -l)"
      if [ $SEARCH_MINCLASS -eq 1 ]; then
        echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) allowed character classes ($PAM_CHAR_CLASSES) for passwords:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      else
        echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) allowed character classes  ($PAM_CHAR_CLASSES) for passwords:\e[1;31m FAILED\e[0m (wrong value)";
        ERR_MSG="$ERR_MSG password classes in /etc/pam.d/$CHK,";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    fi
  done

  #Test Password
  USER="new"
  PW_SHORT="pV.32_0pmBI"  # len <12
  PW_SIMPL="pvo32l0pmbi4" # not mix 3 of uc/lc/nu/sc
  PASSWORD="pV.32_0pmBIx" # len =12, mix of chars
  NUM=1

  useradd $USER &>/dev/null

  # Test 3/3
  # password to short
  CHK_LENGTH="$(printf "$PW_SHORT\n$PW_SHORT\n\n" | passwd $USER 2>&1 |  grep "short\|simple" | wc -l)"
  # password to simple
  CHK_COMPLX="$(printf "$PW_SIMPL\n$PW_SIMPL\n\n" | passwd $USER 2>&1 |  grep "short\|classes" | wc -l)"
  # valid password
  CHK_VALID="$(printf "$PASSWORD\n$PASSWORD\n\n" | passwd $USER 2>&1 | grep "BAD PASSWORD" | wc -l)"

  if [ $CHK_LENGTH -eq 0 ] || [ $CHK_COMPLX -eq 0 ] || [ $CHK_VALID -eq 0 ]; then 
    let PASS=$PASS+1;
    echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check for password complexity rules:\e[1;32m PASSED\e[0m";
  else
    echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check for password complexity rules:\e[1;31m FAILED\e[0m (rule set wrong)"
    ERR_MSG="$ERR_MSG rule set (lenth/classes) wrong,";
    let FAIL=$FAIL+1;
    ERR=1;
  fi

  userdel -r $USER &>/dev/null

  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 44: If PAM is used, a protection against brute force and dictionary
#         attacks that hinder password guessing must be configured in PAM.
REQ_TXT="If PAM is used, a protection against brute force and dictionary\n   attacks that hinder password guessing must be configured in PAM."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  PAM_MODULE_REDHAT="pam_faillock.so";
  PAM_MODULE_SUSE="pam_tally2.so";
  PAM_MODULE_DEBIAN="pam_tally2.so";
  PAM_MODULE_OS="PAM_MODULE_$OS_MAIN_DISTRO";
  PAM_FILES_SUSE="login";
  PAM_FILES_DEBIAN="common-account";
  PAM_FILES_OS="PAM_FILES_$OS_MAIN_DISTRO";

  NUM1=1
  NUM2=1
  ERR_MSG="wrong PAM configuration:";

  for CHK in ${!PAM_FILES_OS}; do
    # Test 1/2
    SEARCH_ATTEMPS="$(grep -e ${!PAM_MODULE_OS} /etc/pam.d/$CHK | grep "deny=$PAM_FAILED_LOGIN_ATTEMPS" | wc -l)"
    if [ $SEARCH_ATTEMPS -ne 0 ]; then
      echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) failed login attemps ($PAM_FAILED_LOGIN_ATTEMPS):\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) failed login attemps ($PAM_FAILED_LOGIN_ATTEMPS):\e[1;31m FAILED\e[0m (wrong configuration)"
      ERR_MSG="$ERR_MSG failed login attemps in /etc/pam.d/$CHK";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 2/2
    SEARCH_UNLOCK_TIME="$(grep -e ${!PAM_MODULE_OS} /etc/pam.d/$CHK | grep "unlock_time=$PAM_UNLOCK_TIME" | wc -l)"
    if [ $SEARCH_UNLOCK_TIME -ne 0 ]; then
      echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) unlock time ($PAM_UNLOCK_TIME):\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) unlock time ($PAM_UNLOCK_TIME):\e[1;31m FAILED\e[0m (wrong configuration)"
      ERR_MSG="$ERR_MSG failed unlock time in /etc/pam.d/$CHK";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 45: If PAM is used, PAM must be configured that motd did not
#         contain any sensitive data.
REQ_TXT="If PAM is used, PAM must be configured that motd did not\n   contain any sensitive data."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  NUM=1
  ERR_MSG="wrong PAM configuration:";
  for CHK in $PAM_FILES_MOTD; do
    # Test 1/1
    SEARCH_MOTD="$(grep "pam_motd.so" /etc/pam.d/$CHK | grep -v "^#" | wc -l)"
    if [ $SEARCH_MOTD -eq 0 ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check pam (/etc/pam.d/$CHK) if motd is enabled:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check pam (/etc/pam.d/$CHK) if motd is enabled:\e[1;31m FAILED\e[0m (wrong configuration)"
      ERR_MSG="$ERR_MSG motd enabled in /etc/pam.d/$CHK,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 46: If iptables is used, policies for loopback traffic must be configured.
REQ_TXT="If iptables is used, policies for loopback traffic must be configured."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  for CNT in 1 2 3; do
    IPTABLES_RULE=IPTABLES_RULE_LOOP_$CNT
    IPTABLES_RULE_NEW="$(echo ${!IPTABLES_RULE} | sed 's/^.//' | sed 's/ -/ \\-/g')"
    CHK_IPTABLES="$(iptables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
    if [ $CHK_IPTABLES -eq 1 ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check iptables ipv4 rule '"${!IPTABLES_RULE}"':\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check iptables ipv4 rule '"${!IPTABLES_RULE}"':\e[1;31m FAILED\e[0m (rule missing)"
      ERR_MSG="$ERR_MSG ${!IPTABLES_RULE} missing,";        
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done
  
  # Test 2/2
  if [ "$IPV6_CHECK" == "ON" ]; then 
    NUM=1
    IPTABLES_RULE_LOOP_3=$IP6TABLES_RULE_LOOP_3
    for CNT in 1 2 3; do
      IPTABLES_RULE=IPTABLES_RULE_LOOP_$CNT
      IPTABLES_RULE_NEW="$(echo ${!IPTABLES_RULE} | sed 's/^.//' | sed 's/ -/ \\-/g')"
      CHK_IPTABLES="$(ip6tables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
      if [ $CHK_IPTABLES -eq 1 ]; then
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check iptables IPv6 rule '"${!IPTABLES_RULE}"':\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      else
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check iptables IPv6 rule '"${!IPTABLES_RULE}"':\e[1;31m FAILED\e[0m (rule missing)"
        ERR_MSG="$ERR_MSG ${!IPTABLES_RULE} (IPv6) missing,";        
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    done
  else
    echo -e "   [Test 2.1] Check iptables IPv6 rules: n/a (IPv6 disabled)";
    SKIP=1;
    TXT="IPv6 is disabled";   
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 47: If iptables is used, policies for outbound and established 
#         connections must be configured.
REQ_TXT="If iptables is used, policies for outbound and established connections\n   must be configured."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  for CNT in 1 2 3 4 5 6; do
    IPTABLES_RULE=IPTABLES_RULE_OUT_$CNT
    IPTABLES_RULE_NEW="$(echo ${!IPTABLES_RULE} | sed 's/^.//' | sed 's/ -/ \\-/g')"
    CHK_IPTABLES="$(iptables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
    if [ $CHK_IPTABLES -eq 1 ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check iptables ipv4 rule '"${!IPTABLES_RULE}"':\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check iptables ipv4 rule '"${!IPTABLES_RULE}"':\e[1;31m FAILED\e[0m (rule missing)"
      ERR_MSG="$ERR_MSG ${!IPTABLES_RULE} missing,"; 
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done

  # Test 1/2
  if [ "$IPV6_CHECK" == "ON" ]; then 
    NUM=1    
    for CNT in 1 2 3 4 5 6; do
      IPTABLES_RULE=IPTABLES_RULE_OUT_$CNT
      IPTABLES_RULE_NEW="$(echo ${!IPTABLES_RULE} | sed 's/^.//' | sed 's/ -/ \\-/g')"
      CHK_IPTABLES="$(ip6tables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
      if [ $CHK_IPTABLES -eq 1 ]; then
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check iptables IPv6 rule '"${!IPTABLES_RULE}"':\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      else
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check iptables IPv6 rule '"${!IPTABLES_RULE}"':\e[1;31m FAILED\e[0m (rule missing)"
        ERR_MSG="$ERR_MSG ${!IPTABLES_RULE} ipv6 missing,"; 
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    done
  else
    echo -e "   [Test 2.1] Check iptables IPv6 rules: n/a (IPv6 disabled)";
    SKIP=1;
    TXT="IPv6 is disabled";   
  fi    
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 48: If iptables is used, policies must exist for all ports in 
#         listening state.
REQ_TXT="If iptables is used, policies must exist for all ports in\n   listening state." 
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  if [ -n "$TCP_PORTS" ]; then 
     
    # Test 1/6 TCP
    NUM=1
    IPTABLES_RULE="$(echo $IPTABLES_RULE_TCP | sed 's/^.//' | sed 's/ -/ \\-/g')";
    for CHK in $TCP_PORTS; do
      CHK_TCP_RULE="$(iptables -S | grep -i "$IPTABLES_RULE $CHK \-j ACCEPT")"
      if [ -n "$CHK_TCP_RULE" ]; then
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check iptables rules for TCP port $CHK:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      else
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check iptables rules for TCP port $CHK:\e[1;31m FAILED\e[0m (no rule exists)";
        ERR_MSG="no rule TCP/$CHK,";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    done

    # Test 2/6 TCP
    if [ "$IPV6_CHECK" == "ON" ]; then 
      NUM=1
      IPTABLES_RULE="$(echo $IPTABLES_RULE_TCP | sed 's/^.//' | sed 's/ -/ \\-/g')";
      for CHK in $TCP_PORTS; do
        CHK_TCP_RULE="$(ip6tables -S | grep -i "$IPTABLES_RULE $CHK \-j ACCEPT")"
        if [ -n "$CHK_TCP_RULE" ]; then
          echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check iptables IPv6 rules for TCP port $CHK:\e[1;32m PASSED\e[0m";
          let PASS=$PASS+1;
        else
          echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check iptables IPv6 rules for TCP port $CHK:\e[1;31m FAILED\e[0m (no rule exists)";
          ERR_MSG="no rule IPv6 TCP/$CHK,";
          let FAIL=$FAIL+1;
          ERR=1;
        fi
      done
    else
      echo -e "   [Test 2.1] Check iptables IPv6 TCP rules: n/a (IPv6 disabled)";
      SKIP=1;
      TXT="IPv6 is disabled";   
    fi    
  else
    echo -e "   [Test -.--] Check iptables rules for TCP port: SKIPPED (no TCP ports open)";
    SKIP=1;
    ERR_MSG="no TCP ports open,";
  fi

  if [ -n "$UDP_PORTS" ]; then 
    # Test 3/6 UDP
    NUM=1
    IPTABLES_RULE="$(echo $IPTABLES_RULE_UDP | sed 's/^.//' | sed 's/ -/ \\-/g')";
    for CHK in $UDP_PORTS; do
      CHK_UDP_RULE="$(iptables -S | grep -i "$IPTABLES_RULE $CHK \-j ACCEPT")";
      if [ -n "$CHK_UDP_RULE" ]; then
        echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check iptables rules for UDP port $CHK:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      else
        echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check iptables rules for UDP port $CHK:\e[1;31m FAILED\e[0m (no rule exists)";
        ERR_MSG="no rule UDP/$CHK,";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    done
    
    # Test 4/6 UDP
    if [ "$IPV6_CHECK" == "ON" ]; then 
      NUM=1
      IPTABLES_RULE="$(echo $IPTABLES_RULE_UDP | sed 's/^.//' | sed 's/ -/ \\-/g')";
      for CHK in $UDP_PORTS; do
        CHK_UDP_RULE="$(ip6tables -S | grep -i "$IPTABLES_RULE $CHK \-j ACCEPT")";
        if [ -n "$CHK_UDP_RULE" ]; then
          echo -e "   [Test 4.$(add_zero $NUM)$(((NUM++)))] Check iptables IPv6 rules for UDP port $CHK:\e[1;32m PASSED\e[0m";
          let PASS=$PASS+1;
        else
          echo -e "   [Test 4.$(add_zero $NUM)$(((NUM++)))] Check iptables IPv6 rules for UDP port $CHK:\e[1;31m FAILED\e[0m (no rule exists)";
          ERR_MSG="no rule IPv6 UDP/$CHK,";
          let FAIL=$FAIL+1;
          ERR=1;
        fi
      done      
    else
      echo -e "   [Test 2.1] Check iptables IPv6 UDP rules: n/a (IPv6 disabled)";
      SKIP=1;
      TXT="IPv6 is disabled";   
    fi        
  else
    echo -e "   [Test -.--] Check iptables rules for UDP port: SKIPPED (no UDP ports open)";
    SKIP=1;
    ERR_MSG="$ERR_MSG no UDP ports open,";
  fi

  # Test 5/6 ICMP
  NUM=1
  IPTABLES_RULE_NEW="$(echo $IPTABLES_RULE_ICMP | sed 's/^.//' | sed 's/ -/ \\-/g')"
  CHK_IPTABLES="$(iptables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
  if [ $CHK_IPTABLES -eq 1 ]; then
    echo -e "   [Test 5.$(add_zero $NUM)$(((NUM++)))] Check iptables rule for ICMP:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 5.$(add_zero $NUM)$(((NUM++)))] Check iptables rule for ICMP:\e[1;31m FAILED\e[0m (rule missing)"
    ERR_MSG="$ERR_MSG no rule ICMP,";
    let FAIL=$FAIL+1;
    ERR=1;
  fi

  # Test 6/6 ICMP
  if [ "$IPV6_CHECK" == "ON" ]; then 
    NUM=1
    IPTABLES_RULE_NEW="$(echo $IP6TABLES_RULE_ICMP | sed 's/^.//' | sed 's/ -/ \\-/g')"
    CHK_IPTABLES="$(ip6tables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
    if [ $CHK_IPTABLES -eq 1 ]; then
      echo -e "   [Test 6.$(add_zero $NUM)$(((NUM++)))] Check iptables IPv6 rule for ICMP:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 6.$(add_zero $NUM)$(((NUM++)))] Check iptables IPv6 rule for ICMP:\e[1;31m FAILED\e[0m (rule missing)"
      ERR_MSG="$ERR_MSG no rule IPv6 ICMP,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  else
    echo -e "   [Test 2.1] Check iptables IPv6 ICMP rules: n/a (IPv6 disabled)";
    SKIP=1;
    TXT="IPv6 is disabled";   
  fi      
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 49: If iptables is used, the default policy for tables INPUT and FORWARD 
#         must be configured to drop all traffic.
REQ_TXT="If iptables is used, the default policy for tables INPUT and FORWARD\n   must be configured to drop all traffic."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  for CNT in 1 2 3; do
    IPTABLES_RULE=IPTABLES_RULE_DROP_$CNT
    IPTABLES_RULE_NEW="$(echo ${!IPTABLES_RULE} | sed 's/^.//' | sed 's/ -/ \\-/g')"
    CHK_IPTABLES="$(iptables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
    if [ $CHK_IPTABLES -eq 1 ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check iptables rule '"${!IPTABLES_RULE}"':\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check iptables rule '"${!IPTABLES_RULE}"':\e[1;31m FAILED\e[0m (rule missing)"
      ERR_MSG="$ERR_MSG ${!IPTABLES_RULE} missing,"
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done

  # Test 2/2  
  if [ "$IPV6_CHECK" == "ON" ]; then 
    NUM=1
    for CNT in 1 2 3; do
      IPTABLES_RULE=IPTABLES_RULE_DROP_$CNT
      IPTABLES_RULE_NEW="$(echo ${!IPTABLES_RULE} | sed 's/^.//' | sed 's/ -/ \\-/g')"
      CHK_IPTABLES="$(ip6tables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
      if [ $CHK_IPTABLES -eq 1 ]; then
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check iptables rule '"${!IPTABLES_RULE}"':\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
      else
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check iptables rule '"${!IPTABLES_RULE}"':\e[1;31m FAILED\e[0m (rule missing)"
        ERR_MSG="$ERR_MSG ${!IPTABLES_RULE} missing,"
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    done
  else
    echo -e "   [Test 2.1] Check iptables IPv6 drop rules: n/a (IPv6 disabled)";
    SKIP=1;
    TXT="IPv6 is disabled";   
  fi      
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 50: If a system has Internet facing services or is a virtualization 
#         host, a MAC solution must be used to restrict these services 
#         respectively guest VMs.
REQ_TXT="If a system has Internet facing services or is a virtualization\n   host, a MAC solution must be used to restrict these services\n   respectively guest VMs."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  ERR_MSG="Missing:";
  for CHK in ${!MAC_TOOLS}; do
    if [ "$($PACKAGE 2>/dev/null | grep -ow $CHK | wc -l)" -ne "0" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if MAC package ($CHK) is installed:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if MAC package ($CHK) is installed:\e[1;31m FAILED\e[0m (present)";
      ERR_MSG="$ERR_MSG $CHK,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done

  if [ "${!MAC_SOLUTION}" == "selinux" ]; then
    
    # Test 2/2 (SELinux)
    CHK=$(sestatus 2>/dev/null | grep -i "SELinux status" | grep -owi "enabled" | tr '[:lower:]' '[:upper:]')
    NUM=1
    if [ "$CHK" == "ENABLED" ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if SELinux is enabled:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if SELinux is enabled:\e[1;31m FAILED\e[0m (SELinux is disabled)";
      ERR_MSG="$ERR_MSG SELinux not running";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

  else
    echo -e "   [Test -.--] Check if SELinux is enabled: SKIPPED (SELinux not used)";
    let CNT_SKIP=$CNT_SKIP+1
  fi

  if [ "${!MAC_SOLUTION}" == "apparmor" ]; then
    
    # Test 2/2 (AppArmor)
    CHK=$(aa-status 2>/dev/null | grep -i "apparmor module is loaded")
    NUM=1
    if [ -n "$CHK" ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if AppArmor is enabled:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if AppArmor is enabled:\e[1;31m FAILED\e[0m (AppArmor is disabled)";
      ERR_MSG="$ERR_MSG AppArmor not running";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

  else
    echo -e "   [Test -.--] Check if AppArmor is enabled: SKIPPED (AppArmor not used)";
    let CNT_SKIP=$CNT_SKIP+1
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 51: If SELinux is used, it must not be disabled in bootloader 
#         configuration.
REQ_TXT="If SELinux is used, it must not be disabled in bootloader\n   configuration."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  if [ "${!MAC_SOLUTION}" == "selinux" ]; then
    # Test 1/2
    NUM=1
    CHK=$(grep -ow "selinux=0" ${!FILE_GRUB})

    if [ -z "$CHK" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if SELinux is not 0 in ${!FILE_GRUB}:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if SELinux is not 0 in ${!FILE_GRUB}:\e[1;31m FAILED\e[0m (entry found)";
      ERR_MSG="SELinux is disabled in ${!FILE_GRUB},";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 2/2
    NUM=1
    CHK=$(grep -ow "enforcing=0" ${!FILE_GRUB})

    if [ -z "$CHK" ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if enforcing is not 0 in ${!FILE_GRUB}:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if enforcing is not 0 in ${!FILE_GRUB}:\e[1;31m FAILED\e[0m (entry found)";
      ERR_MSG="$ERR_MSG SELinux enfocing is disabled in ${!FILE_GRUB}"
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  else
    echo -e "   [Test -.--] Check if SELinux is enabled grub config: SKIPPED (SELinux not used)";
    SKIP=1;
    TXT="SELinux is not used with used Linux";
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 52: If SELinux is used, it must be run in "enforcing" mode to actually 
#         enforce policy.
REQ_TXT="If SELinux is used, it must be run in 'enforcing' mode to actually\n   enforce policy."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  if [ "${!MAC_SOLUTION}" == "selinux" ]; then
    # Test 1/2
    NUM=1
    FILE="$FILE_SELINUX"
    CHK=$(grep -ow "SELINUX=enforcing" $FILE)
    
    if [ -n "$CHK" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if enforcing is set in file '"$FILE"' for SELinux:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if enforcing is set in file '"$FILE"' for SELinux:\e[1;31m FAILED\e[0m (no config found)";
      ERR_MSG="enforcing not enabled in $FILE,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 2/2
    NUM=1
    CHK=$(sestatus 2>/dev/null | grep -i "Current mode" | grep -owi "enforcing" | tr '[:lower:]' '[:upper:]')

    if [ "$CHK" == "ENFORCING" ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if enforcing is activated for SELinux:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if enforcing is activated for SELinux:\e[1;31m FAILED\e[0m (not enforced)";
      ERR_MSG="$ERR_MSG SELinux not enforced ";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  else
    echo -e "   [Test -.--] Check if enforcing is activated for SELinux: SKIPPED (SELinux not used)";
    SKIP=1;
    ERR_MSG="SELinux is not used with used Linux";
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 53: If SELinux is used, the policy must be configured.
REQ_TXT="If SELinux is used, the policy must be configured."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  if [ "${!MAC_SOLUTION}" == "selinux" ]; then
    FILE="$FILE_SELINUX"
    # Test 1/2
    NUM=1
    CHK=$(grep -ow "SELINUXTYPE=targeted" $FILE)

    if [ -n "$CHK" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if targeted is set in file $FILE:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if targeted is set in file $FILE:\e[1;31m FAILED\e[0m (no config found)";
      ERR_MSG="target not set in file $FILE,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 2/2
    NUM=1
    CHK=$(sestatus 2>/dev/null | grep -i "Loaded policy name" | grep -owi "targeted" | tr '[:lower:]' '[:upper:]')

    if [ "$CHK" == "TARGETED" ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if SELinux is set to targeted:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if SELinux is set to targeted:\e[1;31m FAILED\e[0m (not activated)";
      ERR_MSG="$ERR_MSG targeted not set";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  else
    echo -e "   [Test -.--] Check if targeted is is set for SELinux: SKIPPED (SELinux not used)";
    SKIP=1;
    ERR_MSG="SELinux is not used with used Linux";
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 54: If SELinux is used, SETroubleshoot and MCS Translation Service 
#         must not be installed.
REQ_TXT="If SELinux is used, SETroubleshoot and MCS Translation Service\n   must not be installed."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  if [ "${!MAC_SOLUTION}" == "selinux" ]; then
    NUM=1
    for CHK in $SELINUX_SOFTWARE; do
      if [ "$($PACKAGE 2>/dev/null | grep -ow $CHK | wc -l)" -ne "0" ]; then
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if $CHK is not installed:\e[1;31m FAILED\e[0m (present)";
        ERR_MSG="$ERR_MSG $CHK is insatalled, ";
        let FAIL=$FAIL+1;
        ERR=1;
      else
        let PASS=$PASS+1;
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if $CHK is not installed:\e[1;32m PASSED\e[0m";
      fi
    done
  else
    echo -e "   [Test -.--] Check if tool for SELinux are not installed: SKIPPED (SELinux not used)";
    SKIP=1;
    ERR_MSG="SELinux is not used with used Linux";
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 55: If AppArmor is used, it must not be disabled in bootloader 
#         configuration.
REQ_TXT="If AppArmor is used, it must not be disabled in bootloader\n   configuration."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  if [ "${!MAC_SOLUTION}" == "apparmor" ]; then
    # Test 1/1
    NUM=1
    CHK=$(grep -ow "apparmor=0" ${!FILE_GRUB})

    if [ -z "$CHK" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if AppArmor is enabled grub config ${!FILE_GRUB}:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if AppArmor is enabled grub config ${!FILE_GRUB}:\e[1;31m FAILED\e[0m (no config found)";
      ERR_MSG="AppArmor is not disabled in ${!FILE_GRUB}";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  else
    echo -e "   [Test -.--] Check if AppArmor is enabled grub config: SKIPPED (AppArmor not used)";
    SKIP=1;
    ERR_MSG="AppArmor is not used";
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  ERR_MSG="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 56: If AppArmor is used, its state must be enforced.
REQ_TXT="If AppArmor is used, its state must be enforced."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  if [ "${!MAC_SOLUTION}" == "apparmor" ]; then
    # Test 1/1
    NUM=1
    CHK="$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}')"

    if [ $CHK -gt 0 ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if enforcing is activated for AppArmor:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if enforcing is activated for AppArmor:\e[1;31m FAILED\e[0m (not activated)";
      ERR_MSG="AppArmor is not enforced";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  else
    echo -e "   [Test -.--] Check if enforcing is activated for AppArmor: SKIPPED (AppArmor not used)";
    SKIP=1;
    ERR_MSG="AppArmor is not used";
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 57: No legacy + entries must exist in files passwd, shadows and group.
REQ_TXT="No legacy + entries must exist in files passwd, shadows and group."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  FILE_1="/etc/passwd"
  FILE_2="/etc/shadow"
  FILE_3="/etc/group"
  CNT=1
  FILE=FILE_$CNT

  # Test 1/1
  NUM=1
  while [ $CNT -lt 4 ]; do
    CHK_FILE="$(awk -F":" '($1 == "+") {print $1}' ${!FILE} | wc -l)"  
    if [ $CHK_FILE -eq 0 ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check file (${!FILE}) legacy + entries:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check file (${!FILE}) legacy + entries:\e[1;31m FAILED\e[0m (entries found)"
      ERR_MSG="$ERR_MSG entry in file ${!FILE} found,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
    let CNT++
    FILE=FILE_$CNT;
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 58: A user's home directory must be owned by the user and have mode 
#         750 or more restrictive.
REQ_TXT="A user's home directory must be owned by the user and have mode\n   750 or more restrictive."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  NUM1=1
  NUM2=1
  NUM3=1
  CHK_HOME="$(ls /home/)"
  PRIV=750
  ERR_MSG="Wrong setting(s) for home dir:";
  
  for CHK in $CHK_HOME; do

    # Test 1/3
    CHK_USER="$(stat -c %U /home/$CHK)"
    if [ "$CHK_USER" == "$CHK" ]; then
      echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check file ($CHK) for correct user setting:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check file ($CHK) for correct user setting:\e[1;31m FAILED\e[0m (wrong user $CHK_USER)"
      ERR_MSG="$ERR_MSG $CHK user $CHK_USER,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 2/3
    CHK_GRP="$(stat -c %G /home/$CHK)"
    if [ "$CHK_GRP" == "$CHK" ]; then
      echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check file ($CHK) for correct group setting:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check file ($CHK) for correct group setting:\e[1;31m FAILED\e[0m (wrong group $CHK_GRP)"
      ERR_MSG="$ERR_MSG $CHK group $CHK_GRP,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 3/3
    CHK_PRIV=$(stat -c %a /home/$CHK)
    if [ $CHK_PRIV -le $PRIV ]; then
      echo -e "   [Test 3.$(add_zero $NUM3)$(((NUM3++)))] Check file ($CHK) for correct privileges ($PRIV):\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 3.$(add_zero $NUM3)$(((NUM3++)))] Check file ($CHK) for correct privileges ($PRIV):\e[1;31m FAILED\e[0m (wrong privileges $CHK_PRIV)"
      ERR_MSG="$ERR_MSG $CHK mode $CHK_PRIV,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 59: Default group for the root account must be GID 0.
REQ_TXT="Default group for the root account must be GID 0."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  NUM=1
  CHK_GID="$(awk -F':' '{if ($1 == "root") print $4}' /etc/passwd)"
  if [ "$CHK_GID" == "0" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if group for root is GID 0:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if group for root is GID 0:\e[1;31m FAILED\e[0m (wrong GID $CHK_GID)"
    ERR_MSG="wrong GID $CHK_GID";
    let FAIL=$FAIL+1;
    ERR=1;
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 60: Root must be the only UID 0 account.
REQ_TXT="Root must be the only UID 0 account."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  NUM=1
  CHK_UID="$(awk -F':' '{ if ( $1 != "root" && $3 == 0 ) print $1 }' /etc/passwd)"

  if [ -z "$CHK_UID" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if root is the only account with UID 0:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    ERR_MSG="user(s) with UID 0:";
    for CHK in $CHK_UID; do  
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if root is the only account with UID 0:\e[1;31m FAILED\e[0m ($CHK has UID 0)"
      ERR_MSG="$ERR_MSG $CHK,";
      let FAIL=$FAIL+1;
      ERR=1;
    done
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 61: All groups in /etc/passwd must exist in /etc/group.
REQ_TXT="All groups in /etc/passwd must exist in /etc/group."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  NUM=1
  ERR_MSG="group(s) not exist in /etc/group:";
  SEARCH_GROUPS="$(awk -F':' '{print $4}' /etc/passwd | sort -u)"

  for CHK in $SEARCH_GROUPS; do
    CHK_GROUP="$(awk -v var=$CHK -F':' '{if ($3 == var) print $3}' /etc/group | wc -l)"
    if [ $CHK_GROUP -eq 1 ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if group from /etc/passwd ($CHK) exists in /etc/group:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if group from /etc/passwd ($CHK) exists in /etc/group:\e[1;31m FAILED\e[0m (group not found)"
      ERR_MSG="$ERR_MSG $CHK";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 62: No duplicate UIDs and GIDs must exist.
REQ_TXT="No duplicate UIDs and GIDs must exist."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  SEARCH_UIDS="$(awk -F':' '{print $3}' /etc/passwd)"
  ERR_MSG="multiple UID:"; 
  for CHK in $SEARCH_UIDS; do
    CHK_UID="$(awk -F':' '{if ($3 == '$CHK') print $3}' /etc/passwd | wc -l)"
    if [ $CHK_UID -eq 1 ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check in /etc/passwd if UID $CHK exists more than once:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check in /etc/passwd if UID $CHK exists more than once:\e[1;31m FAILED\e[0m (found duplicates)"
      ERR_MSG="$ERR_MSG $CHK,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done

  # Test 2/2
  NUM=1
  SEARCH_GIDS="$(awk -F':' '{print $3}' /etc/group)"
  ERR_MSG="$ERR_MSG multiple GID:"; 
  for CHK in $SEARCH_GIDS; do
    CHK_GID="$(awk -F':' '{if ($3 == '$CHK') print $3}' /etc/group | wc -l)"
    if [ $CHK_GID -eq 1 ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check in /etc/group if GID $CHK exists more than once:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check in /etc/group if GID $CHK exists more than once:\e[1;31m FAILED\e[0m (found duplicate)"
      ERR_MSG="$ERR_MSG $CHK,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 63: No duplicate user and group names must exist.
REQ_TXT="No duplicate user and group names must exist."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  ERR_MSG="duplicate users(s) exist:";
  SEARCH_USERS="$(awk -F':' '{print $1}' /etc/passwd)"
  for CHK in $SEARCH_USERS; do
    CHK_USER="$(awk -v chk="$CHK" -F':' '{if ($1 == chk) print $1}' /etc/passwd | wc -l)"
    if [ $CHK_USER -eq 1 ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check in /etc/passwd if user $CHK exists more than once:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))]  Check in /etc/passwd if user $CHK exists more than once:\e[1;31m FAILED\e[0m (found duplicate)"
      ERR_MSG="$ERR_MSG $CHK";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done

  # Test 2/2
  NUM=1
  ERR_MSG="$ERR_MSG duplicate group(s) exist:";
  SEARCH_GROUPS="$(awk -F':' '{print $1}' /etc/group)"
  for CHK in $SEARCH_GROUPS; do
    CHK_GROUP="$(awk -v chk="$CHK" -F':' '{if ($1 == chk) print $1}' /etc/group | wc -l)"
    if [ $CHK_GROUP -eq 1 ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check in /etc/group if group $CHK exists more than once:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check in /etc/group if group $CHK exists more than once:\e[1;31m FAILED\e[0m (found duplicate)"
      ERR_MSG="$ERR_MSG $CHK";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 64: The shadow group must be empty (only Debian-based Linux distributions).
REQ_TXT="The shadow group must be empty (only Debian-based Linux distributions)."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  if [ "$OS" == "ubuntu" ] ; then
    # Test 1/2
    NUM=1
    CHK_SHADOW="$(awk -F':' '{if ($1 == "shadow") print $4}' /etc/group)"
    if [ "$CHK_SHADOW" == "" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if shadow group in /etc/group is empty:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if shadow group in /etc/group is empty:\e[1;31m FAILED\e[0m (group has users)"
      ERR_MSG="shadow group is not empty,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 2/2
    NUM=1
    CHK_GID="$(awk -F':' '{if ($1 == "shadow") print $3}' /etc/group)"
    CHK_PASSWD="$(awk -v chk="CHK_GID" -F':' '{ if ($4 == chk) print $4}' /etc/passwd | wc -l)"
    if [ $CHK_PASSWD -eq 0 ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check /etc/passwd if user is member in shadow group:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check /etc/passwd if user is member in shadow group:\e[1;31m FAILED\e[0m (user with group shadow found)"
      ERR_MSG="$ERR_MSG found user(s) with group shadow"
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  else
    echo -e "   [Test -.--] Check /etc/passwd if user is member in shadow group: n/a (only Ubuntu)";
    SKIP=1;
    ERR_MSG="Only applicable for Ubuntu";
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 65: No files and directories without assigned user or group must exist.
REQ_TXT="No files and directories without assigned user or group must exist."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  ERR_MSG="dir/file without user:";
  SEARCH_FILES="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)"
  if [ -z "$SEARCH_FILES" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if directories/files without assigned user exist:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    for CHK in $SEARCH_FILES; do
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if directories/files without assigned user exist:\e[1;31m FAILED\e[0m (found $CHK)"
      ERR_MSG="$ERR_MSG $CHK,"
      let FAIL=$FAIL+1;
      ERR=1;
    done
  fi

  # Test 2/2
  NUM=1
  ERR_MSG="$ERR_MSG without group:";
  SEARCH_DIRS="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup)"
  if [ -z "$SEARCH_DIRS" ]; then
    echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if directories/files without assigned group exist:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    for CHK in $SEARCH_DIRS; do
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if directories/files without assigned group exist:\e[1;31m FAILED\e[0m (found $CHK)"
      ERR_MSG="$ERR_MSG $CHK,"
      let FAIL=$FAIL+1;
      ERR=1;
    done
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 66: Permissions of security relevant configuration files must have 
#         the distribution default values or more restrictive.
REQ_TXT="Permissions of security relevant configuration files must have\n   the distribution default values or more restrictive."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  if [ "$OS" == "ubuntu" ] ; then
  OS_NEW="$(echo $OS | tr '[:lower:]' '[:upper:]')"
  SYSOS=$OS_NEW$MAJOR_VERSION
  else
  SYSOS=$OS_MAIN_DISTRO
  fi

  NUM1=1
  NUM2=1
  NUM3=1
  FILE_1="/etc/passwd"
  FILE_2="/etc/passwd"
  FILE_3="/etc/shadow"
  FILE_4="/etc/shadow-"
  FILE_5="/etc/group"
  FILE_6="/etc/group-"
  FILE_7="${!FILE_GRUB}"
  FILE_8="/etc/sysctl.conf"
  FILE_9="/etc/ssh/sshd_config"
  FILE_10="/etc/gshadow"  # not used with Suse
  FILE_11="/etc/gshadow-" # not used with Suse
  if [ "$OS_MAIN_DISTRO" == "SUSE" ]; then CNT_TOTAL=9; else CNT_TOTAL=11; fi

  CNT=1
  FILE=FILE_$CNT
  FILE_SET=FILE_SET_$SYSOS$CNT
  ERR_MSG="Wrong user/group/mode:";

  while [ $CNT -le $CNT_TOTAL ]; do
    PRIV=$(echo ${!FILE_SET} | awk '{print $1}')
    USER="$(echo ${!FILE_SET} | awk '{print $2}')"
    GROUP="$(echo ${!FILE_SET} | awk '{print $3}')"

    # Test 1/3
    CHK_USER="$(stat -c %U ${!FILE})"
    if [ "$CHK_USER" == "$USER" ]; then
      echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check file (${!FILE}) for correct user $USER:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM1)$(((NUM1++)))] Check file (${!FILE}) for correct user $USER:\e[1;31m FAILED\e[0m (wrong user $CHK_USER)"
      ERR_MSG="$ERR_MSG ${!FILE}:$CHK_USER/";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 2/3
    CHK_GRP="$(stat -c %G ${!FILE})"
    if [ "$CHK_GRP" == "$GROUP" ]; then
      echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check file (${!FILE}) for correct group $GROUP:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM2)$(((NUM2++)))] Check file (${!FILE}) for correct group $GROUP:\e[1;31m FAILED\e[0m (wrong group $CHK_GRP)"
      ERR_MSG="$ERR_MSG$CHK_GRP/";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 3/3
    CHK_PRIV=$(stat -c %a ${!FILE})
    if [ $CHK_PRIV -le $PRIV ]; then
      echo -e "   [Test 3.$(add_zero $NUM3)$(((NUM3++)))] Check file (${!FILE}) for correct privileges $PRIV:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 3.$(add_zero $NUM3)$(((NUM3++)))] Check file (${!FILE}) for correct privileges $PRIV:\e[1;31m FAILED\e[0m (wrong privledges $CHK_PRIV)"
      ERR_MSG="$ERR_MSG$CHK_PRIV,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
    
    let CNT++
    FILE=FILE_$CNT;
    FILE_SET=FILE_SET_$SYSOS$CNT;
  done
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# -----------------------------------------------------------------------------
# End of script
# -----------------------------------------------------------------------------

echo -e "\n... Testing finished\n"
