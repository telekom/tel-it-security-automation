#!/bin/bash

# tel-it-security-automation :- Ansible roles for automated security hardening.  
# Copyright (c) 2019 Markus Schumburg, [...] Deutsche Telekom AG 
# contact: devsecops@telekom.de 
# This file is distributed under the conditions of the Apache-2.0 license. 
# For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.

# -----------------------------------------------------------------------------
# Deutsche Telekom IT GmbH (DevSecOps Team)
# Script for Compliance Check - Linux OS for Servers (3.65)
# Version: 0.9.1
# Date: 29-01-20 
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Requirement Configuration
# -----------------------------------------------------------------------------

# Use the following variables (`REQ#`) to enable (TRUE) or disable (FALSE) 
# testing for security requirements. If a requirement is set to disabled it 
# will marked as 'Not Applicable' in Statement of Compliance list. In this 
# case a text with reason can be set with variable `REQ#_TXT`.

REQ01="TRUE"; REQ01_TXT=""
REQ02="TRUE"; REQ02_TXT=""
REQ03="TRUE"; REQ03_TXT=""
REQ04="TRUE"; REQ04_TXT=""
REQ05="TRUE"; REQ05_TXT=""
REQ06="TRUE"; REQ06_TXT=""
REQ07="TRUE"; REQ07_TXT=""
REQ08="TRUE"; REQ08_TXT=""
REQ09="TRUE"; REQ09_TXT=""

REQ10="TRUE"; REQ10_TXT=""
REQ11="TRUE"; REQ11_TXT=""
REQ12="TRUE"; REQ12_TXT=""
REQ13="TRUE"; REQ13_TXT=""
REQ14="TRUE"; REQ14_TXT=""
REQ15="TRUE"; REQ15_TXT=""
REQ16="TRUE"; REQ16_TXT=""
REQ17="TRUE"; REQ17_TXT=""
REQ18="TRUE"; REQ18_TXT=""
REQ19="TRUE"; REQ19_TXT=""

REQ20="TRUE"; REQ20_TXT=""
REQ21="TRUE"; REQ21_TXT=""
REQ22="TRUE"; REQ22_TXT=""
REQ23="TRUE"; REQ23_TXT=""
REQ24="TRUE"; REQ24_TXT=""
REQ25="TRUE"; REQ25_TXT=""
REQ26="TRUE"; REQ26_TXT=""
REQ27="TRUE"; REQ27_TXT=""
REQ28="TRUE"; REQ28_TXT=""
REQ29="TRUE"; REQ29_TXT=""

REQ30="TRUE"; REQ30_TXT=""
REQ31="TRUE"; REQ31_TXT=""
REQ32="TRUE"; REQ32_TXT=""
REQ33="TRUE"; REQ33_TXT=""
REQ34="TRUE"; REQ34_TXT=""
REQ35="TRUE"; REQ35_TXT=""
REQ36="TRUE"; REQ36_TXT=""
REQ37="TRUE"; REQ37_TXT=""
REQ38="TRUE"; REQ38_TXT=""
REQ39="TRUE"; REQ39_TXT=""

REQ40="TRUE"; REQ40_TXT=""
REQ41="TRUE"; REQ41_TXT=""
REQ42="TRUE"; REQ42_TXT=""
REQ43="TRUE"; REQ43_TXT=""
REQ44="TRUE"; REQ44_TXT=""
REQ45="TRUE"; REQ45_TXT=""
REQ46="TRUE"; REQ46_TXT=""
REQ47="TRUE"; REQ47_TXT=""
REQ48="TRUE"; REQ48_TXT=""
REQ49="TRUE"; REQ49_TXT=""

REQ50="TRUE"; REQ50_TXT=""
REQ51="TRUE"; REQ51_TXT=""
REQ52="TRUE"; REQ52_TXT=""
REQ53="TRUE"; REQ53_TXT=""
REQ54="TRUE"; REQ54_TXT=""
REQ55="TRUE"; REQ55_TXT=""
REQ56="TRUE"; REQ56_TXT=""
REQ57="TRUE"; REQ57_TXT=""
REQ58="TRUE"; REQ58_TXT=""
REQ59="TRUE"; REQ59_TXT=""

REQ60="TRUE"; REQ60_TXT=""
REQ61="TRUE"; REQ61_TXT=""
REQ62="TRUE"; REQ62_TXT=""
REQ63="TRUE"; REQ63_TXT=""
REQ64="TRUE"; REQ64_TXT=""
REQ65="TRUE"; REQ65_TXT=""
REQ66="TRUE"; REQ66_TXT=""

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
TCP_PORTS="22"
UDP_PORTS="68 123"
FIREWALL_SOLUTIONS="iptables nftables"
UBUNTU_IPTABLES_TOOLS="iptables-persistent"
REDHAT_IPTABLES_TOOLS="iptables-services"
CLIENTS="rsh-redone-client rsh-client talk telnet ldap-utilsi \
inetutils-telnet rsh ypbind"
SERVERS="openbsd-inetd inetutils-inetd xinetd xserver-xorg-core vsftpd \
nfs-kernel-server ftpd dovecot-core dovecot-pop3d dovecot-imapd nis \
isc-dhcp-server avahi-daemon snmpd avahi telnet-server talk-server \
tftp-server rsh-server yp-tools inetd atftp yast2-tftp-server avahi-dnsconfd \
rsh-server inetutils-telnetd friendly-recovery avahi-dnsconfd avahi-ui-utils \
tftpd-hpa iscsi.service"
PARTITIONS="/tmp /var" # add more if needed: /var/tmp, /var/log instead of /var
UMASK="027"
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
# Sysctl (VARIABLE="<sysctl-parameter> <value>")
SUID_DUMPABLE="fs.suid_dumpable 0"
RANDOM_VA_SPACE="kernel.randomize_va_space 2"
# IPv4 Stack Configuration
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
# IPv6 Stack Configuration
IPV6_1="net.ipv6.conf.all.disable_ipv6 0"
IPV6_2="net.ipv6.conf.default.disable_ipv6 0"
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
ALLOWED_USERS="devsecops ec2-user ubuntu"
# LogRotate
LOG_ROTATE_TIME="weekly"
LOG_ROTATE_COUNT="4"
LOG_ROTATE_MAXSIZE="10M"
TIMEZONE="Europe/Berlin"
MAX_LOG_FILE="10"
MAX_NUM_LOGS="5"
MAX_LOG_FILE_ACTION="ROTATE"
# Logging with Auditd 
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
ACC_GRP_MGMT_EVENTS_1="-w /etc/passwd -p wa -k identity"
ACC_GRP_MGMT_EVENTS_2="-w /etc/group -p wa -k identity"
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
SYSLOG_TYPE="rsyslog" # syslog-ng not supported in this version
# Pluggable Authentication Module (PAM)
PAM_FILES_REDHAT="password-auth system-auth"
PAM_FILES_SUSE="common-password"
PAM_FILES_DEBIAN="common-password"
PAM_ROUNDS="640000"
PAM_ENRYPT_METHOD="sha512"
PAM_PASSWORD_LENGTH="12"
PAM_CHAR_CLASSES="3"
PAM_FAILED_LOGIN_ATTEMPS="5"
PAM_UNLOCK_TIME="600"
# Mandatory Access Control (MAC)
MAC_TOOLS_REDHAT="libselinux"
MAC_TOOLS_SUSE="libapparmor1 apparmor-profiles apparmor-utils apparmor-parser \
yast2-apparmor apparmor-docs audit"
MAC_TOOLS_DEBIAN="apparmor apparmor-utils"
SELINUX_SOFTWARE="setroubleshoot mcstrans"
FILE_SELINUX="/etc/selinux/config"
FILE_APPARMOR="/etc/apparmor.d/*"
# System Files (default user, group & priviledges)
# /etc/passwd
FILE_SET_REDHAT1="644 root root"
FILE_SET_SUSE1="644 root root"
FILE_SET_UBUNTU161="644 root root"
FILE_SET_UBUNTU181="644 root root"
# /etc/passwd-
FILE_SET_REDHAT2="644 root root"
FILE_SET_SUSE2="644 root root"
FILE_SET_UBUNTU162="644 root root"
FILE_SET_UBUNTU182="644 root root"
# /etc/shadow
FILE_SET_REDHAT3="0 root root"
FILE_SET_SUSE3="640 root shadow"
FILE_SET_UBUNTU163="640 root shadow"
FILE_SET_UBUNTU183="640 root shadow"
# /etc/shadow-
FILE_SET_REDHAT4="0 root root"
FILE_SET_SUSE4="640 root shadow"
FILE_SET_UBUNTU164="600 root root"
FILE_SET_UBUNTU184="640 root shadow"
# /etc/group
FILE_SET_REDHAT5="644 root root"
FILE_SET_SUSE5="644 root root"
FILE_SET_UBUNTU165="644 root root"
FILE_SET_UBUNTU185="644 root root"
# /etc/group-
FILE_SET_REDHAT6="644 root root"
FILE_SET_SUSE6="644 root root"
FILE_SET_UBUNTU166="600 root root"
FILE_SET_UBUNTU186="644 root root"
# grub.cfg
FILE_SET_REDHAT7="644 root root"
FILE_SET_SUSE7="600 root root"
FILE_SET_UBUNTU167="444 root root"
FILE_SET_UBUNTU187="444 root root"
# /etc/sysctl.conf
FILE_SET_REDHAT8="644 root root"
FILE_SET_SUSE8="644 root root"
FILE_SET_UBUNTU168="644 root root"
FILE_SET_UBUNTU188="644 root root"
# /etc/ssh/sshd_config
FILE_SET_REDHAT9="600 root root"
FILE_SET_SUSE9="640 root root"
FILE_SET_UBUNTU169="644 root root"
FILE_SET_UBUNTU189="644 root root"
# /etc/gshadow
FILE_SET_REDHAT10="0 root root"
FILE_SET_UBUNTU1610="640 root shadow"
FILE_SET_UBUNTU1810="640 root shadow"
# /etc/gshadow-
FILE_SET_REDHAT11="0 root root"
FILE_SET_UBUNTU1611="600 root root"
FILE_SET_UBUNTU1811="640 root shadow"

# -----------------------------------------------------------------------------
# Output File Configuration
# -----------------------------------------------------------------------------
DAY=`date +"%d%m%y"`
OS=$(awk -F\= '/^ID=/ {print $2}' /etc/os-release | tr -d '"')
OS_VERSION=$(awk -F\" '/^VERSION_ID=/ {print $2}' /etc/os-release)
OUT_FILE="compliance-$OS$OS_VERSION-$DAY.log"
OUT_CSV="compliance-$OS$OS_VERSION-$DAY.csv"
exec > >(tee $OUT_FILE) 2>&1
exec 3>$OUT_CSV
echo "ReqNo.;Requirement;Statement of Compliance">&3

# -----------------------------------------------------------------------------
# Pre-Checks
# -----------------------------------------------------------------------------

# Function: Output for Pre-Checks
write_error () {
  if [ "$1" != "1" ]; then
    echo -e "[Pre-Check] $2:\e[1;32m PASSED\e[0m";
  else
    echo -e "[Pre-Check] $2:\e[1;31m FAILED\e[0m ($3)";
    echo "-------------------------------------------------------------------------------"
    echo -e " \e[1;31m All tests skipped! \e[0m"
    exit 1
  fi
}

TXT="Check running Linux version is supported"
if [ -f /etc/os-release ]; then
   # Linux OS IDs from file /etc/os-release:
   #   - Amazon Linux = amzn
   #   - RHEL = rhel
   #   - CentOS = centos
   #   - SLES = sles
   #   - Ubuntu = ubuntu
   OS=$(awk -F\= '/^ID=/ {print $2}' /etc/os-release | tr -d '"')
   # Full Linux OS name
   OS_NAME=$(awk -F\" '/^NAME=/ {print $2}' /etc/os-release)
   # Linux version (e.g. Ubuntu 18.04)
   OS_VERSION=$(awk -F\" '/^VERSION_ID=/ {print $2}' /etc/os-release)
   # Major version of Linux (e.g. 18 for Ubuntu 18.04)
   MAJOR_VERSION=$(echo $OS_VERSION | awk -F\. '{print $1}')
   if [ "$OS" == "amzn" ] || [ "$OS" == "rhel" ] || [ "$OS" == "centos" ]; then
     OS_MAIN_DISTRO="REDHAT";
     PACKAGE="rpm -qa";
     NOLOGIN_PATH="/sbin/nologin";
     AUDIT_DAEMON="audit";
     RSYSLOG_CONF="/etc/rsyslog.conf";
     FILE_GRUB="/boot/grub2/grub.cfg";
     MAC_SOLUTION="selinux";
     ERR=0;
   elif [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ]; then
     OS_MAIN_DISTRO="DEBIAN";
     PACKAGE="apt list --installed";
     # PACKAGE="dpkg -l";
     NOLOGIN_PATH="/usr/sbin/nologin";
     AUDIT_DAEMON="auditd";
     RSYSLOG_CONF="/etc/rsyslog.d/50-default.conf";
     FILE_GRUB="/boot/grub/grub.cfg";
     MAC_SOLUTION="apparmor";
     ERR=0;
   elif [ "$OS" == "sles" ]; then
     OS_MAIN_DISTRO="SUSE";
     PACKAGE="rpm -qa";
     NOLOGIN_PATH="/sbin/nologin";
     AUDIT_DAEMON="audit";
     RSYSLOG_CONF="/etc/rsyslog.d/remote.conf";
     FILE_GRUB="/boot/grub2/grub.cfg";
     MAC_SOLUTION="apparmor";
     ERR=0;
   else
     ERR=1;
     OS_NAME=$(awk -F\" '/^VERSION=/ {print $2}' /etc/os-release)
     ERR_TXT="Linux $OS_NAME not supported"
   fi
else
  ERR=1;
  ERR_TXT="Linux not identified";
fi

echo "-------------------------------------------------------------------------------"
echo " Telekom IT/DevSecOps - Compliance Check - Linux OS (3.65)"
echo "-------------------------------------------------------------------------------"
echo "   Host: "$HOSTNAME
echo "   Date: "$(date +"%d-%m-%y")
echo "   OS: "$(awk -F\" '/^NAME=/ {print $2}' /etc/os-release)
echo "   Version: "$(awk -F\" '/^VERSION=/ {print $2}' /etc/os-release)
echo -e "-------------------------------------------------------------------------------\n"

write_error $ERR "$TXT" "$ERR_TXT"

# Check if script is started with root priviledges
TXT="Check if script is started with root priviledges"
if [ "$EUID" -ne 0 ]; then
  ERR=1;
  ERR_TXT="not root";
else
  ERR=0;
fi
write_error $ERR "$TXT" "$ERR_TXT"

if [ -z "$(ls -A /etc/sysctl.d/)" ]; then
  SYSCTL_CONF="/etc/sysctl.conf"
else
  SYSCTL_CONF="/etc/sysctl.conf /etc/sysctl.d/*"
fi

# -----------------------------------------------------------------------------
# Functions
# -----------------------------------------------------------------------------
write_to_soc () {
  COMMENT=" ";
  if [ -n "$3" ]; then COMMENT=$3; fi

  if [ $1 -eq 0 ]; then
    echo "Req $REQ_NR;$REQ_TXT;Compliant;">&3;
  else
    if [ $2 -ne 0 ]; then
      echo "Req $REQ_NR;$REQ_TXT;Partly Compliant;$COMMENT">&3;
    else
      echo "Req $REQ_NR;$REQ_TXT;Not Compliant;$COMMENT">&3;
    fi
  fi
}

config_sysctl () {
  SYSCTL=$(sysctl $1 | awk '{print $3}');

  # Test 1
  NUM=1
  if [ $SYSCTL -eq $2 ]; then
    let PASS=$PASS+1;
    echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if $1 is $2:\e[1;32m PASSED\e[0m";
  else
    ERR=1;
    let FAIL=$FAIL+1;
    echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if $1 is $2:\e[1;31m FAILED\e[0m (value: $SYSCTL)";
  fi

  # Test 2
  NUM=1
  CHK_FILE="$(grep -h "$1[ ]*=[ ]*$2" $SYSCTL_CONF | grep "^[[:blank:]]*[^#]" | tr -d ' ')"
  if [ $(echo $CHK_FILE | wc -l) -eq 0 ]; then
    ERR=1;
    let FAIL=$FAIL+1;
    echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check $1 is in config:\e[1;31m FAILED\e[0m (absent)";
  else
    for CHK in $CHK_FILE; do
      CHK_VALUE=$(echo $CHK | awk -F\= '{print $2}')
      if [ "$CHK_VALUE" == "$2" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check $1 is in config:\e[1;32m PASSED\e[0m";
      else
        let FAIL=$FAIL+1;
        ERR=1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check $1 is in config:\e[1;31m FAILED\e[0m (wrong value $CHK_VALUE in $CHK)";
      fi
    done
  fi
}

# -----------------------------------------------------------------------------
# Start Compliance Checks
# -----------------------------------------------------------------------------
REQ_NR=0
CNT_PASSED=0
CNT_ERRORS=0
CNT_SKIP=0
echo "-------------------------------------------------------------------------------"
echo " Start Testing ..."
echo "-------------------------------------------------------------------------------"

# Req 1: Unused services and protocols must be deactivated.
let "REQ_NR++";
REQ_TXT="Unused services and protocols must be deactivated."
FAIL=0
PASS=0

test_req01 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/2
    NUM=1
    CHK_TCP=$(ss -nlt 2>/dev/null | awk '($1 == "LISTEN" && $4 !~ /127\.0\.0\.[0-9]{1,4}/ && $4 !~ /\[?::[0-9]{1,4}\]?:/) {print $4}' | sed 's/.*://' | sort -nu)

    for CHK in $CHK_TCP; do
      if [ "$CHK" != "$(echo $TCP_PORTS | grep -ow "$CHK")" ]; then
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check open tcp ports:\e[1;31m FAILED\e[0m (found port $CHK)";
      else
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check open tcp ports:\e[1;32m PASSED\e[0m";
      fi
    done

    # Test 2/2
    NUM=1
    CHK_UDP=$(ss -nlu 2>/dev/null | awk '($1 == "UNCONN" && $4 !~ /127\.0\.0\.[0-9]{1,4}/ && $4 !~ /\[?::[0-9]{1,4}\]?:/) {print $4}' | sed 's/.*://' | sort -nu)

    for CHK in $CHK_UDP; do
      if [ "$CHK" != "$(echo $UDP_PORTS | grep -ow "$CHK")" ]; then
        if [ "$CHK" -gt "1024" ]; then
          CHK_RSYSLOG="$(ss -ulpn | grep $CHK | grep rsyslog | wc -l)"
          if [ "$CHK_RSYSLOG" -eq "0" ]; then
            echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check open udp ports:\e[1;31m FAILED\e[0m (found port $CHK)";
            let FAIL=$FAIL+1;
            ERR=1;
          else
            let PASS=$PASS+1;
            echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check open udp ports:\e[1;32m PASSED\e[0m";
          fi
        else
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check open udp ports:\e[1;31m FAILED\e[0m (found port $CHK)";
          let FAIL=$FAIL+1;
          ERR=1;
        fi
      else
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check open udp ports:\e[1;32m PASSED\e[0m";
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS
  
  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req01 $REQ01 "$REQ01_TXT"

# Req 2: The reachability of services must be restricted.
let "REQ_NR++"
REQ_TXT="The reachability of services must be restricted."
FAIL=0
PASS=0

test_req02 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/2
    NUM=1
    for CHK in $FIREWALL; do
      if [ "$($PACKAGE 2>/dev/null | grep -ow $CHK | wc -l)" -eq "0" ]; then
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check firewall solution ($CHK):\e[1;31m FAILED\e[0m (not present)";
      else
        let PASS=$PASS+1;
        ERR=0;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check firewall solution ($CHK):\e[1;32m PASSED\e[0m";
        break;
      fi
    done

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
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if iptable tools installed:\e[1;31m FAILED\e[0m (not present)";
    else
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if iptable tools installed:\e[1;32m PASSED\e[0m";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req02 $REQ02 "$REQ02_TXT"

# Req 3: Unused software must not be installed or must be uninstalled.
let "REQ_NR++"
REQ_TXT="Unused software must not be installed or must be uninstalled."
FAIL=0
PASS=0

test_req03 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/2
    NUM=1
    for CHK in $SERVERS; do
      if [ "$($PACKAGE 2>/dev/null | grep -ow $CHK | wc -l)" -ne "0" ]; then
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check unused server ($CHK):\e[1;31m FAILED\e[0m (present)";
      else
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check unused server ($CHK):\e[1;32m PASSED\e[0m";
      fi
    done

    # Test 2/2
    NUM=1
    for CHK in $CLIENTS; do
      if [ "$($PACKAGE 2>/dev/null | grep -ow $CHK | wc -l)" -ne "0" ]; then
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check unused client ($CHK):\e[1;31m FAILED\e[0m (present)";
      else
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check unused client ($CHK):\e[1;32m PASSED\e[0m";
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req03 $REQ03 "$REQ03_TXT"

# Req 4: Dedicated partitions must be used for growing content that can influence the availability of the system.
let "REQ_NR++"
REQ_TXT="Dedicated partitions must be used for growing content that can influence the availability of the system."
FAIL=0
PASS=0

test_req04 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    for CHK in $PARTITIONS; do
      if [ "$(grep -o $CHK /etc/fstab | sort -u | wc -l)" -eq "0" ]; then
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check needed partition ($CHK):\e[1;31m FAILED\e[0m (not found)";
      else
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check needed partition ($CHK):\e[1;32m PASSED\e[0m";
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req04 $REQ04 "$REQ04_TXT"

# Req 5: Parameters nodev, nosuid and noexec must be set for partitions where this is applicable.
let "REQ_NR++"
REQ_TXT="Parameters nodev, nosuid and noexec must be set for partitions where this is applicable."
FAIL=0
PASS=0

test_req05 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    for CHK in $PARTITIONS; do
      PART_SEC=""
      PARTITION=$(grep " $CHK" /etc/fstab 2>/dev/null)
      if [ "$CHK" == "/tmp" ]; then
        PART_SEC="nodev,nosuid";
      elif [ "$CHK" == "/var/tmp" ]; then
        PART_SEC="nodev,nosuid,noexec";
      elif [ "$CHK" == "/dev/shm" ]; then
        PART_SEC="nodev,nosuid,noexec";
      elif [ "$CHK" == "/home" ]; then
        PART_SEC="nodev";
      fi
      if [ ! -z "$PART_SEC" ]; then
        if [ "$(echo $PARTITION | grep -o $PART_SEC 2>/dev/null | wc -l)" -eq "0" ]; then
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check partition parameter ($CHK):\e[1;31m FAILED\e[0m (not found)";
        else
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check partition parameters ($CHK):\e[1;32m PASSED\e[0m";
        fi
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req05 $REQ05 "$REQ05_TXT"

# Req 6: Automounting must be disabled.
let "REQ_NR++"
REQ_TXT="Automounting must be disabled."
FAIL=0
PASS=0

test_req06 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    if [ "$($PACKAGE 2>/dev/null | grep -ow autofs | wc -l)" -ne "0" ]; then
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if autofs is installed:\e[1;31m FAILED\e[0m (present)";
    else
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if autofs is installed:\e[1;32m PASSED\e[0m";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req06 $REQ06 "$REQ06_TXT"

# Req 7: The use of at/cron must be restricted to authorized users.
let "REQ_NR++"
REQ_TXT="The use of at/cron must be restricted to authorized users."
FAIL=0
PASS=0

test_req07 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/3
    NUM=1
    for CHK in at cron; do
      if [ -f "/etc/$CHK.deny" ]; then
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check for $CHK.deny file:\e[1;31m FAILED\e[0m (present)";
      else
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check for $CHK.deny file:\e[1;32m PASSED\e[0m";
      fi
    done

    # Test 2/3
    NUM=1
    for CHK in at cron; do
      if [ -f "/etc/$CHK.allow" ]; then
        if [ "$(stat -L -c "%a %u %g" /etc/$CHK.allow | grep -o ".00 0 0")" != "" ]; then
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check for $CHK.allow file:\e[1;32m PASSED\e[0m";
        else
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check for $CHK.allow file:\e[1;31m FAILED\e[0m (wrong permissions)";
        fi
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check for $CHK.allow file:\e[1;31m FAILED\e[0m (absent)";
      fi
    done

    # Test 3/3
    NUM=1
    for CHK in at cron; do
      FILE="/etc/$CHK.allow"
      if [ -f "$FILE" ]; then
        if [ "$(grep 'root' $FILE)" != "root" ]; then
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check for root in $FILE file:\e[1;31m FAILED\e[0m (not found)";
        else
          if [ "$(cat $FILE | wc -l)" != "1" ]; then
            ERR=1;
            let FAIL=$FAIL+1;
            echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check for entries in $FILE file:\e[1;31m FAILED\e[0m (to many users)";
          else
            let PASS=$PASS+1;
            echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check for users in $CHK.allow file:\e[1;32m PASSED\e[0m";
          fi
        fi
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req07 $REQ07 "$REQ07_TXT"

# Req 8: Sticky bit must be set on all world-writable directories.
let "REQ_NR++"
REQ_TXT="Sticky bit must be set on all world-writable directories."
FAIL=0
PASS=0

test_req08 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    SRCH=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type d -perm -0002 \! -perm -1000 2>/dev/null)
    CHK=$(echo "$SRCH" | wc -w)

    if [ "$CHK" -eq "0" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check for world-writable directory:\e[1;32m PASSED\e[0m";
    else
        ERR=1;
        let FAIL=$FAIL+1;
        for DIR in $SRCH; do
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check for world-writable directory:\e[1;31m FAILED\e[0m (found $DIR)";
        done
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req08 $REQ08 "$REQ08_TXT"

# Req 9: No regular files that are world writable must exist.
let "REQ_NR++"
REQ_TXT="No regular files that are world writable must exist."
FAIL=0
PASS=0

test_req09 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    SRCH="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f -perm -0002 2>/dev/null)"
    # CHK="$(echo "$SRCH" | wc -l)"

    if [ -z "$SRCH" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check for world-writable files:\e[1;32m PASSED\e[0m";
    else
      ERR=1;
      let FAIL=$FAIL+1;
      for FILE in $SRCH; do
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check for world-writable files:\e[1;31m FAILED\e[0m (found $FILE)";
      done
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req09 $REQ09 "$REQ09_TXT"

# Req 10: Passwords must be protected with an appropriate hashing function.
let "REQ_NR++"
REQ_TXT="Passwords must be protected with an appropriate hashing function."
FAIL=0
PASS=0

test_req10 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    if [ "`grep -i "^ENCRYPT_METHOD SHA512" /etc/login.defs`" ] && \
      [ "`grep -i "^SHA_CRYPT_MIN_ROUNDS 640000" /etc/login.defs`" ] && \
      [ "`grep -i "^SHA_CRYPT_MAX_ROUNDS 640000" /etc/login.defs`" ]; then
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check password encryption:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
    else
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check password encryption:\e[1;31m FAILED\e[0m (wrong config)";
        let FAIL=$FAIL+1;
        ERR=1;
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req10 $REQ10 "$REQ10_TXT"

# Req 11: The default user umask must be 027 or more restrictive.
let "REQ_NR++"
REQ_TXT="The default user umask must be 027 or more restrictive."
FAIL=0
PASS=0

test_req11 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    if [ "$(grep -i "^UMASK $UMASK" /etc/login.defs)" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check umask:\e[1;32m PASSED\e[0m";
    else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check umask:\e[1;31m FAILED\e[0m (wrong umask $UMASK)";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req11 $REQ11 "$REQ11_TXT"

# Req 12: Not needed SUID and SGID bits must be removed from executables.
let "REQ_NR++"
REQ_TXT="Not needed SUID and SGID bits must be removed from executables."
FAIL=0
PASS=0

test_req12 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    CHK_FILES=$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -type f \( -perm -4000 -o -perm -2000 \) -print)

    for CHK in $CHK_FILES; do
      if [ "$CHK" != "$(echo $SUID_FILES | grep -ow "$CHK")" ]; then
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check file $CHK for not allowed SUID bit:\e[1;31m FAILED\e[0m (SUID set for $CHK)";
      else
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check file $CHK for not allowed SUID bit:\e[1;32m PASSED\e[0m";
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req12 $REQ12 "$REQ12_TXT"

# Req 13: Core dumps must be disabled.
let "REQ_NR++"
REQ_TXT="Core dumps must be disabled."
FAIL=0
PASS=0

test_req13 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/4 & 2/4
    PAR=$(echo $SUID_DUMPABLE | awk '{print $1}');
    VALUE=$(echo $SUID_DUMPABLE | awk '{print $2}');
    config_sysctl $PAR $VALUE

    # Test 3/4
    NUM=1
    DUMP="soft hard"

    for CHK in $DUMP; do
      if [ -z "$(ls -A /etc/security/limits.conf)" ]; then
        ERR=1;
        echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check if core dump is disaled:\e[1;31m FAILED\e[0m (config file not found)";
      else
        if [ $(grep -i "$CHK core 0" /etc/security/limits.conf | wc -l) -eq 1 ]; then
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check if core dump is disabled:\e[1;32m PASSED\e[0m";
        else
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check if core dump is disabled:\e[1;31m FAILED\e[0m ($CHK core)";
        fi
      fi
    done

    # Test 4/4
    NUM=1
    for CHK in S H; do
      if [ "$(ulimit -$CHK -c)" == "0" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 4.$(((NUM++)))] Check if ulimit is 0:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 4.$(((NUM++)))] Check if ulimit is 0:\e[1;31m FAILED\e[0m (ulimit not 0)";
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req13 $REQ13 "$REQ13_TXT"

# Req 14: Protection against buffer overflows must be enabled.
let "REQ_NR++"
REQ_TXT="Protection against buffer overflows must be enabled."
FAIL=0
PASS=0

test_req14 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/3 & 2/3
    PAR=$(echo $RANDOM_VA_SPACE | awk '{print $1}');
    VALUE=$(echo $RANDOM_VA_SPACE | awk '{print $2}');
    config_sysctl $PAR $VALUE

    # Test 3/3
    NUM=1
    CHK_NX=$(dmesg | awk -F' ' '{if ($3 == "NX") print $7}')

    if [ "$CHK_NX" == "active" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if NX/XD is enabled:\e[1;32m PASSED\e[0m";
    else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if NX/XD is enabled:\e[1;31m FAILED\e[0m ($CHK_NX)";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req14 $REQ14 "$REQ14_TXT"

# Req 15: IPv4 protocol stack must be securely configured.
let "REQ_NR++"
REQ_TXT="IPv4 protocol stack must be securely configured."
FAIL=0
PASS=0

test_req15 () {
  if [ "$1" == "TRUE" ]; then
    
    CNT=1
    IPV4=IPV4_$CNT

    while [ $CNT -lt 24 ]; do

      # Test 1/2 & 2/2
      PAR=$(echo ${!IPV4} | awk '{print $1}');
      VALUE=$(echo ${!IPV4} | awk '{print $2}');
      config_sysctl $PAR $VALUE
      let CNT++;
      IPV4=IPV4_$CNT;
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req15 $REQ15 "$REQ15_TXT"

# Req 16: IPv6 protocol stack must be securely configured.
let "REQ_NR++"
REQ_TXT="IPv6 protocol stack must be securely configured."
FAIL=0
PASS=0

test_req16 () {
  if [ "$1" == "TRUE" ]; then

    CNT=1
    IPV6=IPV6_$CNT

    if [ $(sysctl net.ipv6.conf.all.disable_ipv6 | awk '{print $3}') -eq 0 ] && \
      [ $(sysctl net.ipv6.conf.default.disable_ipv6 | awk '{print $3}') -eq 0 ]; then
      while [ $CNT -lt 23 ]; do
        # Test 1/2 & 2/2
        PAR=$(echo ${!IPV6} | awk '{print $1}');
        VALUE=$(echo ${!IPV6} | awk '{print $2}');
        config_sysctl $PAR $VALUE
        let CNT++;
        IPV6=IPV6_$CNT;
      done
      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS
    else
      echo -e "[Req-$REQ_NR: Test 2.1] Check IPv6 in config: n/a (disabled)";
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable">&3;
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req16 $REQ16 "$REQ16_TXT"

# Req 17: Emerged vulnerabilities in software and hardware of a system must be fixed or protected against misuse.
let "REQ_NR++"
REQ_TXT="Emerged vulnerabilities in software and hardware of a system must be fixed or protected against misuse."
FAIL=0
PASS=0

test_req17 () {
  if [ "$1" == "TRUE" ]; then

    UPDATE_ERR=0

    # Test 1/1
    NUM=1
    if [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ] ; then
      apt update &>/dev/null
      if [ $(apt list --upgradable 2>/dev/null | wc -l) -gt 1 ]; then UPDATE_ERR=1; fi
    elif [ "$OS" == "amzn" ] || [ "$OS" == "rhel" ] || [ "$OS" == "centos" ]; then
      if [ $(yum check-update 2>/dev/null | grep "updates$" | wc -l) -ne 0 ]; then UPDATE_ERR=1; fi
    elif [ "$OS" == "sles" ]; then
      zypper refresh -s &>/dev/null
      if [ $(zypper list-updates 2>/dev/null | grep "No updates found." | wc -l) -ne 1 ]; then UPDATE_ERR=1; fi
    fi

    if [ $UPDATE_ERR -eq 1 ]; then
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if system is up-to-date:\e[1;31m FAILED\e[0m (updates missing)";
    else
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if system is up-to-date:\e[1;32m PASSED\e[0m";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req17 $REQ17 "$REQ17_TXT"

# Req 18: GPG Check for repository server must be activated and corresponding keys for trustable repositories must be configured.
let "REQ_NR++"
REQ_TXT="GPG Check for repository server must be activated and corresponding keys for trustable repositories must be configured."
FAIL=0
PASS=0

test_req18 () {
  if [ "$1" == "TRUE" ]; then
    
    GPG_ERR=0

    # Test 1/1
    NUM=1
    if [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ] ; then
      if [ $(grep "trusted=yes" /etc/apt/sources.list | wc -l) -ne 0 ]; then GPG_ERR=1; fi
    elif [ "$OS" == "amzn" ] || [ "$OS" == "rhel" ] || [ "$OS" == "centos" ]; then
      if [ $(awk -F\= '/^gpgcheck=/ {print $2}' /etc/yum.conf) -ne 1 ]; then GPG_ERR=1; fi
    elif [ "$OS" == "sles" ]; then
      CHK=$(awk -F\= '/^gpgcheck=/ {print $2}' /etc/zypp/zypp.conf)
      CHK2=$(zypper repos -E | grep -i yes | awk -F'|' '{print $5}' | sort -u | wc -l)
      if [ -z $CHK ]; then
        if [ $CHK2 -ne 1 ]; then GPG_ERR=1; fi
      else
        if [ $CHK -ne 1 ]; then GPG_ERR=1; fi
      fi
    fi

    if [ $GPG_ERR -eq 1 ]; then
    #  ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if repos are trusted:\e[1;31m FAILED\e[0m (untrusted repo)";
    else
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if repos are trusted:\e[1;32m PASSED\e[0m";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req18 $REQ18 "$REQ18_TXT"

# Req 19: User accounts must be used that allow unambiguous identification of the user.
let "REQ_NR++"
REQ_TXT="User accounts must be used that allow unambiguous identification of the user."
FAIL=0
PASS=0

test_req19 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    ACCOUNTS=$(awk -v var="$NOLOGIN_PATH" -F':' '{ if ( $3 >= 1000 && $7 != var && $7 != "/bin/false") print $1 }' /etc/passwd)
    for USER in $ALLOWED_USERS; do
      ACCOUNTS=$(echo "$ACCOUNTS" | sed -e "s/$USER//g")
    done

    if [ -z "$ACCOUNTS" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check local user accounts:\e[1;32m PASSED\e[0m";
    else
      ERR=1;
      for FOUND_ACCOUNT in $ACCOUNTS; do
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check local user accounts:\e[1;31m FAILED\e[0m (found account $FOUND_ACCOUNT)"
      done
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req19 $REQ19 "$REQ19_TXT"

# Req 20: System accounts must be non-login.
let "REQ_NR++"
REQ_TXT="System accounts must be non-login."
FAIL=0
PASS=0

test_req20 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    CHK=$(awk -F':' '($1!="root" && $1!="sync" && $1!="shutdown" && $1!="halt" && $3<1000 && $7=="/bin/bash") {print $1}' /etc/passwd)

    if [ -z "$CHK" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check system accounts if non-login:\e[1;32m PASSED\e[0m";
    else
      ERR=1;
      for FOUND_ACCOUNT in $CHK; do
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check system accounts if non-login:\e[1;31m FAILED\e[0m (found account $FOUND_ACCOUNT)";
      done
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req20 $REQ20 "$REQ20_TXT"

# Req 21: User accounts must be protected against unauthorized use by at least one authentication attribute.
let "REQ_NR++"
REQ_TXT="User accounts must be protected against unauthorized use by at least one authentication attribute."
FAIL=0
PASS=0

test_req21 () {
  if [ "$1" == "TRUE" ]; then

    CHK=$(awk -F":" '($2 == "" && $2 != "!" && $2 !="*") {print $1}' /etc/shadow)

    if [ -z "$CHK" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check accounts in /etc/shadow:\e[1;32m PASSED\e[0m";
    else
      ERR=1;
      for FOUND_USER in $CHK; do 
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check accounts in /etc/shadow:\e[1;31m FAILED\e[0m ($FOUND_USER has no password)";
      done
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req21 $REQ21 "$REQ21_TXT"

# Req 22: User accounts with extensive rights must be protected with two authentication attributes.
let "REQ_NR++"
REQ_TXT="User accounts with extensive rights must be protected with two authentication attributes."
FAIL=0
PASS=0

test_req22 () {
  if [ "$1" == "TRUE" ]; then
    
    SSH_CONFIG="/etc/ssh/sshd_config"

    # Test 1/2
    PUB_KEY_AUTH=yes
    NUM=1
    if [ $(grep -i "^PubkeyAuthentication $PUB_KEY_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if SSH PubkeyAuthentication is $PUB_KEY_AUTH:\e[1;32m PASSED\e[0m";
    else
      let FAIL=$FAIL+1;
      ERR=1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if SSH PubkeyAuthentication is $PUB_KEY_AUTH:\e[1;31m FAILED\e[0m (disabled)";
    fi

    # Test 2/2
    NUM=1
    PASS_AUTH=no
    if [ $(grep -i "^PasswordAuthentication $PASS_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if SSH PasswordAuthentication is $PASS_AUTH:\e[1;32m PASSED\e[0m";
    else
      let FAIL=$FAIL+1;
      ERR=1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if SSH PasswordAuthentication is $PASS_AUTH:\e[1;31m FAILED\e[0m (enabled)";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL;
    let CNT_PASSED=$CNT_PASSED+$PASS;
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req22 $REQ22 "$REQ22_TXT"

# Req 23: The system must be connected to a central system for user administration.
let "REQ_NR++"
REQ_TXT="The system must be connected to a central system for user administration."
FAIL=0
PASS=0

test_req23 () {
  if [ "$1" == "TRUE" ]; then

    # Not implemented! Manual Check necessary!
    FAIL=1;
    SKIP=1;
    echo -e "[Req-$REQ_NR: Test 0.0] Check if system for central authentication is configured: SKIPPED (not implemented: Check manual!)"
    REMARK="Not implemented! Depends on your used solution (LDAP, Kerberos etc.)."

    let CNT_SKIP=$CNT_SKIP+$SKIP
    write_to_soc $FAIL $PASS "$REMARK"

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req23 $REQ23 "$REQ23_TXT"

# Req 24: Authentication must be used for single user mode.
let "REQ_NR++"
REQ_TXT="Authentication must be used for single user mode."
FAIL=0
PASS=0

test_req24 () {
  if [ "$1" == "TRUE" ]; then

    MODE_ERR=0

    # Test 1/1
    NUM=1
    if [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ] ; then
      CHK=$(awk -F":" '($1 == "root" && $2 == "[!*]") {print $1}' /etc/shadow)
      if [ -n  "$CHK" ]; then MODE_ERR=1; fi
    elif [ "$OS" == "amzn" ] || [ "$OS" == "rhel" ] || [ "$OS" == "centos" ] || [ "$OS" == "sles" ]; then
      CHK="ExecStart=-/bin/sh -c \"/usr/sbin/sulogin; /usr/bin/systemctl --fail --no-block default\""
      if [ "$CHK" != "`grep ^ExecStart= /usr/lib/systemd/system/rescue.service`" ] && \
        [ "$CHK" != "`grep ^ExecStart= /usr/lib/systemd/system/emergency.service`" ]; then
        MODE_ERR=1;
      fi
    fi

    if [ $MODE_ERR = 0 ]; then
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check single user mode:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check single user mode:\e[1;31m FAILED\e[0m (not activated)"
      ERR=1;
      let FAIL=$FAIL+1;
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req24 $REQ24 "$REQ24_TXT"

# Req 25: The management of the operating system must be done via a dedicated management network.
let "REQ_NR++"
REQ_TXT="The management of the operating system must be done via a dedicated management network."
FAIL=0
PASS=0

test_req25 () {
  if [ "$1" == "TRUE" ]; then

    # Not implemented! Manual Check necessary!
    FAIL=1;
    SKIP=1;
    echo -e "[Req-$REQ_NR: Test 0.0] Check management interface: SKIPPED (not implemented: Check manual!)"
    REMARK="Not implemented! Check manual (Note: not needed for VMs on cloud)."

    let CNT_SKIP=$CNT_SKIP+$SKIP
    write_to_soc $FAIL $PASS "$REMARK"

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req25 $REQ25 "$REQ25_TXT"

# Req 26: Management services must be bound to the management network.
let "REQ_NR++"
REQ_TXT="Management services must be bound to the management network."    
FAIL=0
PASS=0

test_req26 () {
  if [ "$1" == "TRUE" ]; then
    
    # Not implemented! Manual Check necessary!
    FAIL=1;
    SKIP=1;
    echo -e "[Req-$REQ_NR: Test 0.0] Check interface used for services: SKIPPED (not implemented: Check manual!)"
    REMARK="Not implemented! Check manual (Note: not needed for VMs on cloud)."

    let CNT_SKIP=$CNT_SKIP+$SKIP
    write_to_soc $FAIL $PASS "$REMARK"

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req26 $REQ26 "$REQ26_TXT"

# Req 27: Encrypted protocols must be used for management access to administrate the operating system.
let "REQ_NR++"
REQ_TXT="Encrypted protocols must be used for management access to administrate the operating system."
FAIL=0
PASS=0

test_req27 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    CHK_SSH="$(ps -A | grep -ow 'sshd*$' | wc -l)"
    if [ $CHK_SSH -ne 0 ]; then
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if SSH deamon is running:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if SSH deamon is running:\e[1;31m FAILED\e[0m (no process found)"
      ERR=1;
      let FAIL=$FAIL+1;
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req27 $REQ27 "$REQ27_TXT"

# Req 28: Logging must be enabled in bootloader configuration.
let "REQ_NR++"
REQ_TXT="Logging must be enabled in bootloader configuration."
FAIL=0
PASS=0

test_req28 () {
  if [ "$1" == "TRUE" ]; then

    # Not implemented in Ansible role!
    FAIL=1;
    SKIP=1;
    echo -e "[Req-$REQ_NR: Test 0.0] Check for logging in bootloader configuration: SKIPPED (not implemented: Check manual!)"
    REMARK="Not implemented!"

    let CNT_SKIP=$CNT_SKIP+$SKIP
    write_to_soc $FAIL $PASS "$REMARK"

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req28 $REQ28 "$REQ28_TXT"

# Test 1/1 
#NUM=1
#CHK=$(grep "^GRUB_CMDLINE_LINUX=" $FILE_GRUB | grep -ow "audit=1")

#if [ -n "$CHK" ]; then
#  let PASS=$PASS+1;
#  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if audit is enabled grub config $FILE_GRUB:\e[1;32m PASSED\e[0m";
#else
  #ERR=1;
#  let FAIL=$FAIL+1;
#  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if audit is enabled grub config $FILE_GRUB:\e[1;31m FAILED\e[0m (no config found)";
#fi

#let CNT_ERRORS=$CNT_ERRORS+$FAIL
#let CNT_PASSED=$CNT_PASSED+$PASS
#write_to_soc $FAIL $PASS

# Req 29: Log rotation for logfiles must be configured.
let "REQ_NR++"
REQ_TXT="Log rotation for logfiles must be configured."
FAIL=0
PASS=0

test_req29 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/3
    NUM=1
    CHK=$( grep "[[:space:]]$LOG_ROTATE_TIME" /etc/logrotate.conf)

    if [ -n "$CHK" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if logrotate time is set to $LOG_ROTATE_TIME:\e[1;32m PASSED\e[0m";
    else
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if logrotate time is set to $LOG_ROTATE_TIME:\e[1;31m FAILED\e[0m (wrong setting)";
    fi

    # Test 2/3
    NUM=1
    CHK=$( grep "[[:space:]]rotate $LOG_ROTATE_COUNT" /etc/logrotate.conf)

    if [ -n "$CHK" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if logrotate count is set to $LOG_ROTATE_COUNT:\e[1;32m PASSED\e[0m";
    else
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if logrotate count is set to $LOG_ROTATE_COUNT:\e[1;31m FAILED\e[0m (wrong setting)";
    fi

    # Test 3/3
    NUM=1
    CHK=$( grep "[[:space:]]maxsize $LOG_ROTATE_MAXSIZE" /etc/logrotate.conf)

    if [ -n "$CHK" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check if logrotate size is set to $LOG_ROTATE_MAXSIZE:\e[1;32m PASSED\e[0m";
    else
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check if logrotate size is set to $LOG_ROTATE_MAXSIZE:\e[1;31m FAILED\e[0m (wrong setting)";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req29 $REQ29 "$REQ29_TXT"

# Req 30: System time must be synchronized against a reference time source.
let "REQ_NR++"
REQ_TXT="System time must be synchronized against a reference time source."
FAIL=0
PASS=0

test_req30 () {
  if [ "$1" == "TRUE" ]; then

    NTP_SOFTWARE="chrony ntp"

    # Test 1/3
    NUM=1
    for CHK in $NTP_SOFTWARE; do
      if [ "$($PACKAGE 2>/dev/null | grep -ow $CHK | wc -l)" -eq "1" ]; then
        let PASS=$PASS+1;
        ERR=0;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if $CHK is installed:\e[1;32m PASSED\e[0m";
        break;
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if $CHK is installed:\e[1;31m FAILED\e[0m ($CHK not found)";
      fi
    done

    # Test 2/3
    NUM=1
    if [ "$(timedatectl | grep "synchronized: yes" | wc -l)" -eq "1" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if time is synchronized:\e[1;32m PASSED\e[0m";
    else
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if time is synchronized:\e[1;31m FAILED\e[0m (not synchronized)";
    fi

    # Test 3/3
    NUM=1
    if [ "$(timedatectl | grep -ow "$TIMEZONE" | wc -l)" -eq "1" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check if timezone is $TIMEZONE:\e[1;32m PASSED\e[0m";
    else
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check if timezone is $TIMEZONE:\e[1;31m FAILED\e[0m (wrong timezone)";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req30 $REQ30 "$REQ30_TXT"

# Req 31: Auditd service must be used to log security relevant events. 
let "REQ_NR++"
REQ_TXT="Auditd service must be used to log security relevant events."
FAIL=0
PASS=0

test_req31 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/5
    NUM=1
    if [ "$($PACKAGE 2>/dev/null | grep -ow $AUDIT_DAEMON | wc -l)" -eq "0" ]; then
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if $AUDIT_DAEMON is installed:\e[1;31m FAILED\e[0m (not present)";
    else
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if $AUDIT_DAEMON is installed:\e[1;32m PASSED\e[0m";
    fi

    # Test 2/5
    NUM=1
    if [ "$(auditctl -s | awk -F"[ =]" '/enable/ {print $2}')" -ne "0" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if $AUDIT_DAEMON is enabled:\e[1;32m PASSED\e[0m";
    else
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if $AUDIT_DAEMON is enabled:\e[1;31m FAILED\e[0m (not enabled)";
    fi


    # Test 3/5
    NUM=1
    if [ "$(grep -P "max_log_file\s+=\s+$MAX_LOG_FILE" /etc/audit/auditd.conf | wc -l)" -eq "0" ]; then
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check config if max size of logfiles is $MAX_LOG_FILE:\e[1;31m FAILED\e[0m (wrong value)";
    else
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check config if max size of logfiles is $MAX_LOG_FILE:\e[1;32m PASSED\e[0m";
    fi

    # Test 4/5
    NUM=1
    if [ "$(grep -P "num_logs\s+=\s+$MAX_NUM_LOGS" /etc/audit/auditd.conf | wc -l)" -eq "0" ]; then
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 4.$(((NUM++)))] Check config if number of logfiles is $MAX_NUM_LOGS:\e[1;31m FAILED\e[0m (wrong value)";
    else
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 4.$(((NUM++)))] Check config if number of logfiles is $MAX_NUM_LOGS:\e[1;32m PASSED\e[0m";
    fi

    # Test 5/5
    NUM=1
    if [ "$(grep -P "max_log_file_action\s+=\s+$MAX_LOG_FILE_ACTION" /etc/audit/auditd.conf | wc -l)" -eq "0" ]; then
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 5.$(((NUM++)))] Check config if logfile action is $MAX_LOG_FILE_ACTION:\e[1;31m FAILED\e[0m (wrong value)";
    else
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 5.$(((NUM++)))] Check config if logfile action is $MAX_LOG_FILE_ACTION:\e[1;32m PASSED\e[0m";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req31 $REQ31 "$REQ31_TXT"

# Req 32: System events must be logged.
let "REQ_NR++"
REQ_TXT="System events must be logged."
FAIL=0
PASS=0

test_req32 () {
  if [ "$1" == "TRUE" ]; then

    CNT=1
    SYS_EVENTS=SYS_EVENTS_$CNT

    # Test 1/2
    NUM=1
    while [ $CNT -lt 100 ]; do
      if [ -n "${!SYS_EVENTS}" ]; then
        SYS_EVENTS_NEW=$(echo ${!SYS_EVENTS} | sed 's/^.//' | sed 's/ -/ \\-/g')
        if [ "$(auditctl -l | grep -E "$SYS_EVENTS_NEW" | wc -l)" -eq "0" ]; then
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check auditd for system events:\e[1;31m FAILED\e[0m (event missing: ${!SYS_EVENTS})";
        else
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check auditd for system events:\e[1;32m PASSED\e[0m";
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
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check auditd for os specific system events:\e[1;31m FAILED\e[0m (event missing: ${!SYS_EVENTS_OS})";
        else
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check auditd for os specific system events:\e[1;32m PASSED\e[0m";
        fi
        let CNT++;
        SYS_EVENTS_OS=SYS_EVENTS_$OS_MAIN_DISTRO$CNT;
      else
        CNT=100;
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req32 $REQ32 "$REQ32_TXT"

# Req 33: Access and Authentication events must be logged.
let "REQ_NR++"
REQ_TXT="Access and Authentication events must be logged."
FAIL=0
PASS=0

test_req33 () {
  if [ "$1" == "TRUE" ]; then

    CNT=1
    ACCESS_EVENTS=ACCESS_EVENTS_$CNT

    # Test 1/3
    NUM=1
    while [ $CNT -lt 100 ]; do
      if [ -n "${!ACCESS_EVENTS}" ]; then
        ACCESS_EVENTS_NEW=$(echo ${!ACCESS_EVENTS} | sed 's/^.//' | sed 's/ -/ \\-/g')
        if [ "$(auditctl -l | grep -E "$ACCESS_EVENTS_NEW" | wc -l)" -eq "0" ]; then
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check auditd for account events:\e[1;31m FAILED\e[0m (event missing: ${!ACCESS_EVENTS})";
        else
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check auditd for account events:\e[1;32m PASSED\e[0m";
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
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check auditd for os specific account events:\e[1;31m FAILED\e[0m (event missing: ${!ACCESS_EVENTS_OS})";
        else
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check auditd for os specific account events:\e[1;32m PASSED\e[0m";
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
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check auditd for events of priviledged command $CHK:\e[1;31m FAILED\e[0m (event missing)";
      else
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check auditd for events of priviledged command $CHK:\e[1;32m PASSED\e[0m";
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req33 $REQ33 "$REQ33_TXT"

# Req 34: Account and Group Management events must be logged.
let "REQ_NR++"
REQ_TXT="Account and Group Management events must be logged."
FAIL=0
PASS=0

test_req34 () {
  if [ "$1" == "TRUE" ]; then

    CNT=1
    ACC_GRP_MGMT_EVENTS=ACC_GRP_MGMT_EVENTS_$CNT

    # Test 1/1
    NUM=1
    while [ $CNT -lt 100 ]; do
      if [ -n "${!ACC_GRP_MGMT_EVENTS}" ]; then
        ACC_GRP_MGMT_EVENTS_NEW=$(echo ${!ACC_GRP_MGMT_EVENTS} | sed 's/^.//' | sed 's/ -/ \\-/g')
        if [ "$(auditctl -l | grep -E "$ACC_GRP_MGMT_EVENTS_NEW" | wc -l)" -eq "0" ]; then
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check auditd for account mgmt events:\e[1;31m FAILED\e[0m (event missing: ${!ACC_GRP_MGMT_EVENTS})";
        else
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check auditd for account mgmt events:\e[1;32m PASSED\e[0m";
        fi
        let CNT++;
        ACC_GRP_MGMT_EVENTS=ACC_GRP_MGMT_EVENTS_$CNT;
      else
        CNT=100;
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req34 $REQ34 "$REQ34_TXT"

# Req 35: Configuration Change events must be logged.
let "REQ_NR++"
REQ_TXT="Configuration Change events must be logged."
FAIL=0
PASS=0

test_req35 () {
  if [ "$1" == "TRUE" ]; then

    CNT=1
    CHANGE_EVENTS=CHANGE_EVENTS_$CNT

    # Test 1/2
    NUM=1
    while [ $CNT -lt 100 ]; do
      if [ -n "${!CHANGE_EVENTS}" ]; then
        CHANGE_EVENTS_NEW=$(echo ${!CHANGE_EVENTS} | sed 's/^.//' | sed 's/ -/ \\-/g')
        if [ "$(auditctl -l | grep -E "$CHANGE_EVENTS_NEW" | wc -l)" -eq "0" ]; then
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check auditd for change events:\e[1;31m FAILED\e[0m (event missing: ${!CHANGE_EVENTS})";
        else
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check auditd for change events:\e[1;32m PASSED\e[0m";
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
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check auditd for os specific change events:\e[1;31m FAILED\e[0m (event missing: ${!CHANGE_EVENTS_OS})";
        else
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check auditd for os specific change events:\e[1;32m PASSED\e[0m";
        fi
        let CNT++;
        CHANGE_EVENTS_OS=CHANGE_EVENTS_$OS_MAIN_DISTRO$CNT;
      else
        CNT=100;
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req35 $REQ35 "$REQ35_TXT"

# Req 36: Auditd configuration must be immutable.
let "REQ_NR++"
REQ_TXT="Auditd configuration must be immutable."
FAIL=0
PASS=0

test_req36 () {
  if [ "$1" == "TRUE" ]; then

    if [ "$MAJOR_VERSION" -eq "16" ]; then
      CONFIG_FILE="/etc/audit/audit.rules";
    else
      CONFIG_FILE="/etc/audit/rules.d/audit.rules";
    fi

    # Test 1/1
    NUM=1
    if [ "$(grep "\-e 2" $CONFIG_FILE | wc -l)" -eq "0" ]; then
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check auditd config is immutable:\e[1;31m FAILED\e[0m (entry '-e 2' not found)";
    else
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check auditd config is immutable:\e[1;32m PASSED\e[0m";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req36 $REQ36 "$REQ36_TXT"

# Req 37: Security relevant logging data must be send to an external system direct after their creation.
let "REQ_NR++"
REQ_TXT="Security relevant logging data must be send to an external system direct after their creation."
FAIL=0
PASS=0

test_req37 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    if [ "$SYSLOG_TYPE" == "rsyslog" ]; then
      CHK=$(ps -A | grep $SYSLOG_TYPE)
      if [ -z "$CHK" ]; then
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check $SYSLOG_TYPE is installed and running:\e[1;31m FAILED\e[0m ($SYSLOG_TYPE not running)";
      else
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check $SYSLOG_TYPE is installed and running:\e[1;32m PASSED\e[0m";
      fi
    else
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check $SYSLOG_TYPE is installed and running:\e[1;31m FAILED\e[0m ($SYSLOG_TYPE not supported! Check manual.)";
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req37 $REQ37 "$REQ37_TXT"

# Req 38: If RSyslog is used, the default permission of 640 or more restrictive for logfiles must be configured.
let "REQ_NR++"
REQ_TXT="If RSyslog is used, the default permission of 640 or more restrictive for logfiles must be configured."
FAIL=0
PASS=0

test_req38 () {
  if [ "$1" == "TRUE" ]; then

    if [ "$SYSLOG_TYPE" == "rsyslog" ]; then
      # Test 1/3
      NUM=1
      PRIV=$(stat -c %a $RSYSLOG_CONF)
      if [ "$PRIV" -le "640" ]; then 
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if priviledges of $RSYSLOG_CONF is 640 or less:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if priviledges of $RSYSLOG_CONF is 640 or less:\e[1;31m FAILED\e[0m (is $PRIV)";
      fi
      # Test 2/3
      NUM=1
      USER=$(stat -c '%U' $RSYSLOG_CONF)
      if [ "$USER" == "root" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if owner of $RSYSLOG_CONF is root:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if owner of $RSYSLOG_CONF is root:\e[1;31m FAILED\e[0m (owner is $USER)";
      fi
      # Test 3/3
      NUM=1
      GROUP=$(stat -c '%G' $RSYSLOG_CONF)
      if [ "$GROUP" == "root" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check if group of $RSYSLOG_CONF is root:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check if group of $RSYSLOG_CONF is root:\e[1;31m FAILED\e[0m (group is $GROUP)";
      fi
    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check file permission, owner and group of $RSYSLOG_CONF: n/a (rsyslog not used)";
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable">&3;
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req38 $REQ38 "$REQ38_TXT"

# Req 39: If RSyslog is used, at least one central logging server must be configured.
let "REQ_NR++"
REQ_TXT="If RSyslog is used, at least one central logging server must be configured."
FAIL=0
PASS=0

test_req39 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    if [ "$SYSLOG_TYPE" == "rsyslog" ]; then
      if [ "$(rsyslogd -N1 &>/dev/null && echo $?)" -eq "0" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check $SYSLOG_TYPE configuration:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check $SYSLOG_TYPE configuration:\e[1;31m FAILED\e[0m (error(s) found)";
      fi
    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check $SYSLOG_TYPE configuration: n/a (rsyslog not used)";
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable">&3;
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req39 $REQ39 "$REQ39_TXT"

# Req 40: If Syslog-NG is used, the default permission of 640 or more restrictive for logfiles must be configured.
let "REQ_NR++"
REQ_TXT="If Syslog-NG is used, the default permission of 640 or more restrictive for logfiles must be configured."
FAIL=0
PASS=0

test_req40 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    if [ "$SYSLOG_TYPE" == "syslog-ng" ]; then
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 0.0] Check file permission, owner and group for syslog-ng:\e[1;31m FAILED\e[0m (hardening not implemented yet!)"
      write_to_soc $FAIL $PASS "Automated hardening not implemented!"
    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check file permission, owner and group for syslog-ng: SKIPPED (not implemented: Check manual!)"
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable">&3;
      let CNT_SKIP=$CNT_SKIP+1
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req40 $REQ40 "$REQ40_TXT"

# Req 41: If Syslog-NG is used, at least one central logging server must be configured.
let "REQ_NR++"
REQ_TXT="If Syslog-NG is used, at least one central logging server must be configured."
FAIL=0
PASS=0

test_req41 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/1
    NUM=1
    if [ "$SYSLOG_TYPE" == "syslog-ng" ]; then
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 0.0] Check syslog-ng configuration:\e[1;31m FAILED\e[0m (hardening not implemented yet!)"
      write_to_soc $FAIL $PASS "Automated hardening not implemented!"
    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check syslog-ng configuration: SKIPPED (not implemented: Check manual!)"
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable">&3;
      let CNT_SKIP=$CNT_SKIP+1
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req41 $REQ41 "$REQ41_TXT"

# Req 42: If PAM is used, an appropriate hashing function must be configured for password protection for PAM.
let "REQ_NR++"
REQ_TXT="If PAM is used, an appropriate hashing function must be configured for password protection for PAM."
FAIL=0
PASS=0

test_req42 () {
  if [ "$1" == "TRUE" ]; then

    PAM_FILES_OS=PAM_FILES_$OS_MAIN_DISTRO
    NUM1=1
    NUM2=1

    for CHK in ${!PAM_FILES_OS}; do
      # Test 1/2
      SEARCH_METHOD="$(grep -e 'pam_unix.so' /etc/pam.d/$CHK | grep $PAM_ENRYPT_METHOD | wc -l)"
      if [ $SEARCH_METHOD -eq 1 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) encryption method ($PAM_ENRYPT_METHOD) for password hashing:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) encryption method ($PAM_ENRYPT_METHOD) for password hashing:\e[1;31m FAILED\e[0m (wrong configuration)"
      fi

      # Test 2/2
      SEARCH_ROUNDS="$(grep -e 'pam_unix.so' /etc/pam.d/$CHK | grep rounds=$PAM_ROUNDS | wc -l)"
      if [ $SEARCH_ROUNDS -eq 1 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) for rounds ($PAM_ROUNDS) for password hashing:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) for rounds ($PAM_ROUNDS) for password hashing:\e[1;31m FAILED\e[0m (wrong configuration)"
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req42 $REQ42 "$REQ42_TXT"

# Req 43: If PAM is used, password rules must be configured for PAM to force the use of passwords with a minimum length of 8 characters and a combination of three out of the following categories: upper cases, lower case, numbers and special characters.
let "REQ_NR++"
REQ_TXT="If PAM is used, password rules must be configured for PAM to force the use of passwords with a minimum length of 8 characters and a combination of three out of the following categories: upper cases, lower case, numbers and special characters."
FAIL=0
PASS=0

test_req43 () {
  if [ "$1" == "TRUE" ]; then

    PAM_MODULE_SUSE="pam_cracklib.so"
    PAM_MODULE_DEBIAN="pam_pwquality.so"
    PAM_MODULE_OS=PAM_MODULE_$OS_MAIN_DISTRO
    PAM_FILES_OS=PAM_FILES_$OS_MAIN_DISTRO
    NUM1=1
    NUM2=1

    for CHK in ${!PAM_FILES_OS}; do
      if [ "$OS_MAIN_DISTRO" == "REDHAT" ]; then
        
        # Test 1/2 (RedHat)
        SEARCH_PASS_LEN="$(awk -F\= '/minlen/ {print $2}' /etc/security/pwquality.conf | tr -d " ")"
        if [ $SEARCH_PASS_LEN -ge $PAM_PASSWORD_LENGTH ]; then
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check pam (/etc/security/pwquality.conf) password length ($PAM_PASSWORD_LENGTH):\e[1;32m PASSED\e[0m";
        else
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check pam (/etc/security/pwquality.conf) password length ($PAM_PASSWORD_LENGTH):\e[1;31m FAILED\e[0m (wrong configuration)"
        fi

        #Test 2/2 (RedHat)
        SEARCH_MINCLASS="$(grep "minclass *= *$PAM_CHAR_CLASSES" /etc/security/pwquality.conf | wc -l)"
        if [ $SEARCH_MINCLASS -eq 1 ]; then
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check pam (/etc/security/pwquality.conf) allowed character classes ($PAM_CHAR_CLASSES) for passwords:\e[1;32m PASSED\e[0m";
        else
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check pam (/etc/security/pwquality.conf) allowed character classes  ($PAM_CHAR_CLASSES) for passwords:\e[1;31m FAILED\e[0m (wrong configuration)"
        fi
      
      else
      
        # Test 1/2 (Suse + Ubuntu)
        SEARCH_PASS_LEN="$(grep -e ${!PAM_MODULE_OS} /etc/pam.d/$CHK | grep "minlen=$PAM_PASSWORD_LENGTH" | wc -l)"
        if [ $SEARCH_PASS_LEN -eq 1 ]; then
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) password length ($PAM_PASSWORD_LENGTH):\e[1;32m PASSED\e[0m";
        else
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) password length ($PAM_PASSWORD_LENGTH):\e[1;31m FAILED\e[0m (wrong configuration)"
        fi
        
        # Test 2/2 (Suse + Ubuntu)
        SEARCH_MINCLASS="$(grep -e ${!PAM_MODULE_OS} /etc/pam.d/$CHK | grep "minclass=$PAM_CHAR_CLASSES" | wc -l)"
        if [ $SEARCH_MINCLASS -eq 1 ]; then
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) allowed character classes ($PAM_CHAR_CLASSES) for passwords:\e[1;32m PASSED\e[0m";
        else
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) allowed character classes  ($PAM_CHAR_CLASSES) for passwords:\e[1;31m FAILED\e[0m (wrong configuration)"
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
      echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check for password complexity rules:\e[1;32m PASSED\e[0m";
    else
      #ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check for password complexity rules:\e[1;31m FAILED\e[0m (rule set wrong)"
    fi

    userdel -r $USER &>/dev/null

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req43 $REQ43 "$REQ43_TXT"

# Req 44: If PAM is used, a protection against brute force and dictionary attacks that hinder password guessing must be configured in PAM.
let "REQ_NR++"
REQ_TXT="If PAM is used, a protection against brute force and dictionary attacks that hinder password guessing must be configured in PAM."
FAIL=0
PASS=0

test_req44 () {
  if [ "$1" == "TRUE" ]; then

    PAM_MODULE_REDHAT="pam_faillock.so"
    PAM_MODULE_SUSE="pam_tally2.so"
    PAM_MODULE_DEBIAN="pam_tally2.so"
    PAM_FILES_SUSE="login"
    PAM_FILES_DEBIAN="common-account"
    PAM_MODULE_OS=PAM_MODULE_$OS_MAIN_DISTRO
    PAM_FILES_OS=PAM_FILES_$OS_MAIN_DISTRO
    NUM1=1
    NUM2=1

    for CHK in ${!PAM_FILES_OS}; do
      # Test 1/2
      SEARCH_ATTEMPS="$(grep -e ${!PAM_MODULE_OS} /etc/pam.d/$CHK | grep "deny=$PAM_FAILED_LOGIN_ATTEMPS" | wc -l)"
      if [ $SEARCH_ATTEMPS -ne 0 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) failed login attemps ($PAM_FAILED_LOGIN_ATTEMPS):\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check pam (/etc/pam.d/$CHK) failed login attemps ($PAM_FAILED_LOGIN_ATTEMPS):\e[1;31m FAILED\e[0m (wrong configuration)"
      fi

      # Test 2/2
      SEARCH_UNLOCK_TIME="$(grep -e ${!PAM_MODULE_OS} /etc/pam.d/$CHK | grep "unlock_time=$PAM_UNLOCK_TIME" | wc -l)"
      if [ $SEARCH_UNLOCK_TIME -ne 0 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) unlock time ($PAM_UNLOCK_TIME):\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check pam (/etc/pam.d/$CHK) unlock time ($PAM_UNLOCK_TIME):\e[1;31m FAILED\e[0m (wrong configuration)"
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req44 $REQ44 "$REQ444_TXT"

# Req 45: If PAM is used , PAM must be configured that motd did not contain any sensitive data.
let "REQ_NR++"
REQ_TXT="If PAM is used , PAM must be configured that motd did not contain any sensitive data."
FAIL=0
PASS=0

test_req45 () {
  if [ "$1" == "TRUE" ]; then

    PAM_FILES_MOTD="login sshd"
    NUM=1

    for CHK in $PAM_FILES_MOTD; do
      # Test 1/1
      SEARCH_MOTD="$(grep "pam_motd.so" /etc/pam.d/$CHK | grep -v "^#" | wc -l)"
      if [ $SEARCH_MOTD -eq 0 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check pam (/etc/pam.d/$CHK) if motd is enabled:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check pam (/etc/pam.d/$CHK) if motd is enabled:\e[1;31m FAILED\e[0m (wrong configuration)"
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req45 $REQ45 "$REQ45_TXT"

# Req 46: If iptables is used, policies for loopback traffic must be configured.
let "REQ_NR++"
REQ_TXT="If iptables is used, policies for loopback traffic must be configured."
FAIL=0
PASS=0

test_req46 () {
  if [ "$1" == "TRUE" ]; then

    IPTABLES_RULE_1="-A INPUT -i lo -j ACCEPT"
    IPTABLES_RULE_2="-A OUTPUT -o lo -j ACCEPT"
    IPTABLES_RULE_3="-A INPUT -s 127.0.0.0/8 -j DROP"

    if [ "$OS_MAIN_DISTRO" != "SUSE" ]; then

      # Test 1/1
      NUM=1
      for CNT in 1 2 3; do
        IPTABLES_RULE=IPTABLES_RULE_$CNT
        IPTABLES_RULE_NEW="$(echo ${!IPTABLES_RULE} | sed 's/^.//' | sed 's/ -/ \\-/g')"
        CHK_IPTABLES="$(iptables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
        if [ $CHK_IPTABLES -eq 1 ]; then
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check iptables rule '"${!IPTABLES_RULE}"':\e[1;32m PASSED\e[0m";
        else
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check iptables rule '"${!IPTABLES_RULE}"':\e[1;31m FAILED\e[0m (rule missing)"
        fi
      done

      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check IPTables configuration and rules: SKIPPED (Not implemented!)";
      echo "Req $REQ_NR;$REQ_TXT;Not Compliant;IPTables not implemented for Suse Linux">&3;
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req46 $REQ46 "$REQ46_TXT"

# Req 47: If iptables is used, policies for outbound and established connections must be configured.
let "REQ_NR++"
REQ_TXT="If iptables is used, policies for outbound and established connections must be configured."
FAIL=0
PASS=0

test_req47 () {
  if [ "$1" == "TRUE" ]; then

    IPTABLES_RULE_1="-A OUTPUT -p tcp -m state --state NEW,ESTABLISHED -j ACCEPT"
    IPTABLES_RULE_2="-A OUTPUT -p udp -m state --state NEW,ESTABLISHED -j ACCEPT"
    IPTABLES_RULE_3="-A OUTPUT -p icmp -m state --state NEW,ESTABLISHED -j ACCEPT"
    IPTABLES_RULE_4="-A INPUT -p tcp -m state --state ESTABLISHED -j ACCEPT"
    IPTABLES_RULE_5="-A INPUT -p udp -m state --state ESTABLISHED -j ACCEPT"
    IPTABLES_RULE_6="-A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT"

    if [ "$OS_MAIN_DISTRO" != "SUSE" ]; then

      # Test 1/1
      NUM=1
      for CNT in 1 2 3 4 5 6; do
        IPTABLES_RULE=IPTABLES_RULE_$CNT
        IPTABLES_RULE_NEW="$(echo ${!IPTABLES_RULE} | sed 's/^.//' | sed 's/ -/ \\-/g')"
        CHK_IPTABLES="$(iptables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
        if [ $CHK_IPTABLES -eq 1 ]; then
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check iptables rule '"${!IPTABLES_RULE}"':\e[1;32m PASSED\e[0m";
        else
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check iptables rule '"${!IPTABLES_RULE}"':\e[1;31m FAILED\e[0m (rule missing)"
        fi
      done

      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check IPTables configuration and rules: SKIPPED (Not implemented!)";
      echo "Req $REQ_NR;$REQ_TXT;Not Compliant;IPTables not implemented for Suse Linux">&3;
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req47 $REQ47 "$REQ47_TXT"

# Req 48: If iptables is used, policies must exist for all ports in listening state.
let "REQ_NR++"
REQ_TXT="If iptables is used, policies must exist for all ports in listening state."
FAIL=0
PASS=0

test_req48 () {
  if [ "$1" == "TRUE" ]; then

    if [ "$OS_MAIN_DISTRO" != "SUSE" ]; then

      # Test 1/3 TCP
      NUM=1
      IPTABLES_RULE="-A INPUT -p tcp -m state --state NEW -m tcp --dport"
      IPTABLES_RULE_NEW="$(echo $IPTABLES_RULE | sed 's/^.//' | sed 's/ -/ \\-/g')"
      CHK_IPTABLES="$(iptables -S | grep -i "$IPTABLES_RULE_NEW")"
      if [ $(echo $CHK_IPTABLES | wc -l) -eq 1 ]; then
        CHK_PORTS="$(echo $CHK_IPTABLES | awk '{print $12}' | sort -u)"
        for CHK in $CHK_PORTS; do
          if [ "$CHK" == "$(echo $TCP_PORTS | grep -ow "$CHK")" ]; then
            let PASS=$PASS+1;
            echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check iptables rules for TCP port:\e[1;32m PASSED\e[0m";
          else
            ERR=1;
            let FAIL=$FAIL+1;
            echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check iptables rules for TCP port:\e[1;31m FAILED\e[0m (port $CHK not allowed)";
          fi
        done
      else
        echo -e "[Req-$REQ_NR: Test 1.1] Check iptables rules for TCP port: SKIPPED (no tcp input rule found)";
        echo "Req $REQ_NR;$REQ_TXT;Not Applicable;No TCP input rule found">&3;
        let CNT_SKIP=$CNT_SKIP+$SKIP
      fi
      
      # Test 2/3 UDP
      NUM=1
      IPTABLES_RULE="-A INPUT -p tcp -m state --state NEW -m udp --dport"
      IPTABLES_RULE_NEW="$(echo $IPTABLES_RULE | sed 's/^.//' | sed 's/ -/ \\-/g')"
      CHK_IPTABLES="$(iptables -S | grep -i "$IPTABLES_RULE_NEW")"
      if [ $(echo $CHK_IPTABLES | wc -l) -eq 1 ]; then
        CHK_PORTS="$(echo $CHK_IPTABLES | awk '{print $12}' | sort -u)"
        for CHK in $CHK_PORTS; do
          if [ "$CHK" == "$(echo $UDP_PORTS | grep -ow "$CHK")" ]; then
            let PASS=$PASS+1;
            echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check iptables rules for UDP port:\e[1;32m PASSED\e[0m";
          else
            ERR=1;
            let FAIL=$FAIL+1;
            echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check iptables rules for UDP port:\e[1;31m FAILED\e[0m (port $CHK not allowed)"
          fi
        done
      else
        echo -e "[Req-$REQ_NR: Test 2.1] Check iptables rules for UDP port: SKIPPED (no tcp input rule found)";
        echo "Req $REQ_NR;$REQ_TXT;Not Applicable;No UDP input rule found">&3;
        let CNT_SKIP=$CNT_SKIP+$SKIP
      fi

      # Test 3/3 ICMP
      NUM=1
      IPTABLES_RULE="-A INPUT -p icmp -m state --state NEW,RELATED,ESTABLISHED -m icmp --icmp-type 8 -j ACCEPT"
      IPTABLES_RULE_NEW="$(echo $IPTABLES_RULE | sed 's/^.//' | sed 's/ -/ \\-/g')"
      CHK_IPTABLES="$(iptables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
      if [ $CHK_IPTABLES -eq 1 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check iptables rule '-A INPUT -p icmp':\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 3.$(((NUM++)))] Check iptables rule '-A INPUT -p icmp':\e[1;31m FAILED\e[0m (rule missing)"
      fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check IPTables configuration and rules: SKIPPED (Not implemented!)";
      echo "Req $REQ_NR;$REQ_TXT;Not Compliant;IPTables not implemented for Suse Linux">&3;
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req48 $REQ48 "$REQ48_TXT"

# Req 49: If iptables is used, the default policy must be configured to drop all traffic.
let "REQ_NR++"
REQ_TXT="If iptables is used, the default policy must be configured to drop all traffic."
FAIL=0
PASS=0

test_req49 () {
  if [ "$1" == "TRUE" ]; then

    IPTABLES_RULE_1="-P INPUT DROP"
    IPTABLES_RULE_2="-P FORWARD DROP"
    IPTABLES_RULE_3="-P OUTPUT DROP"

    if [ "$OS_MAIN_DISTRO" != "SUSE" ]; then

      # Test 1/1
      NUM=1
      for CNT in 1 2 3 4 5 6; do
        IPTABLES_RULE=IPTABLES_RULE_$CNT
        IPTABLES_RULE_NEW="$(echo ${!IPTABLES_RULE} | sed 's/^.//' | sed 's/ -/ \\-/g')"
        CHK_IPTABLES="$(iptables -S | grep -i "$IPTABLES_RULE_NEW" | wc -l)"
        if [ $CHK_IPTABLES -eq 1 ]; then
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check iptables rule '"${!IPTABLES_RULE}"':\e[1;32m PASSED\e[0m";
        else
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check iptables rule '"${!IPTABLES_RULE}"':\e[1;31m FAILED\e[0m (rule missing)"
        fi
      done

      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check IPTables configuration and rules: SKIPPED (Not implemented!)";
      echo "Req $REQ_NR;$REQ_TXT;Not Compliant;IPTables not implemented for Suse Linux">&3;
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req49 $REQ49 "$REQ49_TXT"

# Req 50: If a system has Internet facing services or is a virtualization host, a MAC solution must be used.
let "REQ_NR++"
REQ_TXT="If a system has Internet facing services or is a virtualization host, a MAC solution must be used."
FAIL=0
PASS=0

test_req50 () {
  if [ "$1" == "TRUE" ]; then

    MAC_TOOLS=MAC_TOOLS_$OS_MAIN_DISTRO

    # Test 1/1
    NUM=1
    for CHK in ${!MAC_TOOLS}; do
      if [ "$($PACKAGE 2>/dev/null | grep -ow $CHK | wc -l)" -ne "0" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if MAC package ($CHK) is installed:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if MAC package ($CHK) is installed:\e[1;31m FAILED\e[0m (present)";
      fi
    done

    if [ "$MAC_SOLUTION" == "selinux" ]; then
      
      # Test 1/1
      CHK=$(sestatus 2>/dev/null | grep -i "SELinux status" | grep -owi "enabled" | tr '[:lower:]' '[:upper:]')
      NUM=1
      if [ "$CHK" == "ENABLED" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if SELinux is enabled:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if SELinux is enabled:\e[1;31m FAILED\e[0m (SELinux is disabled)";
      fi

      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check if SELinux is enabled: SKIPPED (SELinux not used)";
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi

    if [ "$MAC_SOLUTION" == "apparmor" ]; then
      
      # Test 1/1
      CHK=$(aa-status 2>/dev/null | grep -i "apparmor module is loaded")
      NUM=1
      if [ -n "$CHK" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if AppArmor is enabled:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if AppArmor is enabled:\e[1;31m FAILED\e[0m (AppArmor is disabled)";
      fi

      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check if AppArmor is enabled: SKIPPED (AppArmor not used)";
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req50 $REQ50 "$REQ50_TXT"

# Req 51: If SELinux is used, it must not be disabled in bootloader configuration.
let "REQ_NR++"
REQ_TXT="If SELinux is used, it must not be disabled in bootloader configuration."
FAIL=0
PASS=0

test_req51 () {
  if [ "$1" == "TRUE" ]; then

    if [ "$MAC_SOLUTION" == "selinux" ]; then
      # Test 1/2
      NUM=1
      CHK=$(grep -ow "selinux=0" $FILE_GRUB)

      if [ -z "$CHK" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if SELinux is enabled grub config $FILE_GRUB:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if SELinux is enabled grub config $FILE_GRUB:\e[1;31m FAILED\e[0m (no config found)";
      fi

      # Test 2/2
      NUM=1
      CHK=$(grep -ow "enforcing=0" $FILE_GRUB)

      if [ -z "$CHK" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if SELinux is enabled grub config $FILE_GRUB:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if SELinux is enabled grub config $FILE_GRUB:\e[1;31m FAILED\e[0m (no config found)";
      fi

      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check if SELinux is enabled grub config: SKIPPED (SELinux not used)";
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable;SELinux is not used with used Linux">&3;
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req51 $REQ51 "$REQ51_TXT"

# Req 52: If SELinux is used, its state must be enforced.
let "REQ_NR++"
REQ_TXT="If SELinux is used, its state must be enforced."
FAIL=0
PASS=0

test_req52 () {
  if [ "$1" == "TRUE" ]; then

    if [ "$MAC_SOLUTION" == "selinux" ]; then
      # Test 1/2
      NUM=1
      FILE="$FILE_SELINUX"
      CHK=$(grep -ow "SELINUX=enforcing" $FILE)
      
      if [ -n "$CHK" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if enforcing is set in file '"$FILE"' for SELinux:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if enforcing is set in file '"$FILE"' for SELinux:\e[1;31m FAILED\e[0m (no config found)";
      fi

      # Test 2/2
      NUM=1
      CHK=$(sestatus 2>/dev/null | grep -i "Current mode" | grep -owi "enforcing" | tr '[:lower:]' '[:upper:]')

      if [ "$CHK" == "ENFORCING" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if enforcing is activated for SELinux:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if enforcing is activated for SELinux:\e[1;31m FAILED\e[0m (not enforced)";
      fi
      
      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check if enforcing is activated for SELinux: SKIPPED (SELinux not used)";
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable;SELinux is not used with used Linux">&3;
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi
  
  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req52 $REQ52 "$REQ52_TXT"

# Req 53: If SELinux is used, the policy must be configured.
let "REQ_NR++"
REQ_TXT="If SELinux is used, the policy must be configured."
FAIL=0
PASS=0

test_req53 () {
  if [ "$1" == "TRUE" ]; then

    if [ "$MAC_SOLUTION" == "selinux" ]; then
      FILE="$FILE_SELINUX"
      # Test 1/2
      NUM=1
      CHK=$(grep -ow "SELINUXTYPE=targeted" $FILE)

      if [ -n "$CHK" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if targeted is set in file '"$FILE"' for SELinux:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if targeted is set in file '"$FILE"' for SELinux:\e[1;31m FAILED\e[0m (no config found)";
      fi

      # Test 2/2

      NUM=1
      CHK=$(sestatus 2>/dev/null | grep -i "Loaded policy name" | grep -owi "targeted" | tr '[:lower:]' '[:upper:]')

      if [ "$CHK" == "TARGETED" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if SELinux is set to targeted:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if SELinux is set to targeted:\e[1;31m FAILED\e[0m (not activated)";
      fi

      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check if targeted is is set for SELinux: SKIPPED (SELinux not used)";
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable;SELinux is not used with used Linux">&3;
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req53 $REQ53 "$REQ53_TXT"

# Req 54: If SELinux is used, SETroubleshoot and MCS Translation Service must not be installed.
let "REQ_NR++"
REQ_TXT="If SELinux is used, SETroubleshoot and MCS Translation Service must not be installed."
FAIL=0
PASS=0

test_req54 () {
  if [ "$1" == "TRUE" ]; then

    if [ "$MAC_SOLUTION" == "selinux" ]; then
      NUM=1
      for CHK in $SELINUX_SOFTWARE; do
        if [ "$($PACKAGE 2>/dev/null | grep -ow $CHK | wc -l)" -ne "0" ]; then
          ERR=1;
          let FAIL=$FAIL+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if $CHK is not installed:\e[1;31m FAILED\e[0m (present)";
        else
          let PASS=$PASS+1;
          echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if $CHK is not installed:\e[1;32m PASSED\e[0m";
        fi
      done

      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check if tool for SELinux are not installed: SKIPPED (SELinux not used)";
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable;SELinux is not used with used Linux">&3;
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req54 $REQ54 "$REQ54_TXT"

# Req 55: If AppArmor is used, it must not be disabled in bootloader configuration.
let "REQ_NR++"
REQ_TXT="If AppArmor is used, it must not be disabled in bootloader configuration."
FAIL=0
PASS=0

test_req55 () {
  if [ "$1" == "TRUE" ]; then

    if [ "$MAC_SOLUTION" == "apparmor" ]; then
      # Test 1/1
      NUM=1
      CHK=$(grep -ow "apparmor=0" $FILE_GRUB)

      if [ -z "$CHK" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if AppArmor is enabled grub config $FILE_GRUB:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if AppArmor is enabled grub config $FILE_GRUB:\e[1;31m FAILED\e[0m (no config found)";
      fi

      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check if AppArmor is enabled grub config: SKIPPED (AppArmor not used)";
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable;AppArmor is not used with used Linux">&3;
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req55 $REQ55 "$REQ55_TXT"

# Req 56: AppArmor is used, its state must be enforced.
let "REQ_NR++"
REQ_TXT="AppArmor is used, its state must be enforced."
FAIL=0
PASS=0

test_req56 () {
  if [ "$1" == "TRUE" ]; then

    if [ "$MAC_SOLUTION" == "apparmor" ]; then
      # Test 1/1
      NUM=1
      CHK="$(aa-status 2>/dev/null | grep "profiles are in enforce mode" | awk '{print $1}')"

      if [ $CHK -gt 0 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if enforcing is activated for AppArmor:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if enforcing is activated for AppArmor:\e[1;31m FAILED\e[0m (not activated)";
      fi

      let CNT_ERRORS=$CNT_ERRORS+$FAIL
      let CNT_PASSED=$CNT_PASSED+$PASS
      write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check if enforcing is activated for AppArmor: SKIPPED (AppArmor not used)";
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable;AppArmor is not used with used Linux">&3;
      let CNT_SKIP=$CNT_SKIP+$SKIP
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req56 $REQ56 "$REQ56_TXT"

# Req 57: No legacy + entries must exist in files passwd, shadows and group.
let "REQ_NR++"
REQ_TXT="No legacy + entries must exist in files passwd, shadows and group."
FAIL=0
PASS=0

test_req57 () {
  if [ "$1" == "TRUE" ]; then

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
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check file (${!FILE}) legacy + entries:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check file (${!FILE}) legacy + entries:\e[1;31m FAILED\e[0m (entries found)"
      fi
      let CNT++
      FILE=FILE_$CNT;
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req57 $REQ57 "$REQ57_TXT"

# Req 58: A user's home directory must be owned by the user and have mode 750 or more restrictive.
let "REQ_NR++"
REQ_TXT="A user's home directory must be owned by the user and have mode 750 or more restrictive."
FAIL=0
PASS=0
NUM1=1
NUM2=1
NUM3=1

test_req58 () {
  if [ "$1" == "TRUE" ]; then

    CHK_HOME="$(ls /home/)"
    PRIV="750"

    for CHK in $CHK_HOME; do

      # Test 1/3
      CHK_USER="$(stat -c %U /home/$CHK)"
      if [ "$CHK_USER" == "$CHK" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check file ($CHK) for correct user setting:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check file ($CHK) for correct user setting:\e[1;31m FAILED\e[0m (wrong user $CHK_USER)"
      fi

      # Test 2/3
      CHK_GRP="$(stat -c %G /home/$CHK)"
      if [ "$CHK_GRP" == "$CHK" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check file ($CHK) for correct group setting:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check file ($CHK) for correct group setting:\e[1;31m FAILED\e[0m (wrong group $CHK_GRP)"
      fi

      # Test 3/3
      CHK_PRIV="$(stat -c %a /home/$CHK)"
      if [ $CHK_PRIV -le $PRIV ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 3.$(((NUM3++)))] Check file ($CHK) for correct privileges ($PRIV):\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 3.$(((NUM3++)))] Check file ($CHK) for correct privileges ($PRIV):\e[1;31m FAILED\e[0m (wrong privileges $CHK_PRIV)"
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req58 $REQ58 "$REQ58_TXT"

# Req 59: Default group for the root account must be GID 0.
let "REQ_NR++"
REQ_TXT="Default group for the root account must be GID 0."
FAIL=0
PASS=0

test_req59 () {
  if [ "$1" == "TRUE" ]; then

    NUM=1
    CHK_GID="$(awk -F':' '{if ($1 == "root") print $4}' /etc/passwd)"
    if [ "$CHK_GID" == "0" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if group for root is GID 0:\e[1;32m PASSED\e[0m";
    else
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if group for root is GID 0:\e[1;31m FAILED\e[0m (wrong GID $CHK_GID)"
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req59 $REQ59 "$REQ59_TXT"

# Req 60: Root must be the only UID 0 account.
let "REQ_NR++"
REQ_TXT="Root must be the only UID 0 account."
FAIL=0
PASS=0

test_req60 () {
  if [ "$1" == "TRUE" ]; then

    NUM=1
    CHK_UID="$(awk -F':' '{ if ( $1 != "root" && $3 == 0 ) print $1 }' /etc/passwd | wc -l)"

    if [ "$CHK_UID" == "0" ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if root is the only account with UID 0:\e[1;32m PASSED\e[0m";
    else
      ERR=1;
      let FAIL=$FAIL+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if root is the only account with UID 0:\e[1;31m FAILED\e[0m (other accounts found)"
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req60 $REQ60 "$REQ60_TXT"

# Req 61: All groups in /etc/passwd must exist in /etc/group.
let "REQ_NR++"
REQ_TXT="All groups in /etc/passwd must exist in /etc/group."
FAIL=0
PASS=0

test_req61 () {
  if [ "$1" == "TRUE" ]; then

    NUM=1
    SEARCH_GROUPS="$(awk -F':' '{print $4}' /etc/passwd | sort -u)"

    for CHK in $SEARCH_GROUPS; do
      CHK_GROUP="$(awk -v var=$CHK -F':' '{if ($3 == var) print $3}' /etc/group | wc -l)"
      if [ $CHK_GROUP -eq 1 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if group from /etc/passwd ($CHK) exists in /etc/group:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if group from /etc/passwd ($CHK) exists in /etc/group:\e[1;31m FAILED\e[0m (group not found)"
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req61 $REQ61 "$REQ61_TXT"

# Req 62: No duplicate UIDs and GIDs must exist.
let "REQ_NR++"
REQ_TXT="No duplicate UIDs and GIDs must exist."
FAIL=0
PASS=0

test_req62 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/2
    NUM=1
    SEARCH_UIDS="$(awk -F':' '{print $3}' /etc/passwd)"
    for CHK in $SEARCH_UIDS; do
      CHK_UID="$(awk -F':' '{if ($3 == '$CHK') print $3}' /etc/passwd | wc -l)"
      if [ $CHK_UID -eq 1 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check in /etc/passwd if UID $CHK exists more than once:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check in /etc/passwd if UID $CHK exists more than once:\e[1;31m FAILED\e[0m (found duplicates)"
      fi
    done

    # Test 2/2
    NUM=1
    SEARCH_GIDS="$(awk -F':' '{print $3}' /etc/group)"
    for CHK in $SEARCH_GIDS; do
      CHK_GID="$(awk -F':' '{if ($3 == '$CHK') print $3}' /etc/group | wc -l)"
      if [ $CHK_GID -eq 1 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check in /etc/group if GID $CHK exists more than once:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check in /etc/group if GID $CHK exists more than once:\e[1;31m FAILED\e[0m (found duplicate)"
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req62 $REQ62 "$REQ62_TXT"

# Req 63: No duplicate user and group names must exist.
let "REQ_NR++"
REQ_TXT="No duplicate user and group names must exist."
FAIL=0
PASS=0

test_req63 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/2
    NUM=1
    SEARCH_USERS="$(awk -F':' '{print $1}' /etc/passwd)"
    for CHK in $SEARCH_USERS; do
      CHK_USER="$(awk -v chk="$CHK" -F':' '{if ($1 == chk) print $1}' /etc/passwd | wc -l)"
      if [ $CHK_USER -eq 1 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check in /etc/passwd if user $CHK exists more than once:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))]  Check in /etc/passwd if user $CHK exists more than once:\e[1;31m FAILED\e[0m (found duplicate)"
      fi
    done


    # Test 2/2
    NUM=1
    SEARCH_GROUPS="$(awk -F':' '{print $1}' /etc/group)"
    for CHK in $SEARCH_GROUPS; do
      CHK_GROUP="$(awk -v chk="$CHK" -F':' '{if ($1 == chk) print $1}' /etc/group | wc -l)"
      if [ $CHK_GROUP -eq 1 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check in /etc/group if group $CHK exists more than once:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check in /etc/group if group $CHK exists more than once:\e[1;31m FAILED\e[0m (found duplicate)"
      fi
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req63 $REQ63 "$REQ63_TXT"

# Req 64: The shadow group must be empty (only Ubuntu Linux).
let "REQ_NR++"
REQ_TXT="The shadow group must be empty (only Ubuntu Linux)."
FAIL=0
PASS=0

test_req64 () {
  if [ "$1" == "TRUE" ]; then

    if [ "$OS" == "ubuntu" ] ; then
      # Test 1/2
      NUM=1
      CHK_SHADOW="$(awk -F':' '{if ($1 == "shadow") print $4}' /etc/group)"
      if [ "$CHK_SHADOW" == "" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if shadow group in /etc/group is empty:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if shadow group in /etc/group is empty:\e[1;31m FAILED\e[0m (group has users)"
      fi

      # Test 2/2
      NUM=1
      CHK_GID="$(awk -F':' '{if ($1 == "shadow") print $3}' /etc/group)"
      CHK_PASSWD="$(awk -v chk="CHK_GID" -F':' '{ if ($4 == chk) print $4}' /etc/passwd | wc -l)"
      if [ $CHK_PASSWD -eq 0 ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check /etc/passwd if user is member in shadow group:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check /etc/passwd if user is member in shadow group:\e[1;31m FAILED\e[0m (user with group shadow found)"
      fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

    else
      echo -e "[Req-$REQ_NR: Test 0.0] Check /etc/passwd if user is member in shadow group: n/a (only Ubuntu)";
      echo "Req $REQ_NR;$REQ_TXT;Not Applicable">&3;
    fi

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req64 $REQ64 "$REQ64_TXT"

# Req 65: No files and directories without assigned user or group must exist.
let "REQ_NR++"
REQ_TXT="No files and directories without assigned user or group must exist."
FAIL=0
PASS=0

test_req65 () {
  if [ "$1" == "TRUE" ]; then

    # Test 1/2
    NUM=1
    SEARCH_FILES="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nouser)"
    if [ -z $SEARCH_FILES ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if directories without assigned user exist:\e[1;32m PASSED\e[0m";
    else
      #ERR=1;
      for CHK in $SEARCH_FILES; do
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if directories without assigned user exist:\e[1;31m FAILED\e[0m (found $CHK)"
      done
    fi

    # Test 2/2
    NUM=1
    SEARCH_DIRS="$(df --local -P | awk {'if (NR!=1) print $6'} | xargs -I '{}' find '{}' -xdev -nogroup)"
    if [ -z $SEARCH_DIRS ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if directories without assigned group exist:\e[1;32m PASSED\e[0m";
    else
      #ERR=1;
      for CHK in $SEARCH_DIRS; do
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if directories without assigned group exist:\e[1;31m FAILED\e[0m (found $CHK)"
      done
    fi

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req65 $REQ65 "$REQ65_TXT"

# Req 66: Permissions of security relevant configuration files must have the distribution default values or more restrictive.
let "REQ_NR++"
REQ_TXT="Permissions of security relevant configuration files must have the distribution default values or more restrictive."
FAIL=0
PASS=0
NUM1=1
NUM2=1
NUM3=1

test_req66 () {
  if [ "$1" == "TRUE" ]; then

    if [ "$OS" == "ubuntu" ] ; then
    OS="$(echo $OS | tr '[:lower:]' '[:upper:]')"
    SYSOS=$OS$MAJOR_VERSION
    else
    SYSOS=$OS_MAIN_DISTRO
    fi

    FILE_1="/etc/passwd"
    FILE_2="/etc/passwd"
    FILE_3="/etc/shadow"
    FILE_4="/etc/shadow-"
    FILE_5="/etc/group"
    FILE_6="/etc/group-"
    FILE_7="$FILE_GRUB"
    FILE_8="/etc/sysctl.conf"
    FILE_9="/etc/ssh/sshd_config"
    FILE_10="/etc/gshadow"  # not used with Suse
    FILE_11="/etc/gshadow-" # not used with Suse
    if [ "$OS_MAIN_DISTRO" == "SUSE" ]; then CNT_TOTAL=9; else CNT_TOTAL=11; fi

    CNT=1
    FILE=FILE_$CNT
    FILE_SET=FILE_SET_$SYSOS$CNT

    while [ $CNT -le $CNT_TOTAL ]; do
      PRIV="$(echo ${!FILE_SET} | awk '{print $1}')"
      USER="$(echo ${!FILE_SET} | awk '{print $2}')"
      GROUP="$(echo ${!FILE_SET} | awk '{print $3}')"

      # Test 1/3
      CHK_USER="$(stat -c %U ${!FILE})"
      if [ "$CHK_USER" == "$USER" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check file (${!FILE}) for correct user $USER:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check file (${!FILE}) for correct user $USER:\e[1;31m FAILED\e[0m (wrong user $CHK_USER)"
      fi

      # Test 2/3
      CHK_GRP="$(stat -c %G ${!FILE})"
      if [ "$CHK_GRP" == "$GROUP" ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check file (${!FILE}) for correct group $GROUP:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check file (${!FILE}) for correct group $GROUP:\e[1;31m FAILED\e[0m (wrong group $CHK_GRP)"
      fi

      # Test 3/3
      CHK_PRIV="$(stat -c %a ${!FILE})"
      if [ $CHK_PRIV -le $PRIV ]; then
        let PASS=$PASS+1;
        echo -e "[Req-$REQ_NR: Test 3.$(((NUM3++)))] Check file (${!FILE}) for correct privileges $PRIV:\e[1;32m PASSED\e[0m";
      else
        ERR=1;
        let FAIL=$FAIL+1;
        echo -e "[Req-$REQ_NR: Test 3.$(((NUM3++)))] Check file (${!FILE}) for correct privileges $PRIV:\e[1;31m FAILED\e[0m (wrong privledges $CHK_PRIV)"
      fi
      
      let CNT++
      FILE=FILE_$CNT;
      FILE_SET=FILE_SET_$SYSOS$CNT;
    done

    let CNT_ERRORS=$CNT_ERRORS+$FAIL
    let CNT_PASSED=$CNT_PASSED+$PASS
    write_to_soc $FAIL $PASS 

  else
    echo -e "[Req-$REQ_NR: Test 0.0] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
    echo "Req $REQ_NR;$REQ_TXT;Not Applicable;$2">&3;
    let CNT_SKIP=$CNT_SKIP+1 
  fi
}

test_req66 $REQ66 "$REQ66_TXT"

# Req 67: If passwords are used as an authentication attribute, those must be stored using a suitable and approved "Password Hashing" method to protect against offline-attacks like brute force or dictionary attacks.
let "REQ_NR++"
REQ_TXT="If passwords are used as an authentication attribute, those must be stored using a suitable and approved 'Password Hashing' method to protect against offline-attacks like brute force or dictionary attacks."
FAIL=0
PASS=0

echo -e "[Req-$REQ_NR: Test 0.0] Check for password encryption: SKIPPED (n/a: duplicate req. (see req. 42)!)"
echo "Req $REQ_NR;$REQ_TXT;Not Applicable;Duplicate requirement! Implemented with Req. 42">&3;

let CNT_SKIP=$CNT_SKIP+$SKIP

# -----------------------------------------------------------------------------
# Output result of Test script
# -----------------------------------------------------------------------------

CNT_TOTAL=0
let CNT_TOTAL=$CNT_PASSED+$CNT_ERRORS+$CNT_SKIP
echo -e "... Testing finished\n"
echo -e "-------------------------------------------------------------------------------"
echo "SUMMARY ($OS_NAME $OS_VERSION)"
echo -e "-------------------------------------------------------------------------------"
echo -e "Test Cases: $CNT_TOTAL  |  Passed: \e[1;32m$CNT_PASSED\e[0m  |  Failed: \e[1;31m$CNT_ERRORS\e[0m  |  Skipped: $CNT_SKIP\n"

# -----------------------------------------------------------------------------
# Set error code in case of one or more failed checks
# -----------------------------------------------------------------------------

chmod 444 compliance-* 2>/dev/null

if [ "$ERR" == "1" ]; then
  exit 1
else
  exit 0
fi
