#!/bin/bash

# tel-it-security-automation :- Ansible roles for automated security hardening.  
# Copyright (c) 2019 Markus Schumburg, [...] Deutsche Telekom AG 
# contact: devsecops@telekom.de 
# This file is distributed under the conditions of the Apache-2.0 license. 
# For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.

# -----------------------------------------------------------------------------
# Telekom Security - Script for Compliance Check
# SSH (3.04)
# Version: 0.9
# Date: 22-01-20 
# -----------------------------------------------------------------------------

# -----------------------------------------------------------------------------
# Variables
# -----------------------------------------------------------------------------
SSH_CONFIG="/etc/ssh/sshd_config"
PROTOCOL_VERSION=2
MODULI_MIN=2048
KEYEX1="curve25519-sha256@libssh.org"
KEYEX2="diffie-hellman-group-exchange-sha256"
KEYEX3="ecdh-sha2-nistp521"
KEYEX4="ecdh-sha2-nistp384"
KEYEX5="ecdh-sha2-nistp256"
CIPHER1="chacha20-poly1305@openssh.com"
CIPHER2="aes256-gcm@openssh.com"
CIPHER3="aes128-gcm@openssh.com"
CIPHER4="aes256-ctr"
CIPHER5="aes192-ctr"
CIPHER6="aes128-ctr"
MAC1="hmac-sha2-512-etm@openssh.com"
MAC2="hmac-sha2-256-etm@openssh.com"
MAC3="hmac-sha2-512"
MAC4="hmac-sha2-256"
LOG_LEVEL="INFO"
LOGIN_GRACE_TIME=60
MAX_AUTH_TRIES=5
PERMIT_ROOT=no
STRICT_MODES=yes
PUB_KEY_AUTH=yes
PASS_AUTH=no
IGNORE_RHOSTS=yes
HOST_BASED_AUTH=no
ALLOW_GROUPS=""
CLIENT_ALIVE_INT=300
CLIENT_ALIVE_CNT=0
PERMIT_TUNNEL=no
TCP_FORWARDING=no
AGENT_FORWARDING=no
GATEWAY_PORTS=no
X11_FORWARDING=no
PERMIT_USER_ENV=no
PERMIT_EMPTY_PW=no
SFTP_LOG_LEVEL="INFO"
SFTP_GROUP="sftpusr"
SFTP_CHROOT_DIR="/home/%u"
SFTP_TCP_FORWARDING=no
SFTP_AGENT_FORWARDING=no
SFTP_PASS_AUTH=no
SFTP_PERMIT_ROOT=no
SFTP_X11_FORWARDING=no

# -----------------------------------------------------------------------------
# Output File Configuration
# -----------------------------------------------------------------------------
DAY=`date +"%d%m%y"`
OUT_FILE="compliance-ssh-$DAY.log"
OUT_CSV="compliance-ssh-$DAY.csv"

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
      PACKAGE="rpm -qa";
      ERR=0;
   elif [ "$OS" == "debian" ] || [ "$OS" == "ubuntu" ]; then
      PACKAGE="apt list --installed";
      ERR=0;
      # PACKAGE="dpkg -l";
   elif [ "$OS" == "sles" ]; then
     PACKAGE="rpm -qa";
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

SSH_VER="$( 2>&1 ssh -V | awk -F_ '{print $2}' | egrep -o "^.{3}")"

echo "-------------------------------------------------------------------------------"
echo " Telekom Security - Compliance Check - SSH (3.04)"
echo "-------------------------------------------------------------------------------"
echo "   Host: "$HOSTNAME
echo "   Date: "$(date +"%d-%m-%y")
echo "   OS: "$OS_NAME
echo "   Version: "$OS_VERSION
echo "   SSH Version: "$SSH_VER
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

# Check if OpenSSH is installed
TXT="Check if OpenSSH is installed"  
CHK_SSH="$($PACKAGE | grep -ow openssh)"
if [ -z "$CHK_SSH" ]; then 
  ERR=1;
  ERR_TXT="Not installed"
else 
  ERR=0; 
fi
write_error $ERR "$TXT" "$ERR_TXT"

# Check first if SSH deamon is running.
TXT="Check if SSH deamon is running"  
CHK_SSH="$(ps -A | grep -ow 'sshd*$' | wc -l)"
if [ $CHK_SSH -eq 0 ]; then ERR=1; else ERR=0; ERR_TXT="Not running"; fi
write_error $ERR "$TXT" "$ERR_TXT"

# -----------------------------------------------------------------------------
# Function
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

# Req 1: The SSH protocol version 2 must be used.
let "REQ_NR++"
REQ_TXT="The SSH protocol version 2 must be used."
FAIL=0
PASS=0

# Test 1/1
SSH_VER_NEW="7.4"
NUM=1
if [ "$(echo $SSH_VER | awk -F. '{print $1}')" -gt "$(echo $SSH_VER_NEW | awk -F. '{print $1}')" ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check ssh protocol version:\e[1;32m PASSED\e[0m";
elif [ "$(echo $SSH_VER | awk -F. '{print $1}')" -ge "$(echo $SSH_VER_NEW | awk -F. '{print $1}')" ] && 
     [ "$(echo $SSH_VER | awk -F. '{print $2}')" -ge "$(echo $SSH_VER_NEW | awk -F. '{print $2}')" ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check ssh protocol version:\e[1;32m PASSED\e[0m";
else
  if [ $(grep -i "^Protocol $PROTOCOL_VERSION$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    let PASS=$PASS+1;
    echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if protocol version $PROTOCOL_VERSION:\e[1;32m PASSED\e[0m";
  else
    let FAIL=$FAIL+1;
    ERR=1;
    echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if protocol version $PROTOCOL_VERSION:\e[1;31m FAILED\e[0m (incorrect version)";
    
  fi
fi

write_to_soc $FAIL $PASS

# Req 2: SSH moduli smaller than 2048 must not be used.
let "REQ_NR++"
REQ_TXT="SSH moduli smaller than 2048 must not be used."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ -z "$(awk '$5 < $MODULI_MIN' /etc/ssh/moduli)" ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if moduli >= $MODULI_MIN:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check moduli >= $MODULI_MIN:\e[1;31m FAILED\e[0m (found moduli < $MODULI_MIN)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 3: Only approved key exchange algorithms must be used.
let "REQ_NR++"
REQ_TXT="Only approved key exchange algorithms must be used."
FAIL=0
PASS=0
FOUND_KEYEX=""

# Test 1/2
NUM1=1
NUM2=1
if [ -z "$(grep -i ^KexAlgorithms $SSH_CONFIG)" ]; then
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check key exchange algorithms:\e[1;31m FAILED\e[0m (absent KexAlgorithms)";
else
  CNT=1;
  KEYEX=KEYEX$CNT;
  while [ $CNT -lt 6 ]; do
    if [ $(grep -i "${!KEYEX}" $SSH_CONFIG | wc -l) -eq 1 ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check key exchange algorithm ${!KEYEX}:\e[1;32m PASSED\e[0m";
      if [ -z $FOUND_KEYEX ]; then FOUND_KEYEX="${!KEYEX}"; else FOUND_KEYEX="$FOUND_KEYEX,${!KEYEX}"; fi
    else
      let FAIL=$FAIL+1;
      ERR=1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check key exchange algorithm ${!KEYEX}:\e[1;31m FAILED\e[0m (not found)";
    fi
    let CNT++;
    KEYEX=KEYEX$CNT;
  done
  GET_KEYEX="$(awk '/^KexAlgorithms/ {print $2}' $SSH_CONFIG)"
  ORG_IFS=$IFS
  IFS=,
  # Test 2/2
  for CHK in $GET_KEYEX; do
    if [ "$CHK" != "$(echo $FOUND_KEYEX | grep -ow $CHK | sort -u)" ]; then
      let FAIL=$FAIL+1;
      ERR=1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check not allowed key exchange algorithms:\e[1;31m FAILED\e[0m (found incorrect KeyEx:$CHK)";
    fi
  done
  IFS=$ORG_IFS
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 4: Only approved ciphers algorithms must be used.
let "REQ_NR++"
REQ_TXT="Only approved ciphers algorithms must be used."
FAIL=0
PASS=0
FOUND_CIPHERS=""

# Test 1/2
NUM1=1
NUM2=1
if [ -z "$(grep -i ^Ciphers $SSH_CONFIG)" ]; then
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check ciphers:\e[1;31m FAILED\e[0m (absent Ciphers)";
else
  CNT=1
  CIPHERS=CIPHER$CNT
  while [ $CNT -lt 7 ]; do
    if [ $(grep -i "${!CIPHERS}" $SSH_CONFIG | wc -l) -eq 1 ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check ciphers ${!CIPHERS}:\e[1;32m PASSED\e[0m";
      if [ -z $FOUND_CIPHERS ]; then FOUND_CIPHERS="${!CIPHERS}"; else FOUND_CIPHERS="$FOUND_CIPHERS,${!CIPHERS}"; fi
    else
      let FAIL=$FAIL+1;
      ERR=1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check cipher ${!CIPHERS}:\e[1;31m FAILED\e[0m (not found)";
    fi
    let CNT++;
    CIPHERS=CIPHER$CNT;
  done
  GET_CIPHERS="$(awk '/^Ciphers/ {print $2}' $SSH_CONFIG)"
  ORG_IFS=$IFS
  IFS=,
  # Test 2/2
  for CHK in $GET_CIPHERS; do
    if [ "$CHK" != "$(echo $FOUND_CIPHERS | grep -ow $CHK | sort -u)" ]; then
      let FAIL=$FAIL+1;
      ERR=1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check not allowed ciphers:\e[1;31m FAILED\e[0m (found incorrect Cipher:$CHK)";
    fi
  done
  IFS=$ORG_IFS
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 5: Only approved MAC algorithms must be used.
let "REQ_NR++"
REQ_TXT="Only approved MAC algorithms must be used."
FAIL=0
PASS=0
FOUND_MACS=""

# Test 1/2
NUM1=1
NUM2=1
if [ -z "$(grep -i ^MACs $SSH_CONFIG)" ]; then
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check mac algorithms:\e[1;31m FAILED\e[0m (absent MACs)";
else
  CNT=1
  MACS=MAC$CNT
  while [ $CNT -lt 5 ]; do
    if [ $(grep -i "${!MACS}" $SSH_CONFIG | wc -l) -eq 1 ]; then
      let PASS=$PASS+1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check mac algorithm ${!MACS}:\e[1;32m PASSED\e[0m";
      if [ -z $FOUND_MACS ]; then FOUND_MACS="${!MACS}"; else FOUND_MACS="$FOUND_MACS,${!MACS}"; fi
    else
      let FAIL=$FAIL+1;
      ERR=1;
      echo -e "[Req-$REQ_NR: Test 1.$(((NUM1++)))] Check mac algorithm ${!MACS}:\e[1;31m FAILED\e[0m (not found)";
    fi
    let CNT++;
    MACS=MAC$CNT;
  done
  GET_MACS="$(awk '/^MACs/ {print $2}' $SSH_CONFIG)"
  ORG_IFS=$IFS
  IFS=,
  # Test 2/2
  for CHK in $GET_MACS; do
    if [ "$CHK" != "$(echo $FOUND_MACS | grep -o $CHK | sort -u)" ]; then
      let FAIL=$FAIL+1;
      ERR=1;
      echo -e "[Req-$REQ_NR: Test 2.$(((NUM2++)))] Check not allowed mac algorithms:\e[1;31m FAILED\e[0m (found incorrect MAC:$CHK)";
    fi
  done
  IFS=$ORG_IFS
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 6: SSH logging must be enabled.
let "REQ_NR++"
REQ_TXT="SSH logging must be enabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^LogLevel $LOG_LEVEL$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if LogLevel is $LOG_LEVEL:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if LogLevel is $LOG_LEVEL:\e[1;31m FAILED\e[0m (incorrect LogLevel)";
fi

write_to_soc $FAIL $PASS

# Req 7: SSH LoginGraceTime must be set to one minute or less.
let "REQ_NR++"
REQ_TXT="SSH LoginGraceTime must be set to one minute or less."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^LoginGraceTime $LOGIN_GRACE_TIME$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if LoginGraceTime is $LOGIN_GRACE_TIME:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if LoginGraceTime is $LOGIN_GRACE_TIME:\e[1;31m FAILED\e[0m (incorrect time)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 8: SSH MaxAuthTries must be set to 5 or less.
let "REQ_NR++"
REQ_TXT="SSH MaxAuthTries must be set to 5 or less."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^MaxAuthTries $MAX_AUTH_TRIES$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if MaxAuthTries is $MAX_AUTH_TRIES:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if MaxAuthTries is $MAX_AUTH_TRIES:\e[1;31m FAILED\e[0m (incorrect value)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 9: SSH root login must be disabled.
let "REQ_NR++"
REQ_TXT="SSH root login must be disabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^PermitRootLogin $PERMIT_ROOT$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PermitRootLogin is $PERMIT_ROOT:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PermitRootLogin is $PERMIT_ROOT:\e[1;31m FAILED\e[0m (incorrect value)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 10:	SSH strict mode must be enabled.
let "REQ_NR++"
REQ_TXT="SSH strict mode must be enabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^StrictModes $STRICT_MODES$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if StrictModes is $STRICT_MODES:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if StrictModes is $STRICT_MODES:\e[1;31m FAILED\e[0m (disabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 11:	SSH user authentication must be done with public keys.
let "REQ_NR++"
REQ_TXT="SSH user authentication must be done with public keys."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^PubkeyAuthentication $PUB_KEY_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PubkeyAuthentication is $PUB_KEY_AUTH:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PubkeyAuthentication is $PUB_KEY_AUTH:\e[1;31m FAILED\e[0m (disabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 12:	SSH password authentication must be disabled.
let "REQ_NR++"
REQ_TXT="SSH password authentication must be disabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^PasswordAuthentication $PASS_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PasswordAuthentication is $PASS_AUTH:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PasswordAuthentication is $PASS_AUTH:\e[1;31m FAILED\e[0m (enabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 13:	SSH IgnoreRhosts must be enabled.
let "REQ_NR++"
REQ_TXT="SSH IgnoreRhosts must be enabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^IgnoreRhosts $IGNORE_RHOSTS$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if IgnoreRhosts is $IGNORE_RHOSTS:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if IgnoreRhosts is $IGNORE_RHOSTS:\e[1;31m FAILED\e[0m (disabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 14:	SSH HostbasedAuthentication must be disabled.
let "REQ_NR++"
REQ_TXT="SSH HostbasedAuthentication must be disabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^HostbasedAuthentication $HOST_BASED_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if HostbasedAuthentication is $HOST_BASED_AUTH:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if HostbasedAuthentication is $HOST_BASED_AUTH:\e[1;31m FAILED\e[0m (enabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 15:	The usage of the SSH service must be restricted to dedicated groups
# or users.
let "REQ_NR++"
REQ_TXT="The usage of the SSH service must be restricted to dedicated groups or users."
FAIL=0
PASS=0

# Test 1/2
NUM=1
for CHK in AllowUsers DenyGroups DenyUsers; do
  if [ -z "$(grep -i "^$CHK" $SSH_CONFIG)" ]; then
    let PASS=$PASS+1;
    echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if $CHK exists:\e[1;32m PASSED\e[0m"
  else
    let FAIL=$FAIL+1;
    ERR=1;
    echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if $CHK exists:\e[1;31m FAILED\e[0m (entry exists)"
  fi
done

# Test 2/2
NUM=1
if [ ! -z $ALLOWGROUPS ]; then SSH="$SSH_GROUP $ALLOWGROUPS"; fi
CHK_GROUPS=$(awk '/AllowGroups/ {$1=""; print}' /etc/ssh/sshd_config | sed -e 's/^[ \t]*//')

for CHK in $CHK_GROUPS; do
  if [ "$CHK" == "$(echo $SSH_GROUP | grep -ow $CHK)" ]; then
    let PASS=$PASS+1;
    echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check AllowGroups:\e[1;32m PASSED\e[0m";
  else
    let FAIL=$FAIL+1;
    ERR=1;
    echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check AllowGroups:\e[1;31m FAILED\e[0m (group $CHK unknown)";
  fi
done

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 16:	The SSH Idle Timeout Interval must be configured to an adequate time.
let "REQ_NR++"
REQ_TXT="The SSH Idle Timeout Interval must be configured to an adequate time."
FAIL=0
PASS=0

# Test 1/2
NUM=1
if [ $(grep -i "^ClientAliveInterval $CLIENT_ALIVE_INT$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if ClientAliveInterval is $CLIENT_ALIVE_INT:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if ClientAliveInterval is $CLIENT_ALIVE_INT:\e[1;31m FAILED\e[0m (wrong interval)";
fi

# Test 2/2
NUM=1
if [ $(grep -i "^ClientAliveCountMax $CLIENT_ALIVE_CNT$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if ClientAliveCountMax is $CLIENT_ALIVE_CNT:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 2.$(((NUM++)))] Check if ClientAliveCountMax is $CLIENT_ALIVE_CNT:\e[1;31m FAILED\e[0m (incorrect value)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 17:	SSH tunnel devices must be disabled.
let "REQ_NR++"
REQ_TXT="SSH tunnel devices must be disabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^PermitTunnel $PERMIT_TUNNEL$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PermitTunnel is $PERMIT_TUNNEL:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PermitTunnel is $PERMIT_TUNNEL:\e[1;31m FAILED\e[0m (enabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 18:	SSH TCP port forwarding must be disabled.
let "REQ_NR++"
REQ_TXT="SSH TCP port forwarding must be disabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^AllowTcpForwarding $TCP_FORWARDING$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if AllowTcpForwarding is $TCP_FORWARDING:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if AllowTcpForwarding is $TCP_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 19:	SSH agent forwarding must be disabled.
let "REQ_NR++"
REQ_TXT="SSH agent forwarding must be disabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^AllowAgentForwarding $AGENT_FORWARDING$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if AllowAgentForwarding is $AGENT_FORWARDING:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if AllowAgentForwarding is $AGENT_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 20:	SSH gateway ports must be disabled.
let "REQ_NR++"
REQ_TXT="SSH gateway ports must be disabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^GatewayPorts $GATEWAY_PORTS$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if GatewayPorts is $GATEWAY_PORTS:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if GatewayPorts is $GATEWAY_PORTS:\e[1;31m FAILED\e[0m (enabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 21:	SSH X11 forwarding must be disabled.
let "REQ_NR++"
REQ_TXT="SSH X11 forwarding must be disabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^X11Forwarding $X11_FORWARDING$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if X11Forwarding is $X11_FORWARDING:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if X11Forwarding is $X11_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 22:	SSH PermitUserEnvironment must be disabled.
let "REQ_NR++"
REQ_TXT="SSH PermitUserEnvironment must be disabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^PermitUserEnvironment $PERMIT_USER_ENV$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PermitUserEnvironment is $PERMIT_USER_ENV:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PermitUserEnvironment is $PERMIT_USER_ENV:\e[1;31m FAILED\e[0m (enabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 23:	SSH PermitEmptyPasswords must be disabled.
let "REQ_NR++"
REQ_TXT="SSH PermitEmptyPasswords must be disabled."
FAIL=0
PASS=0

# Test 1/1
NUM=1
if [ $(grep -i "^PermitEmptyPasswords $PERMIT_EMPTY_PW$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PermitEmptyPasswords is $PERMIT_EMPTY_PW:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1.$(((NUM++)))] Check if PermitEmptyPasswords is $PERMIT_EMPTY_PW:\e[1;31m FAILED\e[0m (enabled)";
fi

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# Req 24:	If SFTP is activated, internal server of OpenSSH must be used.
let "REQ_NR++"
REQ_TXT="If SFTP is activated, internal server of OpenSSH must be used."
FAIL=0
PASS=0
TMP_FILE="/tmp/sftp_cnf.tmp"

# Test 1/9
NUM=1
if [ $(grep -i "Subsystem sftp internal-sftp -l $SFTP_LOG_LEVEL$" $SSH_CONFIG | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 1/9] Check if SFTP subsystem exists:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 1/9] Check if SFTP subsystem exists:\e[1;31m FAILED\e[0m (not found)";
fi

# Test 2/9
NUM=1
LINE_NUM=$(grep -n "Match Group" $SSH_CONFIG | awk '{print $1}' FS=":")

if [ -z $LINE_NUM ]; then
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 2/9] Check for SFTP chroot settings:\e[1;31m FAILED\e[0m (not found)";
else
  let PASS=$PASS+1;
  let END_LINE=$LINE_NUM+8;
  sed -n -e "$LINE_NUM","$END_LINE"p $SSH_CONFIG > $TMP_FILE
  echo -e "[Req-$REQ_NR: Test 2/9] Check for SFTP chroot settings:\e[1;32m PASSED\e[0m";
fi 

# Test 3/9
NUM=1
if [ $(grep -i "ForceCommand internal-sftp -l $SFTP_LOG_LEVEL$" $TMP_FILE | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 3/9] Check if SSH LogLevel is $SFTP_LOG_LEVEL:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 3/9] Check if SSH LogLevel is $SFTP_LOG_LEVEL::\e[1;31m FAILED\e[0m (wrong log level)";
fi

# Test 4/9
NUM=1
if [ $(grep -i "ChrootDirectory $SFTP_CHROOT_DIR$" $TMP_FILE | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 4/9] Check if ChrootDirectory is $SFTP_CHROOT_DIR:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 4/9] Check if ChrootDirectory is $SFTP_CHROOT_DIR:\e[1;31m FAILED\e[0m (missing)";
fi

# Test 5/9
NUM=1
if [ $(grep -i "AllowTcpForwarding $SFTP_TCP_FORWARDING$" $TMP_FILE | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 5/9] Check if AllowTcpForwarding is $SFTP_TCP_FORWARDING:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 5/9] Check if AllowTcpForwarding is $SFTP_TCP_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
fi

# Test 6/9
NUM=1
if [ $(grep -i "AllowAgentForwarding $SFTP_AGENT_FORWARDING$" $TMP_FILE | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 6/9] Check if AllowAgentForwarding is $SFTP_AGENT_FORWARDING:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 6/9] Check if AllowAgentForwarding is $SFTP_AGENT_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
fi

# Test 7/9
NUM=1
if [ $(grep -i "PasswordAuthentication $SFTP_PASS_AUTH$" $TMP_FILE | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 7/9] Check if PasswordAuthentication is $SFTP_PASS_AUTH:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 7/9] Check if PasswordAuthentication is $SFTP_PASS_AUTH:\e[1;31m FAILED\e[0m (enabled)";
fi

# Test 8/9
NUM=1
if [ $(grep -i "PermitRootLogin $SFTP_PERMIT_ROOT$" $TMP_FILE | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 8/9] Check if PermitRootLogin is $SFTP_PERMIT_ROOT:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 8/9] Check if PermitRootLogin is $SFTP_PERMIT_ROOT:\e[1;31m FAILED\e[0m (enabled)";
fi

# Test 9/9
NUM=1
if [ $(grep -i "X11Forwarding $SFTP_X11_FORWARDING$" $TMP_FILE | wc -l) -eq 1 ]; then
  let PASS=$PASS+1;
  echo -e "[Req-$REQ_NR: Test 9/9] Check if X11Forwarding is $SFTP_X11_FORWARDING:\e[1;32m PASSED\e[0m";
else
  let FAIL=$FAIL+1;
  ERR=1;
  echo -e "[Req-$REQ_NR: Test 9/9] Check if X11Forwarding is $SFTP_X11_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
fi

rm $TMP_FILE 2>/dev/null

let CNT_ERRORS=$CNT_ERRORS+$FAIL;
let CNT_PASSED=$CNT_PASSED+$PASS;
write_to_soc $FAIL $PASS

# -----------------------------------------------------------------------------
# Output result of Test script
# -----------------------------------------------------------------------------

CNT_TOTAL=0
let CNT_TOTAL=$CNT_PASSED+$CNT_ERRORS+$CNT_SKIP
echo -e "...Testing finished\n"
echo "-------------------------------------------------------------------------------"
echo "SUMMARY ($OS_NAME $OS_VERSION)"
echo "-------------------------------------------------------------------------------"
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