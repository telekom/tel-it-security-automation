#!/bin/bash

# tel-it-security-automation :- Ansible roles for automated security hardening.  
# Copyright (c) 2020 Maximilian Hertstein, [...] Deutsche Telekom AG 
# contact: devsecops@telekom.de 
# This file is distributed under the conditions of the Apache-2.0 license. 
# For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.

# -----------------------------------------------------------------------------
# Deutsche Telekom IT GmbH (DevSecOps Team)
# Script for Compliance Check - SSH (3.04, v2.7, 01.07.2020)
# Version: 1.1
# Date: 23.07.2020 
# -----------------------------------------------------------------------------
TEST_NAME="ssh"

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
  
  # -------------------------------------------------------------------------
  # Test case specific pre-checks
  # -------------------------------------------------------------------------

  # Check if OpenSSH is installed
  TXT="Check if OpenSSH is installed"  
  CHK_SSH="$($PACKAGE 2>/dev/null | grep -ow openssh)"
  if [ -z "$CHK_SSH" ]; then 
    ERR_CODE=1;
    ERR_TXT="Not installed"
  else
    ERR_CODE=0;
  fi
  write_error $ERR_CODE "$TXT" "$ERR_TXT"

  # Check first if SSH deamon is running.
  TXT="Check if SSH deamon is running"  
  CHK_SSH="$(ps -A | grep -ow 'sshd*$' | wc -l)"
  if [ $CHK_SSH -eq 0 ]; then ERR_CODE=1; ERR_TXT="Not running"; else ERR_CODE=0; fi
  write_error $ERR_CODE "$TXT" "$ERR_TXT"

  # ---------------------------------------------------------------------------
  # Define and load input file with custom variables
  # ---------------------------------------------------------------------------
  INPUT_VARS_FILE="vars_custom_$TEST_NAME.sh"
  read_variables $INPUT_VARS_FILE
fi 

# -----------------------------------------------------------------------------
# Linux distro specific variables
# -----------------------------------------------------------------------------

SSH_CONFIG="/etc/ssh/sshd_config"

# -----------------------------------------------------------------------------
# Variables for test cases
# -----------------------------------------------------------------------------

# NOTE!
# Variables marked wit '# default' can be overwritten by customer in input file
# with custom variables. Change of all othe variables has effect on security
# compliance!

# Req 1: The SSH protocol version 2 must be used.
PROTOCOL_VERSION=2
# NOTE! with SSH version 7.4 the variable for protocol version is depricated.
SSH_VER_NEW="7.4"

# Req 2: SSH moduli smaller than 2048 must not be used.
MODULI_MIN=2048

# Req 3: Only approved key exchange algorithms must be used.
KEYEX1="curve25519-sha256@libssh.org"
KEYEX2="diffie-hellman-group-exchange-sha256"
KEYEX3="ecdh-sha2-nistp521"
KEYEX4="ecdh-sha2-nistp384"
KEYEX5="ecdh-sha2-nistp256"

# Req 4: Only approved ciphers algorithms must be used.
CIPHER1="chacha20-poly1305@openssh.com"
CIPHER2="aes256-gcm@openssh.com"
CIPHER3="aes128-gcm@openssh.com"
CIPHER4="aes256-ctr"
CIPHER5="aes192-ctr"
CIPHER6="aes128-ctr"

# Req 5: Only approved MAC algorithms must be used.
MAC1="hmac-sha2-512-etm@openssh.com"
MAC2="hmac-sha2-256-etm@openssh.com"
MAC3="hmac-sha2-512"
MAC4="hmac-sha2-256"

# Req 6: Only approved Host Key Algorithms (a.k.a. public key signature algorithms 
#        or server authentication algorithms) must be used.
HKA1="ecdsa-sha2-nistp256-cert-v01@openssh.com"
HKA2="ecdsa-sha2-nistp384-cert-v01@openssh.com"
HKA3="ecdsa-sha2-nistp521-cert-v01@openssh.com"
HKA4="ecdsa-sha2-nistp256"
HKA5="ecdsa-sha2-nistp384"
HKA6="ecdsa-sha2-nistp521"

# Req 7: SSH logging must be enabled.
LOG_LEVEL="INFO"

# Req 8: SSH LoginGraceTime must be set to one minute or less.
LOGIN_GRACE_TIME=60

# Req 9: SSH MaxAuthTries must be set to 5 or less.
MAX_AUTH_TRIES=5

# Req 10: SSH root login must be disabled.
PERMIT_ROOT=no

# Req 11:	SSH strict mode must be enabled.
STRICT_MODES=yes

# Req 12:	SSH user authentication must be done with public keys.
PUB_KEY_AUTH=yes

# Req 13:	SSH password authentication must be disabled.
PASS_AUTH=no

# Req 14:	SSH IgnoreRhosts must be enabled.
IGNORE_RHOSTS=yes

# Req 15:	SSH HostbasedAuthentication must be disabled.
HOST_BASED_AUTH=no

# Req 16:	The usage of the SSH service must be restricted to dedicated groups
# or users.
if [ ! "$ALLOW_GROUPS" ]; then ALLOW_GROUPS="ssh"; fi        # default

# Req 17:	The SSH Idle Timeout Interval must be configured to an adequate time.
if [ ! "$CLIENT_ALIVE_INT" ]; then CLIENT_ALIVE_INT=60; fi  # default
if [ ! "$CLIENT_ALIVE_CNT" ]; then CLIENT_ALIVE_CNT=10; fi    # default

# Req 18:	SSH tunnel devices must be disabled.
PERMIT_TUNNEL=no

# Req 19:	SSH TCP port forwarding must be disabled.
TCP_FORWARDING=no

# Req 20:	SSH agent forwarding must be disabled.
AGENT_FORWARDING=no

# Req 21:	SSH gateway ports must be disabled.
GATEWAY_PORTS=no

# Req 22:	SSH X11 forwarding must be disabled.
X11_FORWARDING=no

# Req 23:	SSH PermitUserEnvironment must be disabled.
PERMIT_USER_ENV=no

# Req 24:	SSH PermitEmptyPasswords must be disabled.
PERMIT_EMPTY_PW=no

# Req 25:	If SFTP is activated, internal server of OpenSSH must be used.
SFTP_LOG_LEVEL="$LOG_LEVEL"
SFTP_GROUP="sftpusr"
SFTP_CHROOT_DIR="/home/%u"
SFTP_TCP_FORWARDING=no
SFTP_AGENT_FORWARDING=no
SFTP_PASS_AUTH=no
SFTP_PERMIT_ROOT=no
SFTP_X11_FORWARDING=no

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
echo " Compliance Checks - SSH (3.04)"
echo "==============================================================================="
echo -e "Start testing ..."
REQ_NR=0

# Req 1: The SSH protocol version 2 must be used.
REQ_TXT="The SSH protocol version 2 must be used."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  SSH_VER="$( 2>&1 ssh -V | awk -F_ '{print $2}' | egrep -o "^.{3}")"
  if [ "$(echo $SSH_VER | awk -F. '{print $1}')" -gt "$(echo $SSH_VER_NEW | awk -F. '{print $1}')" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check ssh protocol version:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  elif [ "$(echo $SSH_VER | awk -F. '{print $1}')" -ge "$(echo $SSH_VER_NEW | awk -F. '{print $1}')" ] && 
       [ "$(echo $SSH_VER | awk -F. '{print $2}')" -ge "$(echo $SSH_VER_NEW | awk -F. '{print $2}')" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check ssh protocol version:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    if [ $(grep -i "^Protocol $PROTOCOL_VERSION$" $SSH_CONFIG | wc -l) -eq 1 ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if protocol version $PROTOCOL_VERSION:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if protocol version $PROTOCOL_VERSION:\e[1;31m FAILED\e[0m (incorrect version)";
      ERR_MSG="Wrong SSH protocol version 1";
      let FAIL=$FAIL+1;
      ERR=1;
      
    fi
  fi
  echo -e "\t\e[33mNOTE!\e[0m SSH software version detected: $SSH_VER."
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 2: SSH moduli smaller than 2048 must not be used.
REQ_TXT="SSH moduli smaller than 2048 must not be used."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ -z "$(awk '$5 < $MODULI_MIN' /etc/ssh/moduli)" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if moduli >= $MODULI_MIN:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check moduli >= $MODULI_MIN:\e[1;31m FAILED\e[0m (found moduli < $MODULI_MIN)";
    ERR_MSG="modulis smaller $MODULI_MIN";
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

# Req 3: Only approved key exchange algorithms must be used.
REQ_TXT="Only approved key exchange algorithms must be used."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ -z "$(grep -i ^KexAlgorithms $SSH_CONFIG)" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check key exchange algorithms:\e[1;31m FAILED\e[0m (absent KexAlgorithms)";
    ERR_MSG="No config for key exchange algorithms found";
    let FAIL=$FAIL+1;
    ERR=1;
  else
    
    CNT=1;
    KEYEX=KEYEX$CNT;
    GET_KEYEX="$(awk '/^KexAlgorithms/ {print $2}' $SSH_CONFIG)"
    ORG_IFS=$IFS
    IFS=,
    ERR_MSG="Missing algorithm(s):";
    while [ $CNT -le 5 ]; do
      FOUND=0;
      for CHK_KEYEX in $GET_KEYEX; do
        if [ "$CHK_KEYEX" == "${!KEYEX}" ]; then let FOUND=1; fi
      done
      if [ $FOUND -eq 1 ]; then
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check key exchange algorithm ${!KEYEX}:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
        if [ -z "$FOUND_KEYEX" ]; then FOUND_KEYEX="${!KEYEX}"; else FOUND_KEYEX="$FOUND_KEYEX,${!KEYEX}"; fi
      else
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check key exchange algorithm ${!KEYEX}:\e[1;31m FAILED\e[0m (not found)";
        ERR_MSG="$ERR_MSG ${!KEYEX},";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
      let CNT++;
      KEYEX=KEYEX$CNT;
    done

    # Test 2/2
    ERR_MSG="$ERR_MSG found incorrect KeyEx:"
    for CHK in $GET_KEYEX; do
      if [ "$CHK" != "$(echo $FOUND_KEYEX | grep -ow $CHK | sort -u)" ]; then
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check not allowed key exchange algorithms:\e[1;31m FAILED\e[0m (found incorrect KeyEx:$CHK)";
        ERR_MSG="$ERR_MSG $CHK";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    done
    IFS=$ORG_IFS
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 4: Only approved ciphers algorithms must be used.
REQ_TXT="Only approved ciphers algorithms must be used."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  if [ -z "$(grep -i ^Ciphers $SSH_CONFIG)" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check ciphers:\e[1;31m FAILED\e[0m (absent Ciphers)";
    ERR_MSG="No config for key chipher algorithms found";
    let FAIL=$FAIL+1;
    ERR=1;
  else

    CNT=1;
    CIPHERS=CIPHER$CNT
    GET_CIPHERS="$(awk '/^Ciphers/ {print $2}' $SSH_CONFIG)"
    ORG_IFS=$IFS
    IFS=,
    ERR_MSG="Missing chipher(s):";
    while [ $CNT -le 6 ]; do
      FOUND=0;
      for CHK_CIPHERS in $GET_CIPHERS; do
        if [ "$CHK_CIPHERS" == "${!CIPHERS}" ]; then let FOUND=1; fi
      done
      if [ $FOUND -eq 1 ]; then
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check ciphers ${!CIPHERS}:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
        if [ -z "$FOUND_CIPHERS" ]; then FOUND_CIPHERS="${!CIPHERS}"; else FOUND_CIPHERS="$FOUND_CIPHERS,${!CIPHERS}"; fi
      else
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check cipher ${!CIPHERS}:\e[1;31m FAILED\e[0m (not found)";
        ERR_MSG="$ERR_MSG ${!CHIPHERS},";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
      let CNT++;
      CIPHERS=CIPHER$CNT;
    done

    # Test 2/2
    ERR_MSG="$ERR_MSG found incorrect chipher(s):"
    for CHK in $GET_CIPHERS; do
      if [ "$CHK" != "$(echo $FOUND_CIPHERS | grep -ow $CHK | sort -u)" ]; then
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check not allowed ciphers:\e[1;31m FAILED\e[0m (found incorrect Cipher:$CHK)";
        ERR_MSG="$ERR_MSG $CHK";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    done
    IFS=$ORG_IFS
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 5: Only approved MAC algorithms must be used.
REQ_TXT="Only approved MAC algorithms must be used."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  if [ -z "$(grep -i ^MACs $SSH_CONFIG)" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check mac algorithms:\e[1;31m FAILED\e[0m (absent MACs)";
    let FAIL=$FAIL+1;
    ERR=1;
  else
    
    CNT=1;
    MACS=MAC$CNT
    GET_MACS="$(awk '/^MACs/ {print $2}' $SSH_CONFIG)"
    ORG_IFS=$IFS
    IFS=,
    ERR_MSG="Missing MAC(s):";
    while [ $CNT -le 4 ]; do
      FOUND=0;
      for CHK_MACS in $GET_MACS; do
        if [ "$CHK_MACS" == "${!MACS}" ]; then let FOUND=1; fi
      done
      if [ $FOUND -eq 1 ]; then
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check mac algorithm ${!MACS}:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
        if [ -z "$FOUND_MACS" ]; then FOUND_MACS="${!MACS}"; else FOUND_MACS="$FOUND_MACS,${!MACS}"; fi
      else
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check mac algorithm ${!MACS}:\e[1;31m FAILED\e[0m (not found)";
        ERR_MSG="$ERR_MSG ${!MACS},";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
      let CNT++;
      MACS=MAC$CNT;
    done

    # Test 2/2
    ERR_MSG="$ERR_MSG found incorrect MAC(s):"
    for CHK in $GET_MACS; do
      if [ "$CHK" != "$(echo $FOUND_MACS | grep -o $CHK | sort -u)" ]; then
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check not allowed mac algorithms:\e[1;31m FAILED\e[0m (found incorrect MAC:$CHK)";
        ERR_MSG="$ERR_MSG $CHK";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    done
    IFS=$ORG_IFS
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 6: Only approved Host Key Algorithms (a.k.a. public key signature algorithms 
#        or server authentication algorithms) must be used.
REQ_TXT="Only approved Host Key Algorithms (a.k.a. public key signature algorithms\n   or server authentication algorithms) must be used."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ -z "$(grep -i ^HostKeyAlgorithms $SSH_CONFIG)" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check host key algorithms:\e[1;31m FAILED\e[0m (absent HostKeyAlgorithm)";
    ERR_MSG="No config for host key algorithms found";
    let FAIL=$FAIL+1;
    ERR=1;
  else
    
    CNT=1;
    HKA=HKA$CNT;
    GET_HKA="$(awk '/^HostKeyAlgorithms/ {print $2}' $SSH_CONFIG)"
    ORG_IFS=$IFS
    IFS=,
    ERR_MSG="Missing algorithm(s):";
    while [ $CNT -le 6 ]; do
      FOUND=0;
      for CHK_HKA in $GET_HKA; do
        if [ "$CHK_HKA" == "${!HKA}" ]; then let FOUND=1; fi
      done
      if [ $FOUND -eq 1 ]; then
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check host key algorithm ${!HKA}:\e[1;32m PASSED\e[0m";
        let PASS=$PASS+1;
        if [ -z "$FOUND_HKA" ]; then FOUND_HKA="${!HKA}"; else FOUND_HKA="$FOUND_HKA,${!HKA}"; fi
      else
        echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check host key algorithm ${!HKA}:\e[1;31m FAILED\e[0m (not found)";
        ERR_MSG="$ERR_MSG ${!HKA},";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
      let CNT++;
      HKA=HKA$CNT;
    done
    
    # Test 2/2
    ERR_MSG="$ERR_MSG found incorrect HostKeyAlgotithm:"
    for CHK in $GET_HKA; do
      if [ "$CHK" != "$(echo $FOUND_HKA | grep -ow $CHK | sort -u)" ]; then
        echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check not allowed host key algorithms:\e[1;31m FAILED\e[0m (found incorrect HostKeyAlgorithm: $CHK)";
        ERR_MSG="$ERR_MSG $CHK";
        let FAIL=$FAIL+1;
        ERR=1;
      fi
    done
    IFS=$ORG_IFS
  fi
  TXT="$ERR_MSG"
else
  echo -e "   [Test -.--] Checks for requirement $REQ_NR disabled: SKIPPED (N/A)"
  SKIP=1;
  TXT="${!REMARK}";
fi
  
write_to_soc $FAIL $PASS $SKIP "$TXT"

# Req 7: SSH logging must be enabled.
REQ_TXT="SSH logging must be enabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^LogLevel $LOG_LEVEL$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if LogLevel is $LOG_LEVEL:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if LogLevel is $LOG_LEVEL:\e[1;31m FAILED\e[0m (incorrect LogLevel)";
    ERR_MSG="wrong log level";
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

# Req 8: SSH LoginGraceTime must be set to one minute or less.
REQ_TXT="SSH LoginGraceTime must be set to one minute or less."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^LoginGraceTime $LOGIN_GRACE_TIME$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if LoginGraceTime is $LOGIN_GRACE_TIME:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if LoginGraceTime is $LOGIN_GRACE_TIME:\e[1;31m FAILED\e[0m (incorrect time)";
    ERR_MSG="wrong value for LoginGraceTime";
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

# Req 9: SSH MaxAuthTries must be set to 5 or less.
REQ_TXT="SSH MaxAuthTries must be set to 5 or less."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^MaxAuthTries $MAX_AUTH_TRIES$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if MaxAuthTries is $MAX_AUTH_TRIES:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if MaxAuthTries is $MAX_AUTH_TRIES:\e[1;31m FAILED\e[0m (incorrect value)";
    ERR_MSG="wrong value for MaxAuthTries";
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

# Req 10: SSH root login must be disabled.
REQ_TXT="SSH root login must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^PermitRootLogin $PERMIT_ROOT$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PermitRootLogin is $PERMIT_ROOT:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    ERR_MSG="root login is enabled";
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PermitRootLogin is $PERMIT_ROOT:\e[1;31m FAILED\e[0m (incorrect value)";
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

# Req 11:	SSH strict mode must be enabled.
REQ_TXT="SSH strict mode must be enabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^StrictModes $STRICT_MODES$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if StrictModes is $STRICT_MODES:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if StrictModes is $STRICT_MODES:\e[1;31m FAILED\e[0m (disabled)";
    ERR_MSG="StrictModes is diabled";
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

# Req 12:	SSH user authentication must be done with public keys.
REQ_TXT="SSH user authentication must be done with public keys."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^PubkeyAuthentication $PUB_KEY_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PubkeyAuthentication is $PUB_KEY_AUTH:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PubkeyAuthentication is $PUB_KEY_AUTH:\e[1;31m FAILED\e[0m (disabled)";
    ERR_MSG="pubic key authentication is disabled";
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

# Req 13:	SSH password authentication must be disabled.
REQ_TXT="SSH password authentication must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^PasswordAuthentication $PASS_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PasswordAuthentication is $PASS_AUTH:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PasswordAuthentication is $PASS_AUTH:\e[1;31m FAILED\e[0m (enabled)";
    ERR_MSG="password authentication is enabled";
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

# Req 14:	SSH IgnoreRhosts must be enabled.
REQ_TXT="SSH IgnoreRhosts must be enabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^IgnoreRhosts $IGNORE_RHOSTS$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if IgnoreRhosts is $IGNORE_RHOSTS:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if IgnoreRhosts is $IGNORE_RHOSTS:\e[1;31m FAILED\e[0m (disabled)";
    ERR_MSG="ignore rhosts is enabled";
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

# Req 15:	SSH HostbasedAuthentication must be disabled.
REQ_TXT="SSH HostbasedAuthentication must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^HostbasedAuthentication $HOST_BASED_AUTH$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if HostbasedAuthentication is $HOST_BASED_AUTH:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if HostbasedAuthentication is $HOST_BASED_AUTH:\e[1;31m FAILED\e[0m (enabled)";
    ERR_MSG="host based authentication is enabled";
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

# Req 16:	The usage of the SSH service must be restricted to dedicated 
#         groups or users.
REQ_TXT="The usage of the SSH service must be restricted to dedicated\n   groups or users."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  for CHK in AllowUsers DenyGroups DenyUsers; do
    if [ -z "$(grep -i "^$CHK" $SSH_CONFIG)" ]; then
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if $CHK not exists:\e[1;32m PASSED\e[0m"
      let PASS=$PASS+1;
    else
      echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if $CHK not exists:\e[1;31m FAILED\e[0m (entry exists)"
      ERR_MSG="$ERR_MSG $CHK exists,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
  done

  # Test 2/2
  NUM=1
  if [ -n "$ALLOWGROUPS" ]; then SSH="$SSH_GROUP $ALLOWGROUPS"; fi
  CHK_GROUPS=$(awk '/AllowGroups/ {$1=""; print}' /etc/ssh/sshd_config | sed -e 's/^[ \t]*//')
  ERR_MSG="$ERR_MSG wrong group:";
  for CHK in $CHK_GROUPS; do
    if [ "$CHK" == "$(echo $SSH_GROUP | grep -ow $CHK)" ]; then
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check AllowGroups:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check AllowGroups:\e[1;31m FAILED\e[0m (wrong group $CHK)";
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

# Req 17:	The SSH Idle Timeout Interval must be configured to an 
#         adequate time.
REQ_TXT="The SSH Idle Timeout Interval must be configured to an\n   adequate time."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/2
  NUM=1
  CHK_INT="$(awk '/^ClientAliveInterval/ {print $2}' $SSH_CONFIG)";
  if [ "$CHK_INT" == "$CLIENT_ALIVE_INT" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if ClientAliveInterval is $CLIENT_ALIVE_INT:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if ClientAliveInterval is $CLIENT_ALIVE_INT:\e[1;31m FAILED\e[0m (wrong value $CHK_INT)";
    ERR_MSG="wrong value $CHK_INT for CLientAliveInterval,";
    let FAIL=$FAIL+1;
    ERR=1;
  fi

  # Test 2/2
  NUM=1
  CHK_ALIVE="$(awk '/^ClientAliveCountMax/ {print $2}' $SSH_CONFIG)";
  if [ "$CHK_ALIVE" == "$CLIENT_ALIVE_CNT" ]; then
    echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if ClientAliveCountMax is $CLIENT_ALIVE_CNT:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check if ClientAliveCountMax is $CLIENT_ALIVE_CNT:\e[1;31m FAILED\e[0m (wrong value $CHK_ALIVE)";
    ERR_MSG="$ERR_MSG value $CHK_ALIVE ClientAliveCountMax";
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

# Req 18:	SSH tunnel devices must be disabled.
REQ_TXT="SSH tunnel devices must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^PermitTunnel $PERMIT_TUNNEL$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PermitTunnel is $PERMIT_TUNNEL:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PermitTunnel is $PERMIT_TUNNEL:\e[1;31m FAILED\e[0m (enabled)";
    ERR_MSG="tunnel use is enabled";
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

# Req 19:	SSH TCP port forwarding must be disabled.
REQ_TXT="SSH TCP port forwarding must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^AllowTcpForwarding $TCP_FORWARDING$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if AllowTcpForwarding is $TCP_FORWARDING:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if AllowTcpForwarding is $TCP_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
    ERR_MSG="TCP forwarding is enabled";
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

# Req 20:	SSH agent forwarding must be disabled.
REQ_TXT="SSH agent forwarding must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^AllowAgentForwarding $AGENT_FORWARDING$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if AllowAgentForwarding is $AGENT_FORWARDING:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if AllowAgentForwarding is $AGENT_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
    ERR_MSG="agengt frwarding is enabled";
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

# Req 21:	SSH gateway ports must be disabled.
REQ_TXT="SSH gateway ports must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^GatewayPorts $GATEWAY_PORTS$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if GatewayPorts is $GATEWAY_PORTS:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if GatewayPorts is $GATEWAY_PORTS:\e[1;31m FAILED\e[0m (enabled)";
    ERR_MSG="gateway ports are enabled";
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

# Req 22:	SSH X11 forwarding must be disabled.
REQ_TXT="SSH X11 forwarding must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^X11Forwarding $X11_FORWARDING$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if X11Forwarding is $X11_FORWARDING:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if X11Forwarding is $X11_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
    ERR_MSG="X11 forwarding is enabled";
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

# Req 23:	SSH PermitUserEnvironment must be disabled.
REQ_TXT="SSH PermitUserEnvironment must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^PermitUserEnvironment $PERMIT_USER_ENV$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PermitUserEnvironment is $PERMIT_USER_ENV:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PermitUserEnvironment is $PERMIT_USER_ENV:\e[1;31m FAILED\e[0m (enabled)";
    ERR_MSG="PermitUserEnvironment is enabled";
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

# Req 24:	SSH PermitEmptyPasswords must be disabled.
REQ_TXT="SSH PermitEmptyPasswords must be disabled."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  if [ $(grep -i "^PermitEmptyPasswords $PERMIT_EMPTY_PW$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PermitEmptyPasswords is $PERMIT_EMPTY_PW:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if PermitEmptyPasswords is $PERMIT_EMPTY_PW:\e[1;31m FAILED\e[0m (enabled)";
    ERR_MSG="use of empty passwords is enabled";
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

# Req 25:	If SFTP is activated, internal server of OpenSSH must be used.
REQ_TXT="If SFTP is activated, internal server of OpenSSH must be used."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  TMP_FILE="/tmp/sftp_cnf.tmp";
  SKIP_REST=0;

  # Test 1/9
  NUM=1
  if [ $(grep -i "Subsystem sftp internal-sftp -l $SFTP_LOG_LEVEL$" $SSH_CONFIG | wc -l) -eq 1 ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if SFTP subsystem exists:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if SFTP subsystem exists:\e[1;31m FAILED\e[0m (not found)";
    ERR_MSG="SFTP subsystem did not exist";
    ERR=1;
    let FAIL=$FAIL+1;
  fi

  # Test 2/9
  NUM=1
  LINE_NUM=$(grep -n "Match Group" $SSH_CONFIG | awk '{print $1}' FS=":")

  if [ -z $LINE_NUM ]; then
    echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check for SFTP chroot settings:\e[1;31m FAILED\e[0m (not found)";
    ERR_MSG="$ERR_MSG SFTP chroot not found,";
    let FAIL=$FAIL+1;
    SKIP_REST=1;
    ERR=1;
  else
    echo -e "   [Test 2.$(add_zero $NUM)$(((NUM++)))] Check for SFTP chroot settings:\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
    let END_LINE=$LINE_NUM+8;
    sed -n -e "$LINE_NUM","$END_LINE"p $SSH_CONFIG > $TMP_FILE
  fi 

  if [ $SKIP_REST -eq 0 ]; then
    # Test 3/9
    NUM=1
    if [ $(grep -i "ForceCommand internal-sftp -l $SFTP_LOG_LEVEL$" $TMP_FILE | wc -l) -eq 1 ]; then
      echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if SSH LogLevel is $SFTP_LOG_LEVEL:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 3.$(add_zero $NUM)$(((NUM++)))] Check if SSH LogLevel is $SFTP_LOG_LEVEL::\e[1;31m FAILED\e[0m (wrong log level)";
      ERR_MSG="$ERR_MSG worng log level for SFTP";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 4/9
    NUM=1
    if [ $(grep -i "ChrootDirectory $SFTP_CHROOT_DIR$" $TMP_FILE | wc -l) -eq 1 ]; then
      echo -e "   [Test 4.$(add_zero $NUM)$(((NUM++)))] Check if ChrootDirectory is $SFTP_CHROOT_DIR:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 4.$(add_zero $NUM)$(((NUM++)))] Check if ChrootDirectory is $SFTP_CHROOT_DIR:\e[1;31m FAILED\e[0m (missing)";
      ERR_MSG="$ERR_MSG chroot directory is missing,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 5/9
    NUM=1
    if [ $(grep -i "AllowTcpForwarding $SFTP_TCP_FORWARDING$" $TMP_FILE | wc -l) -eq 1 ]; then
      echo -e "   [Test 5.$(add_zero $NUM)$(((NUM++)))] Check if AllowTcpForwarding is $SFTP_TCP_FORWARDING:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 5.$(add_zero $NUM)$(((NUM++)))] Check if AllowTcpForwarding is $SFTP_TCP_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
      ERR_MSG="$ERR_MSG tcp forwarding is enabled,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 6/9
    NUM=1
    if [ $(grep -i "AllowAgentForwarding $SFTP_AGENT_FORWARDING$" $TMP_FILE | wc -l) -eq 1 ]; then
      echo -e "   [Test 6.$(add_zero $NUM)$(((NUM++)))] Check if AllowAgentForwarding is $SFTP_AGENT_FORWARDING:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 6.$(add_zero $NUM)$(((NUM++)))] Check if AllowAgentForwarding is $SFTP_AGENT_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
      ERR_MSG="$ERR_MSG agent forwarding is enabled,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 7/9
    NUM=1
    if [ $(grep -i "PasswordAuthentication $SFTP_PASS_AUTH$" $TMP_FILE | wc -l) -eq 1 ]; then
      echo -e "   [Test 7.$(add_zero $NUM)$(((NUM++)))] Check if PasswordAuthentication is $SFTP_PASS_AUTH:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 7.$(add_zero $NUM)$(((NUM++)))] Check if PasswordAuthentication is $SFTP_PASS_AUTH:\e[1;31m FAILED\e[0m (enabled)";
      ERR_MSG="$ERR_MSG password authentication is enabled,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 8/9
    NUM=1
    if [ $(grep -i "PermitRootLogin $SFTP_PERMIT_ROOT$" $TMP_FILE | wc -l) -eq 1 ]; then
      echo -e "   [Test 8.$(add_zero $NUM)$(((NUM++)))] Check if PermitRootLogin is $SFTP_PERMIT_ROOT:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 8.$(add_zero $NUM)$(((NUM++)))] Check if PermitRootLogin is $SFTP_PERMIT_ROOT:\e[1;31m FAILED\e[0m (enabled)";
      ERR_MSG="$ERR_MSG root login is enabled,";
      let FAIL=$FAIL+1;
      ERR=1;
    fi

    # Test 9/9
    NUM=1
    if [ $(grep -i "X11Forwarding $SFTP_X11_FORWARDING$" $TMP_FILE | wc -l) -eq 1 ]; then
      echo -e "   [Test 9.$(add_zero $NUM)$(((NUM++)))] Check if X11Forwarding is $SFTP_X11_FORWARDING:\e[1;32m PASSED\e[0m";
      let PASS=$PASS+1;
    else
      echo -e "   [Test 9.$(add_zero $NUM)$(((NUM++)))] Check if X11Forwarding is $SFTP_X11_FORWARDING:\e[1;31m FAILED\e[0m (enabled)";
      ERR_MSG="$ERR_MSG X11 forwarding is enabled";
      let FAIL=$FAIL+1;
      ERR=1;
    fi
    rm $TMP_FILE 2>/dev/null
  else
    echo -e "   [Test -.--] Checks for SFTP security settings: SKIPPED";
    echo -e "\t\e[33mNOTE!\e[0m Test for SFTP chroot settings failed. All other SFTP tests skipped!"
    SKIP=1;
    ERR_MSG="$ERR_MSG, all other SFTP tests skipped";
  fi
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
