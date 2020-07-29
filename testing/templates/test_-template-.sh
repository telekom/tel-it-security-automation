#!/bin/bash

# tel-it-security-automation :- Ansible roles for automated security hardening.  
# Copyright (c) 2020 Maximilian Hertstein, [...] Deutsche Telekom AG 
# contact: devsecops@telekom.de 
# This file is distributed under the conditions of the Apache-2.0 license. 
# For details see the files LICENSING, LICENSE, and/or COPYING on the toplevel.

# -----------------------------------------------------------------------------
# Deutsche Telekom IT GmbH (DevSecOps Team)
# Script for Compliance Check - Template
# Version: 1.0
# Date: 08.06.2020 
# -----------------------------------------------------------------------------
TEST_NAME="<<<< insert test name here! >>>>"

# -----------------------------------------------------------------------------
# Check if script is executed directly
# -----------------------------------------------------------------------------

if [ ! "$1" ]; then 
  
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
  # -----------------------------------------------------------------------------
  # Define and load input file with custom variables
  # -----------------------------------------------------------------------------
  INPUT_VARS_FILE="vars_custom_$TEST_NAME.sh"
  read_variables $INPUT_VARS_FILE
fi 

# -----------------------------------------------------------------------------
# Linux distro specific variables
# -----------------------------------------------------------------------------

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# Add OS specific variabled if needed. 
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Variable '$OS_MAIN_DISTRO' can have the following values:
# - DEBIAN
# - REDHAT
# - SUSE

# Example: 
# NOLOGIN_PATH_REDHAT="/sbin/nologin";
# NOLOGIN_PATH_DEBIAN="/usr/sbin/nologin";
# NOLOGIN_PATH_SUSE="/sbin/nologin";
# NOLOGIN_PATH="NOLOGIN_PATH_$OS_MAIN_DISTRO";

# -----------------------------------------------------------------------------
# Variables for test cases
# -----------------------------------------------------------------------------

# NOTE!
# Variables marked wit '# default' can be overwritten by customer in input file
# with custom variables. Change of all othe variables has effect on security
# compliance!

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# Add variables for test cases for different requirements
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Req 1: example.
#if [ ! "$TCP_PORTS" ]; then TCP_PORTS=""; fi  # default
# UDP_PORT=""

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
echo " Compliance Checks - <<<< add security req. source here >>>>"
echo "==============================================================================="
echo -e "Start testing ..."
REQ_NR=0

# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>
# >>>> Add test cases for here ...
# >>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>>

# Req 1: Example
REQ_TXT="Example requirement."
initiate_test

if [ "${!REQ}" == "TRUE" ] || [ ! ${!REQ} ]; then

  # Test 1/1
  NUM=1
  CHK_TEST=$( -- test --- )

  if [ -z "$CHK_TEST" ]; then
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if ... :\e[1;32m PASSED\e[0m";
    let PASS=$PASS+1;
  else
    echo -e "   [Test 1.$(add_zero $NUM)$(((NUM++)))] Check if ... :\e[1;31m FAILED\e[0m (reason why)";
    ERR_MSG1="reason why test failes";
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

# -----------------------------------------------------------------------------
# End of script
# -----------------------------------------------------------------------------

echo -e "\n... Testing finished"
